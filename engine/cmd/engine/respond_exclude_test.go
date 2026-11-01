package main

import (
	"context"
	"encoding/json"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/devitex-soft/argus/engine/internal/incidents"
)

// Исключение адреса — явное решение со сроком: проверка ввода, запись в журнал
// до применения (503 без записи), список в /respond/status, отзыв; снятие блока
// и исключение независимы.
func TestRespondExcludeAPI(t *testing.T) {
	f := newFakeCH(t)
	x := newKeyExecutor(t)
	x.available.Store(true)
	e := keyEngine(t, f, x, 4)
	h := e.handler()
	for _, body := range []string{
		`{"ip":"203.0.113.7","ttl":"24h","user":"qa"}`,               // нет причины
		`{"ip":"203.0.113.7","ttl":"30s","user":"qa","reason":"r"}`,  // короче минуты
		`{"ip":"203.0.113.7","ttl":"800h","user":"qa","reason":"r"}`, // дольше 30 дней
		`{"ip":"203.0.113.7","user":"qa","reason":"r"}`,              // без срока
		`{"ip":"not-an-ip","ttl":"24h","user":"qa","reason":"r"}`,    // не адрес
	} {
		if code, out := do(t, h, http.MethodPost, "/respond/exclude", "s", body); code != http.StatusBadRequest {
			t.Fatalf("%s: HTTP %d %s, ожидался 400", body, code, out)
		}
	}
	if code, _ := do(t, h, http.MethodPost, "/respond/exclude/revoke", "s", `{"ip":"203.0.113.7","user":"qa","reason":"r"}`); code != http.StatusUnprocessableEntity {
		t.Fatalf("отзыв неисключённого адреса: HTTP %d", code)
	}
	setFail(f, "response_log", true)
	code, _ := do(t, h, http.MethodPost, "/respond/exclude", "s", `{"ip":"203.0.113.7","ttl":"24h","user":"qa","reason":"сканер партнёра"}`)
	setFail(f, "response_log", false)
	if _, excluded := e.excludedUntil("203.0.113.7", time.Now()); code != http.StatusServiceUnavailable || excluded {
		t.Fatalf("журнал недоступен: HTTP %d, исключение применено=%v", code, excluded)
	}
	if code, out := do(t, h, http.MethodPost, "/respond/exclude", "s", `{"ip":"::ffff:203.0.113.7","ttl":"24h","user":"qa","reason":"сканер партнёра"}`); code != http.StatusOK {
		t.Fatalf("исключение: HTTP %d %s", code, out)
	}
	_, out := do(t, h, http.MethodGet, "/respond/status", "s", "")
	var st struct{ Excluded []Exclusion }
	if err := json.Unmarshal([]byte(out), &st); err != nil || len(st.Excluded) != 1 || st.Excluded[0].IP != "203.0.113.7" || st.Excluded[0].Actor != "qa" {
		t.Fatalf("статус: %v %s", err, out)
	}
	ctx, now := context.Background(), time.Now().UTC().Truncate(time.Second)
	e.autoRespond(ctx, []*incidents.Incident{capInc("INC-1", "203.0.113.7")}, now)
	if x.blocks.Load() != 0 || keyState(e, "INC-1", "203.0.113.7") != keyExcluded || countSteps(f, stepExcluded) != 1 {
		t.Fatalf("исключённый адрес заблокирован: блоков %d, состояние %q", x.blocks.Load(), keyState(e, "INC-1", "203.0.113.7"))
	}
	// Повтор события того же инцидента в срок — без новой строки журнала.
	e.autoRespond(ctx, []*incidents.Incident{capInc("INC-1", "203.0.113.7")}, now.Add(time.Minute))
	if countSteps(f, stepExcluded) != 1 {
		t.Fatal("каждое событие исключённого инцидента пишет строку журнала")
	}
	if code, out := do(t, h, http.MethodPost, "/respond/exclude/revoke", "s", `{"ip":"203.0.113.7","user":"qa","reason":"окно закрыто"}`); code != http.StatusOK {
		t.Fatalf("отзыв: HTTP %d %s", code, out)
	}
	if countSteps(f, stepExclude) != 2 {
		t.Fatal("исключение и отзыв — две строки exclude")
	}
	_, out = do(t, h, http.MethodGet, "/respond/status", "s", "")
	if !strings.Contains(out, `"excluded":[]`) {
		t.Fatalf("после отзыва в статусе осталось исключение: %s", out)
	}
	e.autoRespond(ctx, []*incidents.Incident{capInc("INC-1", "203.0.113.7")}, now.Add(2*time.Minute))
	if x.blocks.Load() != 1 || keyState(e, "INC-1", "203.0.113.7") != keyDone {
		t.Fatalf("после отзыва свежие события инцидента не блокируют: блоков %d, состояние %q", x.blocks.Load(), keyState(e, "INC-1", "203.0.113.7"))
	}
}
