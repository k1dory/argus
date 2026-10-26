package store

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/devitex-soft/argus/engine/internal/identity"
)

// Чтение алиасов: последняя версия строки, пустой valid_to — открытый алиас,
// OpenAliases отфильтровывает закрытые; запись — полная строка JSONEachRow.
func TestIdentityAliasesRoundTrip(t *testing.T) {
	var gotQuery, gotBody string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		if q := r.URL.Query().Get("query"); strings.HasPrefix(q, "INSERT") {
			gotQuery, gotBody = q, string(body)
			return
		}
		gotQuery = string(body)
		if strings.Contains(gotQuery, "max(updated_at)") {
			_, _ = w.Write([]byte(`{"m":"1970-01-01 00:00:00.000"}` + "\n"))
			return
		}
		if strings.Contains(gotQuery, "FROM identities ") {
			_, _ = w.Write([]byte(`{"person_id":"i.petrov"}` + "\n"))
			return
		}
		_, _ = w.Write([]byte(`{"person_id":"a.sidorov","alias_kind":"ip","alias_value":"10.77.0.42","valid_from":"2026-10-01 00:00:00.000","valid_to":"2026-10-15 09:00:00.000","source":"yaml","confidence":1,"note":"","deleted":0}
{"person_id":"i.petrov","alias_kind":"ip","alias_value":"10.77.0.42","valid_from":"2026-10-15 09:00:00.000","valid_to":"","source":"event:vpn.example","confidence":0.9,"note":"ноутбук","deleted":0}
`))
	}))
	defer srv.Close()
	c := New(srv.URL, "argus", "u", "p")
	ctx := context.Background()

	open, err := c.OpenAliases(ctx, "ip", "10.77.0.42", "")
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(gotQuery, "argMax(ifNull(toString(valid_to), ''), updated_at)") || !strings.Contains(gotQuery, "HAVING deleted = 0") || !strings.Contains(gotQuery, "alias_value = {value:String}") {
		t.Errorf("запрос: %s", gotQuery)
	}
	if len(open) != 1 || open[0].PersonID != "i.petrov" || open[0].ValidTo != nil || open[0].Confidence != 0.9 || open[0].Note != "ноутбук" ||
		!open[0].ValidFrom.Equal(time.Date(2026, 10, 15, 9, 0, 0, 0, time.UTC)) {
		t.Errorf("open: %+v", open)
	}
	yaml, err := c.AliasesBySource(ctx, "yaml")
	if err != nil {
		t.Fatal(err)
	}
	if len(yaml) != 1 || yaml[0].PersonID != "a.sidorov" || yaml[0].ValidTo == nil || !yaml[0].ValidTo.Equal(time.Date(2026, 10, 15, 9, 0, 0, 0, time.UTC)) {
		t.Errorf("yaml: %+v", yaml)
	}
	byPerson, err := c.AliasesByPerson(ctx, "i.petrov", "ip")
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(gotQuery, "person_id = {person:String} AND alias_kind = {kind:String}") || len(byPerson) != 2 {
		t.Errorf("AliasesByPerson: %s → %+v", gotQuery, byPerson)
	}
	known, err := c.KnownPersons(ctx, []string{"i.petrov", "x"})
	if err != nil || !known["i.petrov"] || known["x"] {
		t.Errorf("known: %v %v", known, err)
	}

	to := time.Date(2026, 10, 15, 9, 0, 0, 0, time.UTC)
	if err := c.DeleteAliases(ctx, []identity.Alias{{PersonID: "a.sidorov", Kind: "ip", Value: "10.77.0.42", ValidFrom: time.Date(2026, 10, 1, 0, 0, 0, 0, time.UTC), ValidTo: &to, Source: "yaml", Confidence: 1}}); err != nil {
		t.Fatal(err)
	}
	if gotQuery != "INSERT INTO identity_aliases FORMAT JSONEachRow" {
		t.Errorf("insert: %s", gotQuery)
	}
	for _, want := range []string{`"valid_from":"2026-10-01 00:00:00.000"`, `"valid_to":"2026-10-15 09:00:00.000"`, `"deleted":1`, `"source":"yaml"`, `"updated_at":"`} {
		if !strings.Contains(gotBody, want) {
			t.Errorf("нет %s в %s", want, gotBody)
		}
	}
	if err := c.UpsertAliases(ctx, []identity.Alias{{PersonID: "i.petrov", Kind: "ip", Value: "10.77.0.42", ValidFrom: to, Source: "event:vpn.example", Confidence: 1}}); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(gotBody, `"valid_to":null`) || !strings.Contains(gotBody, `"deleted":0`) {
		t.Errorf("открытый алиас: %s", gotBody)
	}
	if err := c.UpsertIdentities(ctx, []identity.Person{{ID: "svc-x"}}); err != nil {
		t.Fatal(err)
	}
	if gotQuery != "INSERT INTO identities FORMAT JSONEachRow" || !strings.Contains(gotBody, `"display":"svc-x"`) || !strings.Contains(gotBody, `"kind":"person"`) {
		t.Errorf("identities: %s %s", gotQuery, gotBody)
	}
}

// Метки updated_at: первая запись начинает не ниже max(updated_at) из базы
// (после рестарта часы могли отстать), дальше строго возрастают на 1 мс при
// частых батчах; ошибка чтения max не блокирует запись и повторяется.
func TestIdentityStampsSeededFromDatabase(t *testing.T) {
	future := time.Now().UTC().Add(time.Hour).Truncate(time.Millisecond)
	var stamps []string
	failMax := true
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		if q := r.URL.Query().Get("query"); strings.HasPrefix(q, "INSERT") {
			var row struct {
				UpdatedAt string `json:"updated_at"`
			}
			for _, line := range strings.Split(strings.TrimSpace(string(body)), "\n") {
				_ = json.Unmarshal([]byte(line), &row)
				stamps = append(stamps, row.UpdatedAt)
			}
			return
		}
		if failMax {
			http.Error(w, "Code: 60. DB::Exception: table missing", http.StatusInternalServerError)
			return
		}
		_, _ = w.Write([]byte(`{"m":"` + future.Format(ts3) + `"}` + "\n"))
	}))
	defer srv.Close()
	c := New(srv.URL, "argus", "u", "p")
	ctx := context.Background()
	a := identity.Alias{PersonID: "i.petrov", Kind: "login", Value: "ipetrov", ValidFrom: identity.Epoch, Source: "yaml", Confidence: 1}
	// max(updated_at) недоступен — пишем от текущего времени, не падаем.
	if err := c.UpsertAliases(ctx, []identity.Alias{a}); err != nil {
		t.Fatal(err)
	}
	if len(stamps) != 1 || stamps[0] >= future.Format(ts3) {
		t.Fatalf("без базы — метка от текущего времени: %v", stamps)
	}
	// База отвечает — нижняя граница из неё: следующая метка строго выше max.
	failMax = false
	if err := c.UpsertAliases(ctx, []identity.Alias{a, {PersonID: "a.sidorov", Kind: "login", Value: "asidorov", ValidFrom: identity.Epoch, Source: "yaml", Confidence: 1}, a}); err != nil {
		t.Fatal(err)
	}
	if len(stamps) != 3 || stamps[1] <= future.Format(ts3) || stamps[1] != stamps[2] {
		t.Fatalf("метка батча не ниже max(updated_at)+1мс и одна на батч (дубль ключа свёрнут): %v", stamps)
	}
	if err := c.UpsertIdentities(ctx, []identity.Person{{ID: "i.petrov"}}); err != nil {
		t.Fatal(err)
	}
	prev, _ := identity.ParseTime(stamps[2])
	next, _ := identity.ParseTime(stamps[3])
	if next.Sub(prev) != time.Millisecond {
		t.Fatalf("следующий батч ровно +1 мс, без ухода в будущее: %s → %s", stamps[2], stamps[3])
	}
}
