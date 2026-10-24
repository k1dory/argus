package respond

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

func newNGFW(t *testing.T) (*httptest.Server, *atomic.Int32, *atomic.Int32) {
	t.Helper()
	var blocks, unblocks atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/block":
			blocks.Add(1)
		case "/unblock":
			unblocks.Add(1)
		default:
			w.WriteHeader(404)
		}
	}))
	t.Cleanup(srv.Close)
	return srv, &blocks, &unblocks
}

func cfg(srv *httptest.Server, mode string) Config {
	return Config{
		Mode: mode, TTL: "1h", Allowlist: []string{"203.0.113.0/24", "198.51.100.7"},
		HTTP: []HTTPAction{{Name: "ngfw.test", URL: srv.URL + "/block", Body: `{"ip":"${ip}"}`,
			Unblock: &HTTPCall{Method: "POST", URL: srv.URL + "/unblock", Body: `{"ip":"${ip}"}`}}},
	}
}

func TestAllowlistAndPrivateNeverBlocked(t *testing.T) {
	srv, blocks, _ := newNGFW(t)
	r := New(cfg(srv, ModeIPS))
	for _, ip := range []string{"10.1.2.3", "127.0.0.1", "203.0.113.9", "198.51.100.7", "fe80::1", "not-an-ip"} {
		if err := r.Check(ip); err == nil {
			t.Fatalf("%s должен быть запрещён к блокировке", ip)
		}
		if _, err := r.BlockIP(context.Background(), ip, "INC-1", "test"); err == nil {
			t.Fatalf("ручная блокировка %s должна отклоняться", ip)
		}
		if _, applied, err := r.Auto(context.Background(), ip, "INC-1", "test", 0); err == nil || applied {
			t.Fatalf("автоблокировка %s должна отклоняться", ip)
		}
	}
	if blocks.Load() != 0 {
		t.Fatalf("исполнитель не должен вызываться: %d", blocks.Load())
	}
}

func TestModesIDSSimulateIPS(t *testing.T) {
	srv, blocks, _ := newNGFW(t)
	r := New(cfg(srv, "bogus"))
	if m, from := r.Mode(); m != ModeSimulate || from != "config" {
		t.Fatalf("неизвестный режим должен становиться simulate, got %s/%s", m, from)
	}
	// simulate: результат dry-run, исполнитель не вызывается
	res, applied, err := r.Auto(context.Background(), "192.0.2.10", "INC-2", "burst", 0)
	if err != nil || applied || len(res) != 1 || !res[0].DryRun || !res[0].OK || blocks.Load() != 0 {
		t.Fatalf("simulate: res=%+v applied=%v err=%v blocks=%d", res, applied, err, blocks.Load())
	}
	// ids: автоматика молчит совсем
	r.SetMode(ModeIDS)
	if res, applied, _ := r.Auto(context.Background(), "192.0.2.10", "INC-2", "burst", 0); len(res) != 0 || applied {
		t.Fatalf("ids: ожидался пустой результат, got %+v", res)
	}
	// ручная кнопка работает в любом режиме
	if res, err := r.BlockIP(context.Background(), "192.0.2.10", "INC-2", "operator"); err != nil || !res[0].OK || blocks.Load() != 1 {
		t.Fatalf("manual in ids: %+v %v", res, err)
	}
	// ips: реальная блокировка, повтор — «уже заблокирован»
	r.SetMode(ModeIPS)
	if m, from := r.Mode(); m != ModeIPS || from != "console" {
		t.Fatalf("SetMode: %s/%s", m, from)
	}
	res, applied, err = r.Auto(context.Background(), "192.0.2.11", "INC-3", "rce", 30*time.Minute)
	if err != nil || !applied || blocks.Load() != 2 {
		t.Fatalf("ips: res=%+v applied=%v err=%v blocks=%d", res, applied, err, blocks.Load())
	}
	if res, applied, _ := r.Auto(context.Background(), "192.0.2.11", "INC-3", "rce", 0); applied || !strings.Contains(res[0].Detail, "уже заблокирован") {
		t.Fatalf("повтор: %+v", res)
	}
	// автоблок 192.0.2.11 (30m) раньше ручного 192.0.2.10 (manual_ttl 24h); оба со сроком
	if a := r.Active(); len(a) != 2 || a[0].IP != "192.0.2.11" || a[0].Until.IsZero() || !a[1].Manual || a[1].IP != "192.0.2.10" || a[1].Until.IsZero() {
		t.Fatalf("active: %+v", a)
	}
	// возврат к конфигу
	r.SetMode("")
	if m, from := r.Mode(); m != ModeSimulate || from != "config" {
		t.Fatalf("reset: %s/%s", m, from)
	}
}

func TestExpireUnblocksViaTemplate(t *testing.T) {
	srv, _, unblocks := newNGFW(t)
	r := New(cfg(srv, ModeIPS))
	now := time.Date(2026, 9, 13, 12, 0, 0, 0, time.UTC)
	r.nowFn = func() time.Time { return now }
	if _, applied, err := r.Auto(context.Background(), "192.0.2.20", "INC-4", "x", 10*time.Minute); err != nil || !applied {
		t.Fatal(err)
	}
	if out := r.Expire(context.Background()); len(out) != 0 {
		t.Fatalf("рано: %+v", out)
	}
	now = now.Add(11 * time.Minute)
	out := r.Expire(context.Background())
	if len(out) != 1 || !out[0].OK || unblocks.Load() != 1 || len(r.Active()) != 0 {
		t.Fatalf("expire: %+v unblocks=%d active=%d", out, unblocks.Load(), len(r.Active()))
	}
}

func TestEmptyExecutorsDroppedAndNestedTemplateSafe(t *testing.T) {
	r := New(Config{Mode: ModeIPS, WazuhAR: &WazuhAR{APIURL: ""}, HTTP: []HTTPAction{{Name: "ngfw", URL: ""}, {Name: "ok", URL: "http://x/block", Unblock: &HTTPCall{URL: ""}}}})
	if r.Enabled() != true || len(r.executors()) != 1 || r.executors()[0] != "ok" {
		t.Fatalf("исполнители с пустым адресом должны отбрасываться: %v", r.executors())
	}
	if r.cfg.HTTP[0].Unblock != nil {
		t.Fatal("unblock с пустым url должен обнуляться")
	}
	if len(r.ConfigErrors()) != 3 { // два пустых url + откат ips → simulate без unblock
		t.Fatalf("ожидались 3 ошибки конфигурации: %v", r.ConfigErrors())
	}
	if m, _ := r.Mode(); m != ModeSimulate {
		t.Fatalf("ips без unblock должен откатываться в simulate, got %s", m)
	}
}

func TestSubstituteIsInjectionSafe(t *testing.T) {
	vals := map[string]string{"ip": "1.2.3.4", "incident": `INC-1","action":"delete_all","x":"`, "reason": "a\"b\\c\n"}
	body := substitute(`{"ip":"${ip}","c":"ARGUS ${incident}: ${reason}"}`, vals, false)
	var out map[string]string
	if err := json.Unmarshal([]byte(body), &out); err != nil {
		t.Fatalf("тело после подстановки должно оставаться валидным JSON: %v\n%s", err, body)
	}
	if out["c"] != `ARGUS INC-1","action":"delete_all","x":": a"b\c`+"\n" || len(out) != 2 {
		t.Fatalf("значения должны попадать как строки, а не как структура: %+v", out)
	}
	if u := substitute("https://h/block/${ip}/${incident}", vals, true); strings.Contains(u, `"`) || !strings.Contains(u, "%22") {
		t.Fatalf("URL-подстановка должна экранировать: %s", u)
	}
}

func TestManualBlockHasTTLAndIsNotOverriddenByAuto(t *testing.T) {
	srv, blocks, unblocks := newNGFW(t)
	r := New(cfg(srv, ModeIPS))
	now := time.Date(2026, 9, 13, 12, 0, 0, 0, time.UTC)
	r.nowFn = func() time.Time { return now }
	if _, err := r.BlockIP(context.Background(), "192.0.2.30", "INC-7", ""); err == nil {
		t.Fatal("ручная блокировка без причины должна отклоняться")
	}
	if _, err := r.BlockIP(context.Background(), "192.0.2.30", "INC-7", "оператор"); err != nil {
		t.Fatal(err)
	}
	if a := r.Active(); len(a) != 1 || !a[0].Manual || !a[0].Until.Equal(now.Add(24*time.Hour)) {
		t.Fatalf("ручной блок должен жить manual_ttl (24h по умолчанию): %+v", a)
	}
	// автоматика не перекрывает ручной блок своим TTL
	res, applied, _ := r.Auto(context.Background(), "192.0.2.30", "INC-8", "rule", time.Minute)
	if applied || !strings.Contains(res[0].Detail, "оператор") || blocks.Load() != 1 {
		t.Fatalf("auto over manual: %+v applied=%v blocks=%d", res, applied, blocks.Load())
	}
	now = now.Add(23 * time.Hour)
	if out := r.Expire(context.Background()); len(out) != 0 || unblocks.Load() != 0 {
		t.Fatalf("до manual_ttl ручной блок не снимается: %+v", out)
	}
	now = now.Add(2 * time.Hour)
	if out := r.Expire(context.Background()); len(out) != 1 || !out[0].OK || unblocks.Load() != 1 || len(r.Active()) != 0 {
		t.Fatalf("после manual_ttl ручной блок снимается через unblock: %+v unblocks=%d", out, unblocks.Load())
	}
}

func TestAllExecutorsFailedGoesToRetryQueue(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(500) }))
	t.Cleanup(srv.Close)
	r := New(cfg(srv, ModeIPS))
	now := time.Date(2026, 9, 13, 12, 0, 0, 0, time.UTC)
	r.nowFn = func() time.Time { return now }
	res, applied, err := r.Auto(context.Background(), "192.0.2.40", "INC-9", "x", 0)
	if err != nil || applied || len(r.Active()) != 0 || r.Pending() != 1 || !strings.Contains(res[len(res)-1].Detail, "повтор №1") {
		t.Fatalf("failed executors: res=%+v applied=%v active=%d pending=%d", res, applied, len(r.Active()), r.Pending())
	}
	if out := r.Retry(context.Background()); len(out) != 0 {
		t.Fatalf("повтор до срока не должен выполняться: %+v", out)
	}
	now = now.Add(2 * time.Minute)
	if out := r.Retry(context.Background()); len(out) == 0 || r.Pending() != 1 {
		t.Fatalf("повтор по сроку: %+v pending=%d", out, r.Pending())
	}
	for i := 0; i < maxRetries; i++ {
		now = now.Add(time.Hour)
		r.Retry(context.Background())
	}
	if r.Pending() != 0 {
		t.Fatalf("после %d попыток очередь должна опустеть, pending=%d", maxRetries, r.Pending())
	}
}

func TestExpireWithoutUnblockKeepsPermanentBlock(t *testing.T) {
	var blocks atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { blocks.Add(1) }))
	t.Cleanup(srv.Close)
	r := New(Config{Mode: ModeIPS, HTTP: []HTTPAction{{Name: "ngfw.noun", URL: srv.URL + "/block"}}})
	if m, _ := r.Mode(); m != ModeSimulate {
		t.Fatalf("ips без unblock должен откатываться в simulate, got %s", m)
	}
	r.SetMode(ModeIPS) // консоль может включить осознанно — снятие тогда не гарантируется
	now := time.Date(2026, 9, 13, 12, 0, 0, 0, time.UTC)
	r.nowFn = func() time.Time { return now }
	if _, applied, _ := r.Auto(context.Background(), "192.0.2.50", "INC-10", "x", time.Minute); !applied {
		t.Fatal("block expected")
	}
	now = now.Add(2 * time.Minute)
	out := r.Expire(context.Background())
	if len(out) != 1 || out[0].OK || !strings.Contains(out[0].Detail, "постоянным") {
		t.Fatalf("expire w/o unblock: %+v", out)
	}
	if a := r.Active(); len(a) != 1 || !a[0].Until.IsZero() {
		t.Fatalf("блок должен остаться постоянным: %+v", a)
	}
	if out := r.Expire(context.Background()); len(out) != 0 {
		t.Fatalf("постоянный блок не должен экспайриться повторно: %+v", out)
	}
}

func TestCheckRejectsCGNATAndFailClosedOnBadAllowlist(t *testing.T) {
	r := New(Config{Mode: ModeIPS, Allowlist: []string{"garbage/99"}, HTTP: []HTTPAction{{Name: "x", URL: "http://x"}}})
	if m, _ := r.Mode(); m != ModeSimulate {
		t.Fatalf("битый allowlist в ips должен откатывать в simulate, got %s", m)
	}
	if err := r.Check("100.64.1.1"); err == nil {
		t.Fatal("CGNAT должен отклоняться")
	}
	if err := r.Check("2001:db8::1"); err != nil {
		t.Fatalf("публичный IPv6 должен проходить: %v", err)
	}
}

func TestAutoWithoutExecutors(t *testing.T) {
	r := New(Config{Mode: ModeIPS})
	if _, _, err := r.Auto(context.Background(), "192.0.2.1", "INC-5", "x", 0); err == nil {
		t.Fatal("без исполнителей автоблокировка должна возвращать ошибку конфигурации")
	}
	if r := New(Config{Allowlist: []string{"garbage/99"}}); len(r.ConfigErrors()) != 1 {
		t.Fatal("битый allowlist должен попадать в ConfigErrors")
	}
}

// ARGUS_RESPOND_MANUAL_TTL=0 — ручная блокировка без срока: Until нулевой,
// Expire её не трогает, снимает только Unblock.
func TestManualTTLZeroMeansNoExpiry(t *testing.T) {
	srv, _, unblocks := newNGFW(t)
	c := cfg(srv, ModeIPS)
	c.ManualTTL = "0"
	r := New(c)
	if r.ManualTTL() != 0 || len(r.ConfigErrors()) != 0 {
		t.Fatalf("manual_ttl=0: ttl=%s errors=%v", r.ManualTTL(), r.ConfigErrors())
	}
	now := time.Date(2026, 9, 13, 12, 0, 0, 0, time.UTC)
	r.nowFn = func() time.Time { return now }
	if _, err := r.BlockIP(context.Background(), "192.0.2.60", "INC-11", "оператор"); err != nil {
		t.Fatal(err)
	}
	if a := r.Active(); len(a) != 1 || !a[0].Manual || !a[0].Until.IsZero() {
		t.Fatalf("бессрочный ручной блок: %+v", a)
	}
	now = now.Add(365 * 24 * time.Hour)
	if out := r.Expire(context.Background()); len(out) != 0 || unblocks.Load() != 0 {
		t.Fatalf("бессрочный блок не экспайрится: %+v", out)
	}
	if _, err := r.Unblock(context.Background(), "192.0.2.60", "ложное"); err != nil || unblocks.Load() != 1 || len(r.Active()) != 0 {
		t.Fatalf("снятие вручную: %v unblocks=%d", err, unblocks.Load())
	}
	// нечитаемое и отрицательное — 24h с записью в config_errors
	for _, bad := range []string{"garbage", "-1h"} {
		c.ManualTTL = bad
		if r := New(c); r.ManualTTL() != defaultManualTTL || len(r.ConfigErrors()) != 1 {
			t.Fatalf("manual_ttl=%q: ttl=%s errors=%v", bad, r.ManualTTL(), r.ConfigErrors())
		}
	}
}

// Пока Unblock ходил по сети, блок сняли по TTL и поставили заново другим
// инцидентом: чужую запись Unblock не трогает.
func TestUnblockDoesNotTouchReplacedBlock(t *testing.T) {
	var r *Responder
	var replaced atomic.Bool
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		if req.URL.Path == "/unblock" && replaced.CompareAndSwap(false, true) {
			// во время сетевого вызова блок заменяется новым
			r.mu.Lock()
			r.active["192.0.2.70"] = Block{IP: "192.0.2.70", Incident: "INC-NEW", Until: r.nowFn().Add(time.Hour), Executors: []string{"ngfw.test"}}
			r.mu.Unlock()
		}
	}))
	t.Cleanup(srv.Close)
	r = New(cfg(srv, ModeIPS))
	if _, applied, err := r.Auto(context.Background(), "192.0.2.70", "INC-OLD", "x", time.Minute); err != nil || !applied {
		t.Fatal(err)
	}
	if _, err := r.Unblock(context.Background(), "192.0.2.70", "ложное"); err != nil {
		t.Fatal(err)
	}
	if a := r.Active(); len(a) != 1 || a[0].Incident != "INC-NEW" {
		t.Fatalf("новый блок должен остаться: %+v", a)
	}
}

// «Уже заблокирован» — не отказ исполнителя: Noop без вызова исполнителей.
func TestAutoAlreadyBlockedIsNoop(t *testing.T) {
	srv, blocks, _ := newNGFW(t)
	r := New(cfg(srv, ModeIPS))
	if _, applied, _ := r.Auto(context.Background(), "192.0.2.80", "INC-1", "x", time.Hour); !applied {
		t.Fatal("первая блокировка")
	}
	res, applied, err := r.Auto(context.Background(), "192.0.2.80", "INC-2", "x", time.Hour)
	if err != nil || applied || !Noop(res) || !res[0].OK || blocks.Load() != 1 {
		t.Fatalf("повтор: res=%+v applied=%v err=%v blocks=%d", res, applied, err, blocks.Load())
	}
}

// Вне режима ips очередь повторов не дёргается: simulate иначе писал бы
// «симуляция» на каждый цикл, не убывая; при возврате в ips повтор выполняется.
func TestRetryOnlyInIPS(t *testing.T) {
	var fail atomic.Bool
	fail.Store(true)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		if fail.Load() {
			w.WriteHeader(500)
		}
	}))
	t.Cleanup(srv.Close)
	r := New(cfg(srv, ModeIPS))
	now := time.Date(2026, 9, 13, 12, 0, 0, 0, time.UTC)
	r.nowFn = func() time.Time { return now }
	if _, _, err := r.Auto(context.Background(), "192.0.2.90", "INC-9", "x", 0); err != nil || r.Pending() != 1 {
		t.Fatalf("%v pending=%d", err, r.Pending())
	}
	now = now.Add(2 * time.Minute)
	r.SetMode(ModeSimulate)
	if out := r.Retry(context.Background()); len(out) != 0 || r.Pending() != 1 {
		t.Fatalf("simulate: повтор не должен выполняться: %+v pending=%d", out, r.Pending())
	}
	r.SetMode(ModeIDS)
	if out := r.Retry(context.Background()); len(out) != 0 {
		t.Fatalf("ids: %+v", out)
	}
	fail.Store(false)
	r.SetMode(ModeIPS)
	if out := r.Retry(context.Background()); len(out) != 1 || !out[0].OK || r.Pending() != 0 || len(r.Active()) != 1 {
		t.Fatalf("ips: %+v pending=%d", out, r.Pending())
	}
}
