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

func TestNeverBlockFromConfigAndEnv(t *testing.T) {
	t.Setenv("ARGUS_RESPOND_NEVER_BLOCK_1", "198.51.100.40/29")
	t.Setenv("ARGUS_RESPOND_NEVER_BLOCK_3", "203.0.113.77") // дырка в нумерации допустима
	srv, blocks, _ := newNGFW(t)
	c := cfg(srv, ModeIPS)
	c.Allowlist = nil
	c.NeverBlock = []string{"192.0.2.1", "2001:db8:ff::/48"}
	r := New(c)
	if len(r.NeverBlock()) != 4 {
		t.Fatalf("never_block из конфига и env: %v", r.NeverBlock())
	}
	for _, ip := range []string{"192.0.2.1", "198.51.100.42", "203.0.113.77", "2001:db8:ff::10"} {
		err := r.Check(ip)
		if err == nil || !strings.Contains(err.Error(), "never_block") {
			t.Fatalf("%s должен отклоняться never_block: %v", ip, err)
		}
		if _, err := r.BlockIP(context.Background(), ip, "INC-1", "test"); err == nil {
			t.Fatalf("ручная блокировка %s должна отклоняться", ip)
		}
		if _, applied, err := r.Auto(context.Background(), ip, "INC-1", "test", 0); err == nil || applied {
			t.Fatalf("автоблокировка %s должна отклоняться", ip)
		}
	}
	if err := r.Check("192.0.2.2"); err != nil {
		t.Fatalf("соседний адрес вне never_block должен проходить: %v", err)
	}
	if blocks.Load() != 0 {
		t.Fatal("исполнитель не должен вызываться")
	}
	// битый never_block в ips — откат в simulate, как и для allowlist
	bad := cfg(srv, ModeIPS)
	bad.NeverBlock = []string{"nonsense/1"}
	if m, _ := New(bad).Mode(); m != ModeSimulate {
		t.Fatalf("битый never_block в ips должен откатывать в simulate, got %s", m)
	}
}

func TestTrustedEvent(t *testing.T) {
	t.Setenv("ARGUS_RESPOND_TRUSTED_1", "10.0.10.0/24")
	r := New(Config{TrustedSources: []string{"192.168.5.7"}})
	cases := []struct {
		transport, peer string
		want            bool
	}{
		{"file", "", true}, {"http", "203.0.113.1", true}, {"TLS", "", true}, {"pull", "", true},
		{"udp", "", false}, {"udp", "10.0.10.5", true}, {"tcp", "10.0.10.5:51423", true}, {"udp", "10.0.11.5", false},
		{"tcp", "192.168.5.7", true}, {"tcp", "192.168.5.8", false}, {"", "", false}, {"udp", "garbage", false},
	}
	for _, c := range cases {
		if got := r.TrustedEvent(c.transport, c.peer); got != c.want {
			t.Errorf("TrustedEvent(%q, %q) = %v, want %v", c.transport, c.peer, got, c.want)
		}
	}
}

func TestManualTTLFromEnvAndConfig(t *testing.T) {
	t.Setenv("ARGUS_RESPOND_MANUAL_TTL", "2h")
	if d := New(Config{}).ManualTTL(); d != 2*time.Hour {
		t.Fatalf("manual_ttl из env: %s", d)
	}
	if d := New(Config{ManualTTL: "30m"}).ManualTTL(); d != 30*time.Minute {
		t.Fatalf("manual_ttl из конфига важнее env: %s", d)
	}
	r := New(Config{ManualTTL: "later"})
	if r.ManualTTL() != 24*time.Hour || len(r.ConfigErrors()) != 1 {
		t.Fatalf("битый manual_ttl → 24h и ошибка конфига: %s %v", r.ManualTTL(), r.ConfigErrors())
	}
}

func TestUnblockManualAndAuto(t *testing.T) {
	srv, _, unblocks := newNGFW(t)
	r := New(cfg(srv, ModeIPS))
	ctx := context.Background()
	if _, err := r.Unblock(ctx, "192.0.2.60", "нет такого"); err == nil || !strings.Contains(err.Error(), "не найдена") {
		t.Fatalf("снятие несуществующего блока — ошибка: %v", err)
	}
	if _, err := r.BlockIP(ctx, "192.0.2.60", "INC-11", "оператор"); err != nil {
		t.Fatal(err)
	}
	if _, _, err := r.Auto(ctx, "192.0.2.61", "INC-12", "rule", time.Hour); err != nil {
		t.Fatal(err)
	}
	if _, err := r.Unblock(ctx, "192.0.2.60", ""); err == nil {
		t.Fatal("снятие без причины должно отклоняться")
	}
	for _, ip := range []string{"192.0.2.60", "192.0.2.61"} {
		res, err := r.Unblock(ctx, ip, "ложное срабатывание")
		if err != nil || len(res) != 1 || !res[0].OK || res[0].Executor != "ngfw.test.unblock" {
			t.Fatalf("unblock %s: %+v %v", ip, res, err)
		}
	}
	if unblocks.Load() != 2 || len(r.Active()) != 0 {
		t.Fatalf("оба блока должны сняться: unblocks=%d active=%d", unblocks.Load(), len(r.Active()))
	}
}

func TestUnblockNotConfiguredIsError(t *testing.T) {
	var blocks atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { blocks.Add(1) }))
	t.Cleanup(srv.Close)
	r := New(Config{HTTP: []HTTPAction{{Name: "ngfw.noun", URL: srv.URL + "/block"}}})
	if _, err := r.BlockIP(context.Background(), "192.0.2.70", "INC-13", "оператор"); err != nil {
		t.Fatal(err)
	}
	res, err := r.Unblock(context.Background(), "192.0.2.70", "передумал")
	if err == nil || !strings.Contains(err.Error(), "не настроено") || len(res) != 1 || res[0].OK {
		t.Fatalf("без unblock снятие — ошибка 422: %v %+v", err, res)
	}
	if len(r.Active()) != 1 {
		t.Fatal("блок должен остаться в списке")
	}
}

func TestUnblockExecutorFailureKeepsBlock(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/unblock" {
			w.WriteHeader(502)
		}
	}))
	t.Cleanup(srv.Close)
	r := New(cfg(srv, ModeIPS))
	if _, err := r.BlockIP(context.Background(), "192.0.2.71", "INC-14", "оператор"); err != nil {
		t.Fatal(err)
	}
	res, err := r.Unblock(context.Background(), "192.0.2.71", "x")
	if err != nil || len(res) != 1 || res[0].OK {
		t.Fatalf("отказ NGFW — не ошибка запроса, а ok=false: %v %+v", err, res)
	}
	if a := r.Active(); len(a) != 1 || a[0].IP != "192.0.2.71" {
		t.Fatalf("после отказа блок остаётся: %+v", a)
	}
}

// wazuhMock — менеджер Wazuh 4.x: auth и PUT /active-response с заданным total_affected_items.
func wazuhMock(t *testing.T, affected, failed int) (*httptest.Server, *[]string) {
	t.Helper()
	var cmds []string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.URL.Path == "/security/user/authenticate":
			_, _ = w.Write([]byte("jwt"))
		case r.URL.Path == "/active-response" && r.Method == http.MethodPut:
			var body struct {
				Command string `json:"command"`
			}
			_ = json.NewDecoder(r.Body).Decode(&body)
			cmds = append(cmds, body.Command+"@"+r.URL.Query().Get("agents_list"))
			_ = json.NewEncoder(w).Encode(map[string]any{"data": map[string]any{"total_affected_items": affected, "total_failed_items": failed}, "error": 0})
		default:
			w.WriteHeader(404)
		}
	}))
	t.Cleanup(srv.Close)
	return srv, &cmds
}

func TestWazuhRequiresAffectedAgentsAndExplicitAgents(t *testing.T) {
	srv, cmds := wazuhMock(t, 0, 0)
	r := New(Config{WazuhAR: &WazuhAR{APIURL: srv.URL, User: "u", Password: "p", Agents: "001,002", Timeout: 600}})
	res, err := r.BlockIP(context.Background(), "192.0.2.80", "INC-15", "x")
	if err != nil || len(res) != 1 || res[0].OK || !strings.Contains(res[0].Detail, "affected=0") {
		t.Fatalf("affected=0 — не успех: %+v %v", res, err)
	}
	if len(*cmds) != 1 || (*cmds)[0] != "firewall-drop@001,002" {
		t.Fatalf("команда и агенты: %v", *cmds)
	}
	if len(r.Active()) != 0 {
		t.Fatal("неподтверждённый блок не должен попадать в active")
	}
	// agents пуст — исполнитель выключен, а не «all»
	r2 := New(Config{WazuhAR: &WazuhAR{APIURL: srv.URL}})
	if r2.Enabled() || !strings.Contains(strings.Join(r2.ConfigErrors(), "\n"), "agents не задан") {
		t.Fatalf("без agents исполнитель должен выключаться: %v", r2.ConfigErrors())
	}
	// agents: all — предупреждение
	r3 := New(Config{WazuhAR: &WazuhAR{APIURL: srv.URL, Agents: "all", Timeout: 60}})
	if !r3.Enabled() || !strings.Contains(strings.Join(r3.ConfigErrors(), "\n"), "agents: all") {
		t.Fatalf("agents: all — работает, но с предупреждением: %v", r3.ConfigErrors())
	}
}

func TestWazuhExpireConfirmsOnlyWithTimeoutOrUnblockCommand(t *testing.T) {
	srv, cmds := wazuhMock(t, 1, 0)
	now := time.Date(2026, 9, 13, 12, 0, 0, 0, time.UTC)
	// без timeout и unblock_command: Expire не пишет OK, блок остаётся
	r := New(Config{Mode: ModeIPS, WazuhAR: &WazuhAR{APIURL: srv.URL, Agents: "001"}})
	r.nowFn = func() time.Time { return now }
	if !strings.Contains(strings.Join(r.ConfigErrors(), "\n"), "снятие по TTL не подтверждается") {
		t.Fatalf("ожидалось предупреждение о timeout: %v", r.ConfigErrors())
	}
	if _, applied, err := r.Auto(context.Background(), "192.0.2.90", "INC-16", "x", time.Minute); err != nil || !applied {
		t.Fatal(err, applied)
	}
	now = now.Add(2 * time.Minute)
	out := r.Expire(context.Background())
	if len(out) != 1 || out[0].OK || !strings.Contains(out[0].Detail, "TTL не подтверждён") || len(r.Active()) != 1 {
		t.Fatalf("expire без timeout: %+v active=%d", out, len(r.Active()))
	}
	// с timeout: OK «снят таймаутом»
	r = New(Config{Mode: ModeIPS, WazuhAR: &WazuhAR{APIURL: srv.URL, Agents: "001", Timeout: 60}})
	r.nowFn = func() time.Time { return now }
	if _, applied, _ := r.Auto(context.Background(), "192.0.2.91", "INC-17", "x", time.Minute); !applied {
		t.Fatal("block expected")
	}
	now = now.Add(2 * time.Minute)
	if out := r.Expire(context.Background()); len(out) != 1 || !out[0].OK || !strings.Contains(out[0].Detail, "<timeout>=60") || len(r.Active()) != 0 {
		t.Fatalf("expire с timeout: %+v", out)
	}
	// досрочное снятие: только через unblock_command
	if _, err := r.BlockIP(context.Background(), "192.0.2.92", "INC-18", "оператор"); err != nil {
		t.Fatal(err)
	}
	if _, err := r.Unblock(context.Background(), "192.0.2.92", "x"); err == nil || !strings.Contains(err.Error(), "не настроено") {
		t.Fatalf("без unblock_command ручное снятие у Wazuh невозможно: %v", err)
	}
	r = New(Config{Mode: ModeIPS, WazuhAR: &WazuhAR{APIURL: srv.URL, Agents: "001", UnblockCommand: "firewall-drop-delete"}})
	if _, err := r.BlockIP(context.Background(), "192.0.2.93", "INC-19", "оператор"); err != nil {
		t.Fatal(err)
	}
	res, err := r.Unblock(context.Background(), "192.0.2.93", "ложное")
	if err != nil || len(res) != 1 || !res[0].OK || (*cmds)[len(*cmds)-1] != "firewall-drop-delete@001" || len(r.Active()) != 0 {
		t.Fatalf("unblock_command: %+v %v cmds=%v", res, err, *cmds)
	}
}

func TestExpectRegexAndJSON(t *testing.T) {
	var body atomic.Pointer[string]
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { _, _ = w.Write([]byte(*body.Load())) }))
	t.Cleanup(srv.Close)
	set := func(s string) { body.Store(&s) }
	set(`{"success": false, "data": {"status": "denied"}}`)
	r := New(Config{HTTP: []HTTPAction{
		{Name: "re", URL: srv.URL, Expect: `^\{"success":\s*true`},
		{Name: "js", URL: srv.URL, ExpectJSON: map[string]any{"success": true, "data.status": "ok"}},
		{Name: "sub", URL: srv.URL, Expect: `success`}, // без якорей — предупреждение, но работает как regex
	}})
	if errs := strings.Join(r.ConfigErrors(), "\n"); !strings.Contains(errs, "без якорей") {
		t.Fatalf("ожидалось предупреждение про якоря: %v", r.ConfigErrors())
	}
	res, err := r.BlockIP(context.Background(), "192.0.2.100", "INC-20", "x")
	if err != nil || len(res) != 3 || res[0].OK || res[1].OK || !res[2].OK {
		t.Fatalf("false-ответ: regex и json должны отказать, подстрока — пройти: %+v", res)
	}
	set(`{"success": true, "data": {"status": "ok", "n": 3}}`)
	res, _ = r.BlockIP(context.Background(), "192.0.2.101", "INC-20", "x")
	if !res[0].OK || !res[1].OK || !res[2].OK {
		t.Fatalf("true-ответ должен проходить у всех: %+v", res)
	}
	if err := expectJSON([]byte(`{"data":{"n":3}}`), map[string]any{"data.n": 3}); err != nil {
		t.Fatalf("число из YAML (int) равно числу из JSON (float64): %v", err)
	}
	if err := expectJSON([]byte(`not json`), map[string]any{"a": 1}); err == nil {
		t.Fatal("не-JSON при expect_json — отказ")
	}
	bad := New(Config{Mode: ModeIPS, HTTP: []HTTPAction{{Name: "x", URL: srv.URL, Expect: `(`}}})
	if bad.Enabled() {
		t.Fatal("битый expect — исполнитель выключен")
	}
}
