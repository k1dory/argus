package analyst

import (
	"context"
	"errors"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/devitex-soft/argus/engine/internal/incidents"
)

// fakeBackend — сторонний бэкенд: отдаёт заданный вердикт и запоминает, что
// ему передали.
type fakeBackend struct {
	verdict Verdict
	err     error
	calls   int
	prompt  string
	system  string
	profile Profile
}

func (f *fakeBackend) Analyze(_ context.Context, p Profile, client *http.Client, system, prompt string) (Verdict, uint32, error) {
	f.calls++
	f.prompt, f.system, f.profile = prompt, system, p
	if client == nil {
		return Verdict{}, 0, errors.New("клиент не передан")
	}
	return f.verdict, 7, f.err
}

func withBackend(t *testing.T, name string, b Backend) {
	t.Helper()
	RegisterBackend(name, b)
	t.Cleanup(func() {
		backendsMu.Lock()
		delete(backends, name)
		backendsMu.Unlock()
	})
}

// Зарегистрированный бэкенд идёт тем же путём, что встроенные: маршрутизация
// по ПДн, редакция данных, validate и decideShown применяются к нему без
// исключений.
func TestRegisteredBackendGoesThroughCommonPath(t *testing.T) {
	good := Verdict{SummaryRU: "Перебор паролей по SSH с одного адреса, успешного входа нет.", Evidence: []string{"ssh.login.failure от 203.0.113.7"}, FirstAction: "заблокировать адрес", Confidence: 0.9}
	fb := &fakeBackend{verdict: good}
	withBackend(t, "fake", fb)
	c := cfg()
	c.Profiles["fake-cloud"] = Profile{Backend: "fake", Endpoint: "https://llm.example/v1", Model: "fake-1"}
	c.Profiles["fake-local"] = Profile{Backend: "fake", Endpoint: "https://10.0.0.9/v1", Model: "fake-1", Egress: "deny"}
	c.PIIProfile = "fake-local"
	if problems := c.Validate(); len(problems) != 0 {
		t.Fatalf("конфиг с зарегистрированным бэкендом валиден: %v", problems)
	}
	a := New(c)
	inc := &incidents.Incident{IncidentID: "INC-1", Level: "high", RuleTitle: "SSH", ActorName: "203.0.113.7", Node: "web-01",
		Chain: []string{"10:00:00 linux.auth web-01 ssh.login.failure 203.0.113.7 user=i.petrov@corp.local"}}

	res := a.Analyze(context.Background(), inc, "fake-cloud", nil)
	if res.Err != nil || !res.Shown || res.Tokens != 7 || res.Model != "fake-1" || fb.calls != 1 {
		t.Fatalf("%+v calls=%d", res, fb.calls)
	}
	if fb.system != systemPrompt || !strings.Contains(fb.prompt, "<<<EVENT_DATA") || fb.profile.Backend != "fake" {
		t.Fatalf("бэкенд получил не тот промпт: %q", fb.prompt)
	}
	// облачный профиль: данные редактируются и обезличиваются до бэкенда
	if strings.Contains(fb.prompt, "i.petrov@corp.local") || strings.Contains(fb.prompt, "web-01") {
		t.Fatalf("данные ушли в бэкенд без редакции: %q", fb.prompt)
	}
	// ПДн → только профиль без egress, даже если правило просит облачный
	inc.PII = 1
	res = a.Analyze(context.Background(), inc, "fake-cloud", nil)
	if res.Err != nil || res.Profile != "fake-local" || fb.profile.Egress != "deny" {
		t.Fatalf("ПДн должен уйти в fake-local: %+v", res)
	}
	// decideShown скрывает выдумку и у стороннего бэкенда
	fb.verdict = Verdict{SummaryRU: "Замечен майнер на контроллере домена, нужна изоляция.", Evidence: []string{"xmrig на dc-01"}, FirstAction: "изолировать", Confidence: 0.99}
	inc.PII = 0
	res = a.Analyze(context.Background(), inc, "fake-cloud", nil)
	if res.Err != nil || res.Shown || !strings.Contains(res.ShownReason, "evidence") {
		t.Fatalf("evidence не из данных должен скрывать вердикт любого бэкенда: %+v", res)
	}
	// схема проверяется до показа
	fb.verdict = Verdict{SummaryRU: "x"}
	if res = a.Analyze(context.Background(), inc, "fake-cloud", nil); res.Err == nil || !strings.Contains(res.Err.Error(), "схема") {
		t.Fatalf("пустой вердикт должен отклоняться: %+v", res)
	}
	// ошибка бэкенда — ошибка разбора
	fb.verdict, fb.err = good, errors.New("модель недоступна")
	if res = a.Analyze(context.Background(), inc, "fake-cloud", nil); res.Err == nil || res.Shown {
		t.Fatalf("ошибка бэкенда потеряна: %+v", res)
	}
}

func TestUnknownBackendIsConfigError(t *testing.T) {
	c := cfg()
	c.Profiles["typo"] = Profile{Backend: "openai-compatibel", Endpoint: "https://10.0.0.9/v1"}
	problems := c.Validate()
	if len(problems) != 1 || !strings.Contains(problems[0], "profiles.typo") || !strings.Contains(problems[0], `"openai-compatibel"`) || !strings.Contains(problems[0], "mock, openai-compatible") {
		t.Fatalf("%v", problems)
	}
	if _, _, err := New(c).Route(&incidents.Incident{}, "typo"); err == nil {
		t.Fatal("маршрут на неизвестный бэкенд должен отказывать")
	}
	// LoadConfig на файле: ошибка на старте, а не на первом разборе
	p := filepath.Join(t.TempDir(), "a.yml")
	_ = os.WriteFile(p, []byte("profiles:\n  x: {backend: nosuch}\ndefault_profile: x\n"), 0o600)
	if _, err := LoadConfig(p); err == nil || !strings.Contains(err.Error(), "nosuch") {
		t.Fatalf("LoadConfig: %v", err)
	}
	_ = os.WriteFile(p, []byte("profiles:\n  x: {backend: mock}\ndefault_profile: nosuch\n"), 0o600)
	if _, err := LoadConfig(p); err == nil || !strings.Contains(err.Error(), "default_profile") {
		t.Fatalf("LoadConfig: %v", err)
	}
	// пустое имя бэкенда — openai-compatible
	c = cfg()
	c.Profiles["plain"] = Profile{Endpoint: "https://10.0.0.9/v1"}
	if problems := c.Validate(); len(problems) != 0 {
		t.Fatalf("пустой backend = openai-compatible: %v", problems)
	}
	if b, err := backendFor(c.Profiles["plain"]); err != nil || b == nil {
		t.Fatal(err)
	}
	if got := Backends(); strings.Join(got, ",") != "mock,openai-compatible" {
		t.Fatalf("реестр: %v", got)
	}
}

// mock строит вердикт из того же промпта, что получает модель: уровень из
// шапки, цепочка из блока данных.
func TestMockVerdictFromPrompt(t *testing.T) {
	inc := &incidents.Incident{IncidentID: "INC-3", Level: "critical", RuleID: "r-1", RuleTitle: "WAF RCE", ActorName: "203.0.113.9", Node: "shop",
		Sources: []string{"waf"}, EventCount: 3, FirstTS: "2026-09-10 10:00:00", LastTS: "2026-09-10 10:01:00", Chain: []string{"10:00:00 waf shop http.attack GET /x", "10:00:30 waf shop http.attack GET /y"}}
	v := mockVerdict(buildHeader(inc) + "<<<EVENT_DATA\n" + buildData(inc, false) + "EVENT_DATA>>>\n")
	if v.Confidence != 0.9 || !strings.Contains(v.SummaryRU, "«WAF RCE»") || !strings.Contains(v.SummaryRU, "203.0.113.9") || !strings.Contains(v.SummaryRU, "3 событий") {
		t.Fatalf("%+v", v)
	}
	if len(v.Evidence) != 2 || v.Evidence[1] != "первое событие: 10:00:00 waf shop http.attack GET /x" {
		t.Fatalf("evidence %v", v.Evidence)
	}
	if err := validate(v); err != nil {
		t.Fatal(err)
	}
}
