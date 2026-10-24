package analyst

import (
	"context"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/devitex-soft/argus/engine/internal/incidents"
)

func cfg() Config {
	c := Config{Profiles: map[string]Profile{
		"mock":           {Backend: "mock"},
		"on-prem-strict": {Backend: "openai-compatible", Endpoint: "http://10.0.0.5:8000/v1", Model: "qwen", Egress: "deny", AllowPlainHTTP: true},
		"cloud-fast":     {Backend: "openai-compatible", Endpoint: "https://8.8.8.8/v1", Model: "x"},
	}, DefaultProfile: "cloud-fast", PIIProfile: "on-prem-strict"}
	c.Output.RejectIfConfidenceBelow = 0.35
	return c
}

func TestRedactPatternsAndFields(t *testing.T) {
	a := New(cfg())
	in := "user=i.petrov@corp.local phone +7 (912) 345-67-89 serial=SN-12345 passport 4510 123456 card 4276 1234 5678 9012"
	out := a.redact(in, []string{"host.serial"}, false, nil)
	for _, leak := range []string{"@corp.local", "912", "SN-12345", "4510 123456", "4276"} {
		if strings.Contains(out, leak) {
			t.Fatalf("утечка %q в %q", leak, out)
		}
	}
	if !strings.Contains(out, "serial=[REDACTED]") {
		t.Fatalf("поле из правила не замаскировано: %q", out)
	}
}

func TestRoutePIIForcesLocalProfile(t *testing.T) {
	a := New(cfg())
	name, _, err := a.Route(&incidents.Incident{PII: 1}, "cloud-fast")
	if err != nil || name != "on-prem-strict" {
		t.Fatalf("ПДн → on-prem-strict, получено %s %v", name, err)
	}
	name, _, err = a.Route(&incidents.Incident{PII: 0}, "cloud-fast")
	if err != nil || name != "cloud-fast" {
		t.Fatalf("без ПДн профиль правила сохраняется: %s %v", name, err)
	}
	// pii_profile с egress разрешён — отказ, а не тихая отправка
	c := cfg()
	c.PIIProfile = "cloud-fast"
	if _, _, err := New(c).Route(&incidents.Incident{PII: 1}, ""); err == nil {
		t.Fatal("профиль с egress не должен принимать ПДн")
	}
}

func TestEgressGuard(t *testing.T) {
	a := New(cfg())
	if err := a.egressGuard(Profile{Endpoint: "http://10.0.0.5:8000/v1", Egress: "deny"}); err == nil {
		t.Fatal("strict без allow_plain_http должен требовать https")
	}
	if err := a.egressGuard(Profile{Endpoint: "http://10.0.0.5:8000/v1", Egress: "deny", AllowPlainHTTP: true}); err != nil {
		t.Fatalf("приватный адрес с allow_plain_http разрешён: %v", err)
	}
	if err := a.egressGuard(Profile{Endpoint: "https://10.0.0.5:8000/v1", Egress: "deny"}); err != nil {
		t.Fatalf("приватный адрес по https разрешён: %v", err)
	}
	if err := a.egressGuard(Profile{Endpoint: "https://8.8.8.8/v1", Egress: "deny"}); err == nil {
		t.Fatal("публичный адрес при egress deny должен блокироваться")
	}
	if err := a.egressGuard(Profile{Endpoint: "https://8.8.8.8/v1", Egress: "deny", Allow: []string{"8.8.8.8"}}); err != nil {
		t.Fatalf("allow_hosts не сработал: %v", err)
	}
}

func TestMockVerdictAndThreshold(t *testing.T) {
	a := New(cfg())
	crit := a.Analyze(context.Background(), &incidents.Incident{IncidentID: "INC-1", Level: "critical", RuleTitle: "t", Chain: []string{"x"}}, "mock", nil)
	if crit.Err != nil || !crit.Shown || crit.Verdict.Confidence < 0.35 {
		t.Fatalf("%+v", crit)
	}
	low := a.Analyze(context.Background(), &incidents.Incident{IncidentID: "INC-2", Level: "low", RuleTitle: "t"}, "mock", nil)
	if low.Err != nil || low.Shown {
		t.Fatalf("низкая уверенность не должна показываться: %+v", low)
	}
}

func TestExpandEnvDefaults(t *testing.T) {
	t.Setenv("ARGUS_T_SET", "value")
	t.Setenv("ARGUS_T_EMPTY", "")
	os.Unsetenv("ARGUS_T_UNSET")
	got, unresolved := expandEnv("a=${ARGUS_T_SET} b=${ARGUS_T_UNSET:-def} c=${ARGUS_T_UNSET} d=${ARGUS_T_EMPTY} e=${ARGUS_T_EMPTY:-def2} f=${ip} g=${ARGUS_T_UNSET}")
	// не заданная переменная без default остаётся как есть (и попадает в список), пустая заданная — пустота, пустая с default — default
	if got != "a=value b=def c=${ARGUS_T_UNSET} d= e=def2 f=${ip} g=${ARGUS_T_UNSET}" {
		t.Fatalf("%q", got)
	}
	if len(unresolved) != 1 || unresolved[0] != "ARGUS_T_UNSET" {
		t.Fatalf("unresolved: %v", unresolved)
	}
}

// Шаблонные плейсхолдеры исполнителей не подставляются даже при наличии
// одноимённой переменной окружения: иначе NGFW получил бы {"ip": ""} или чужой адрес.
func TestExpandEnvSkipsExecutorTemplates(t *testing.T) {
	t.Setenv("ip", "1.2.3.4")
	t.Setenv("incident", "x")
	t.Setenv("reason", "y")
	tpl := `body: '{"ip": "${ip}", "comment": "ARGUS ${incident}: ${reason}"}'`
	if got := ExpandEnv(tpl); got != tpl {
		t.Fatalf("%q", got)
	}
}

// LoadConfig на настоящем argus.analyst.yml: шаблоны блокировки/снятия
// доходят до respond.Config нетронутыми, без переменных окружения вообще.
func TestLoadConfigKeepsTemplatePlaceholders(t *testing.T) {
	for _, k := range []string{"NGFW_BLOCK_URL", "NGFW_UNBLOCK_URL", "NGFW_TOKEN", "ip", "incident", "reason"} {
		os.Unsetenv(k)
	}
	cfg, err := LoadConfig(filepath.Join("..", "..", "argus.analyst.yml"))
	if err != nil {
		t.Fatal(err)
	}
	if len(cfg.Respond.HTTP) == 0 {
		t.Fatal("в argus.analyst.yml ожидается HTTP-исполнитель")
	}
	h := cfg.Respond.HTTP[0]
	if !strings.Contains(h.Body, "${ip}") || !strings.Contains(h.Body, "${incident}") || !strings.Contains(h.Body, "${reason}") {
		t.Fatalf("шаблон блокировки потерял плейсхолдеры: %q", h.Body)
	}
	if h.Unblock == nil || !strings.Contains(h.Unblock.Body, "${ip}") {
		t.Fatalf("шаблон снятия потерял плейсхолдеры: %+v", h.Unblock)
	}
	// значение с default подставилось, plain-контекст сохранил тип
	if cfg.Notify.Email.Port != 587 || cfg.Respond.Mode != "simulate" {
		t.Fatalf("defaults: port=%d mode=%q", cfg.Notify.Email.Port, cfg.Respond.Mode)
	}
	// и наоборот: заданный NGFW_TOKEN подставляется в заголовок, шаблон в теле по-прежнему цел
	t.Setenv("NGFW_TOKEN", "s3cret")
	cfg, err = LoadConfig(filepath.Join("..", "..", "argus.analyst.yml"))
	if err != nil {
		t.Fatal(err)
	}
	if cfg.Respond.HTTP[0].Headers["Authorization"] != "Bearer s3cret" || !strings.Contains(cfg.Respond.HTTP[0].Body, "${ip}") {
		t.Fatalf("%+v", cfg.Respond.HTTP[0])
	}
}

// Контекст кавычек — по открывающей кавычке значения, а не по чётности
// кавычек в строке: внутри '…' с JSON в двойных кавычках апостроф удваивается,
// а обратный слеш не появляется.
func TestExpandEnvQuoteContext(t *testing.T) {
	t.Setenv("ARGUS_T_Q", `it's "x"`)
	var doc struct {
		Body string `yaml:"body"`
		Hdr  string `yaml:"hdr"`
		Raw  string `yaml:"raw"`
	}
	src := "body: '{\"ip\": \"${ip}\", \"c\": \"${ARGUS_T_Q}\"}'\n" +
		"hdr: \"Bearer ${ARGUS_T_Q}\"\n" +
		"raw: ${ARGUS_T_Q}\n"
	out := ExpandEnv(src)
	if err := yamlUnmarshal(out, &doc); err != nil {
		t.Fatalf("%v\n%s", err, out)
	}
	if doc.Body != `{"ip": "${ip}", "c": "it's "x""}` || doc.Hdr != `Bearer it's "x"` || doc.Raw != `it's "x"` {
		t.Fatalf("%+v\n%s", doc, out)
	}
	if quoteContext(`a: "x" b: 'y `) != '\'' || quoteContext(`a: "x\"y `) != '"' || quoteContext(`a: 'it''s `) != '\'' || quoteContext(`a: 'x' `) != 0 {
		t.Fatal("quoteContext")
	}
}

// Прокси из окружения — только облачным профилям; egress deny соединяется напрямую.
func TestClientProxyOnlyForCloud(t *testing.T) {
	a := New(cfg())
	cloud, err := a.client("cloud-fast", a.cfg.Profiles["cloud-fast"])
	if err != nil {
		t.Fatal(err)
	}
	strict, err := a.client("on-prem-strict", a.cfg.Profiles["on-prem-strict"])
	if err != nil {
		t.Fatal(err)
	}
	if cloud.Transport.(*http.Transport).Proxy == nil {
		t.Fatal("облачный профиль должен уважать HTTPS_PROXY из окружения")
	}
	if strict.Transport.(*http.Transport).Proxy != nil {
		t.Fatal("egress deny не должен ходить через прокси")
	}
}

func TestReplaceWordBoundaries(t *testing.T) {
	cases := []struct{ text, name, want string }{
		{"user ann opened channel; ann again", "ann", "user U opened channel; U again"},
		{"ivanova and ivan", "ivan", "ivanova and U"},
		{"login=petrov,host", "petrov", "login=U,host"},
		{"i.petrov@corp", "petrov", "i.U@corp"},
		{"ann", "ann", "U"},
		{"Иванов и Иванова", "Иванов", "U и Иванова"},
	}
	for _, c := range cases {
		if got := replaceWord(c.text, c.name, "U"); got != c.want {
			t.Errorf("%q/%q: got %q, want %q", c.text, c.name, got, c.want)
		}
	}
	inc := &incidents.Incident{ActorName: "ann", Node: "db"}
	got := anonymize("ann on db: channel closed, dbx", inc)
	if !strings.HasPrefix(got, "user-") || !strings.Contains(got, " on host-") || !strings.Contains(got, "channel closed, dbx") {
		t.Fatalf("учётка и узел — только целым словом: %q", got)
	}
}

func TestForceProfileOverridesRule(t *testing.T) {
	c := cfg()
	c.ForceProfile = "mock"
	name, _, err := New(c).Route(&incidents.Incident{}, "cloud-fast")
	if err != nil || name != "mock" {
		t.Fatalf("force_profile должен перекрывать профиль правила: %s %v", name, err)
	}
}
