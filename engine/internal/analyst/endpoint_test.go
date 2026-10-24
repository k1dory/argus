package analyst

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/devitex-soft/argus/engine/internal/incidents"
)

const endpointYAML = `
profiles:
  on-prem-strict:
    backend: openai-compatible
    endpoint: ${ARGUS_LLM_LOCAL_ENDPOINT:-}
    model: m
    egress: deny
    allow_plain_http: true
  mock:
    backend: mock
default_profile: ${ARGUS_ANALYST_PROFILE:-mock}
`

// У endpoint нет рабочего умолчания: выбранный профиль без адреса — ошибка
// на старте; невыбранный — не мешает старту, но разбор по нему отказывает понятно.
func TestEndpointRequiredOnlyWhenSelected(t *testing.T) {
	p := filepath.Join(t.TempDir(), "a.yml")
	if err := os.WriteFile(p, []byte(endpointYAML), 0o600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("ARGUS_LLM_LOCAL_ENDPOINT", "")
	t.Setenv("ARGUS_ANALYST_PROFILE", "")
	cfg, err := LoadConfig(p)
	if err != nil {
		t.Fatalf("невыбранный профиль без endpoint не должен ломать старт: %v", err)
	}
	// Правило выбрало on-prem-strict — разбор отказывает с понятной причиной.
	_, _, err = New(cfg).Route(&incidents.Incident{}, "on-prem-strict")
	if err == nil || !strings.Contains(err.Error(), "ARGUS_LLM_LOCAL_ENDPOINT") {
		t.Fatalf("ожидалась ошибка про endpoint: %v", err)
	}
	if _, _, err := New(cfg).Route(&incidents.Incident{}, "mock"); err != nil {
		t.Fatalf("mock без endpoint допустим: %v", err)
	}

	t.Setenv("ARGUS_ANALYST_PROFILE", "on-prem-strict")
	if _, err := LoadConfig(p); err == nil || !strings.Contains(err.Error(), "default_profile: profiles.on-prem-strict") || !strings.Contains(err.Error(), "ARGUS_LLM_LOCAL_ENDPOINT") {
		t.Fatalf("выбранный профиль без endpoint — ошибка старта: %v", err)
	}
	t.Setenv("ARGUS_LLM_LOCAL_ENDPOINT", "http://10.0.0.5:8000/v1")
	if _, err := LoadConfig(p); err != nil {
		t.Fatalf("с адресом профиль валиден: %v", err)
	}
}

// Файл репозитория: endpoint on-prem-strict берётся только из переменной.
func TestRepoConfigHasNoEndpointFallback(t *testing.T) {
	raw, err := os.ReadFile(filepath.Join("..", "..", "argus.analyst.yml"))
	if err != nil {
		t.Skip("argus.analyst.yml недоступен:", err)
	}
	if strings.Contains(string(raw), "llm.internal") || !strings.Contains(string(raw), "${ARGUS_LLM_LOCAL_ENDPOINT:-}") {
		t.Fatal("endpoint on-prem-strict должен быть ${ARGUS_LLM_LOCAL_ENDPOINT:-} без рабочего умолчания")
	}
}
