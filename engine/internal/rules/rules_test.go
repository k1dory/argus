package rules

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/devitex-soft/argus/engine/internal/model"
)

func load(t *testing.T, yml string) *Rule {
	t.Helper()
	p := filepath.Join(t.TempDir(), "r.yml")
	_ = os.WriteFile(p, []byte(yml), 0o600)
	r, err := LoadFile(p)
	if err != nil {
		t.Fatal(err)
	}
	return r
}

func TestModifiersAndOperators(t *testing.T) {
	r := load(t, `
title: m
id: m-1
level: low
detection:
  selection:
    object|regex: '(?i)temp'
    attrs.name|startswith: susp
    severity: '>= 7'
    event.action: [threat.detect, process.create]
    node|endswith: '-01'
  condition: selection
`)
	e := &model.Event{Action: "threat.detect", Object: `C:\Temp\x.exe`, Severity: 8, Node: "wks-01", Attrs: map[string]string{"name": "Suspicious"}}
	if !r.Match(e) {
		t.Fatal("должно совпасть")
	}
	e.Severity = 6
	if r.Match(e) {
		t.Fatal("severity 6 < 7 — не должно")
	}
}

func TestLoadRejectsBrokenRules(t *testing.T) {
	cases := map[string]string{
		"без id":                "title: x\ndetection:\n  selection: {a: b}\n",
		"чужое поле":            "title: x\nid: y\ndetection:\n  selection: {nosuch.field: b}\n",
		"порог без окна":        "title: x\nid: y\ndetection:\n  selection: {node: a}\n  threshold: {count: 3}\n  condition: selection and threshold\n",
		"consecutive без reset": "title: x\nid: y\ndetection:\n  selection: {value: '>= 90'}\n  threshold: {kind: consecutive, count: 3, window: 15m}\n  condition: selection and threshold\n",
		"consecutive count 1":   "title: x\nid: y\ndetection:\n  selection: {value: '>= 90'}\n  reset: {value: '< 90'}\n  threshold: {kind: consecutive, count: 1, window: 15m}\n  condition: selection and threshold\n",
		"reset с чужим полем":   "title: x\nid: y\ndetection:\n  selection: {value: '>= 90'}\n  reset: {nosuch: 1}\n  threshold: {kind: consecutive, count: 3, window: 15m}\n  condition: selection and threshold\n",
	}
	for name, yml := range cases {
		p := filepath.Join(t.TempDir(), "r.yml")
		_ = os.WriteFile(p, []byte(yml), 0o600)
		if _, err := LoadFile(p); err == nil {
			t.Errorf("%s: ожидалась ошибка загрузки", name)
		}
	}
}

func TestRepoRulesLoad(t *testing.T) {
	rs, err := Load("../../../rules")
	if err != nil {
		t.Fatal(err)
	}
	if len(rs) < 7 {
		t.Fatalf("правил в репозитории %d", len(rs))
	}
	seen := map[string]bool{}
	for _, r := range rs {
		if seen[r.ID] {
			t.Fatalf("дубль id %s", r.ID)
		}
		seen[r.ID] = true
	}
}

func TestRespondMinEvents(t *testing.T) {
	r := load(t, "title: x\nid: y\nlevel: critical\ndetection:\n  selection: {node: a}\nrespond: {action: block_ip}\n")
	if r.RespondMinEvents() != 1 {
		t.Fatalf("умолчание min_events = 1, got %d", r.RespondMinEvents())
	}
	r = load(t, "title: x\nid: y\nlevel: critical\ndetection:\n  selection: {node: a}\nrespond: {action: block_ip, min_events: 3}\n")
	if r.RespondMinEvents() != 3 {
		t.Fatalf("got %d", r.RespondMinEvents())
	}
	p := filepath.Join(t.TempDir(), "r.yml")
	_ = os.WriteFile(p, []byte("title: x\nid: y\ndetection:\n  selection: {node: a}\nrespond: {action: block_ip, min_events: -1}\n"), 0o600)
	if _, err := LoadFile(p); err == nil {
		t.Fatal("отрицательный min_events — ошибка загрузки")
	}
	rs, err := Load("../../../rules")
	if err != nil {
		t.Fatal(err)
	}
	for _, r := range rs {
		if r.ID == "a41c-waf-053" && r.RespondMinEvents() != 2 {
			t.Fatalf("waf-rce-critical: блок со второго события, got %d", r.RespondMinEvents())
		}
	}
}

func TestCloseMatchAndAutoCloseAction(t *testing.T) {
	r := load(t, `
title: t
id: t-1
level: high
detection: {selection: {source.class: cicd}, condition: selection}
close_on: {event.action|contains: token_rotated}
close_match: [object, attrs.secret_id]
auto_close: 4h
auto_close_action: escalate
`)
	if !r.AutoCloseEscalates() {
		t.Fatal("escalate")
	}
	e := &model.Event{Object: "Group/A", Attrs: map[string]string{"secret_id": " Tok-1 "}}
	if k, ok := r.CloseMatchKey(e); !ok || k != "group/a\x00tok-1" {
		t.Fatalf("ключ %q %v", k, ok)
	}
	if _, ok := r.CloseMatchKey(&model.Event{Object: "Group/A"}); ok {
		t.Fatal("пустое поле — сопоставить нельзя")
	}
	for name, yml := range map[string]string{
		"action": "title: t\nid: t-2\nlevel: high\ndetection: {selection: {source.class: x}, condition: selection}\nauto_close: 1h\nauto_close_action: delete\n",
		"field":  "title: t\nid: t-3\nlevel: high\ndetection: {selection: {source.class: x}, condition: selection}\nclose_on: {action: x}\nclose_match: [nosuch]\n",
		"orphan": "title: t\nid: t-4\nlevel: high\ndetection: {selection: {source.class: x}, condition: selection}\nclose_match: [object]\n",
	} {
		p := filepath.Join(t.TempDir(), "r.yml")
		_ = os.WriteFile(p, []byte(yml), 0o600)
		if _, err := LoadFile(p); err == nil {
			t.Errorf("%s: ожидалась ошибка", name)
		}
	}
}

// value/unit — числовое измерение: сравнивается операторами как любое поле.
func TestValueAndUnitGetters(t *testing.T) {
	r := load(t, `
title: disk
id: d-1
level: high
detection:
  selection:
    source.class: telemetry
    action: disk.usage
    value: '>= 90'
  condition: selection
close_on:
  action: disk.usage
  value: '< 85'
`)
	hot := &model.Event{SourceClass: "telemetry", Action: "disk.usage", Value: 91.5, Unit: "percent"}
	if !r.Match(hot) || r.MatchClose(hot) {
		t.Fatal("91.5 ≥ 90 — совпадение, не закрытие")
	}
	cold := &model.Event{SourceClass: "telemetry", Action: "disk.usage", Value: 84.9, Unit: "percent"}
	if r.Match(cold) || !r.MatchClose(cold) {
		t.Fatal("84.9 < 85 — закрытие, не совпадение")
	}
	if Getter("value")(hot) != "91.5" || Getter("unit")(hot) != "percent" || Getter("value")(&model.Event{}) != "0" {
		t.Fatalf("getter: %q %q", Getter("value")(hot), Getter("unit")(hot))
	}
	big := &model.Event{Value: 1e21}
	if Getter("value")(big) != "1e+21" {
		t.Fatalf("большое число: %q", Getter("value")(big))
	}
	u := load(t, "title: u\nid: u-1\nlevel: low\ndetection:\n  selection: {unit: percent, value: '> 50'}\n")
	if !u.Match(&model.Event{Value: 51, Unit: "percent"}) || u.Match(&model.Event{Value: 51, Unit: "bytes"}) {
		t.Fatal("unit сравнивается как строка")
	}
}

// Load читает подкаталоги (wazuh/, ops/), пропускает tests/ и запоминает
// относительный путь файла.
func TestLoadRecursiveSkipsTests(t *testing.T) {
	dir := t.TempDir()
	rule := func(id string) string {
		return "title: x\nid: " + id + "\nlevel: low\ndetection:\n  selection: {node: a}\n"
	}
	for p, body := range map[string]string{
		"top.yml":           rule("top"),
		"wazuh/agent.yaml":  rule("agent"),
		"ops/disk.yml":      rule("disk"),
		"tests/disk.yml":    "rule: disk\nfixture: f\nexpect_incidents: 1\n",
		"ops/tests/old.yml": "not a rule",
		"ops/readme.md":     "не правило",
	} {
		full := filepath.Join(dir, filepath.FromSlash(p))
		_ = os.MkdirAll(filepath.Dir(full), 0o755)
		_ = os.WriteFile(full, []byte(body), 0o600)
	}
	rs, err := Load(dir)
	if err != nil {
		t.Fatal(err)
	}
	var files []string
	for _, r := range rs {
		files = append(files, r.File)
	}
	if got := strings.Join(files, ","); got != "ops/disk.yml,top.yml,wazuh/agent.yaml" {
		t.Fatalf("файлы: %s", got)
	}
	_ = os.WriteFile(filepath.Join(dir, "ops", "broken.yml"), []byte("title: x\n"), 0o600)
	if _, err := Load(dir); err == nil || !strings.Contains(err.Error(), "ops/broken.yml") {
		t.Fatalf("ошибка должна называть относительный путь: %v", err)
	}
	if _, err := Load(filepath.Join(dir, "nosuch")); err == nil {
		t.Fatal("несуществующий каталог — ошибка, а не пустой набор")
	}
}

// Правила репозитория разложены по подкаталогам: wazuh-специфичные — в
// wazuh/, мониторинг инфраструктуры — в ops/, вендор-нейтральные — в корне.
func TestRepoRulesLayout(t *testing.T) {
	rs, err := Load("../../../rules")
	if err != nil {
		t.Fatal(err)
	}
	byFile := map[string]*Rule{}
	for _, r := range rs {
		byFile[r.File] = r
	}
	for _, f := range []string{"wazuh/ssh-bruteforce.yml", "wazuh/agent-silence.yml", "wazuh/sudoers-change.yml", "ops/disk-usage-high.yml", "ops/host-silence.yml", "ops/argus-disk-low.yml", "waf-rce-critical.yml"} {
		if byFile[f] == nil {
			t.Errorf("нет правила %s", f)
		}
	}
	for f, r := range byFile {
		wazuh := false
		for k, v := range r.Detection.Selection {
			s := fmt.Sprint(v)
			if (k == "source" && s == "wazuh.agents") || (k == "source.class" && s == "wazuh") {
				wazuh = true
			}
		}
		if wazuh != strings.HasPrefix(f, "wazuh/") {
			t.Errorf("%s: правило по Wazuh должно лежать в wazuh/ (и только оно): %v", f, r.Detection.Selection)
		}
	}
}
