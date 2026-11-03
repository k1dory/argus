package rules

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// group_by_previous: известное поле и отличие от group_by проверяет загрузчик.
func TestGroupByPreviousValidation(t *testing.T) {
	for _, tc := range []struct{ prev, wantErr string }{
		{"attrs.peer", ""},
		{"nosuch.field", "group_by_previous: неизвестное поле"},
		{"attrs.peer ,attrs.source", "совпадает с group_by"},
	} {
		yml := "title: t\nid: t-prev\nlevel: low\ndetection:\n  selection: {action: x}\n  condition: selection\n  group_by: attrs.peer, attrs.source\n  group_by_previous: " + tc.prev + "\n"
		path := filepath.Join(t.TempDir(), "r.yml")
		if err := os.WriteFile(path, []byte(yml), 0o600); err != nil {
			t.Fatal(err)
		}
		r, err := LoadFile(path)
		switch {
		case tc.wantErr == "" && (err != nil || r.Detection.GroupByPrevious != tc.prev):
			t.Fatalf("%q: %v", tc.prev, err)
		case tc.wantErr != "" && (err == nil || !strings.Contains(err.Error(), tc.wantErr)):
			t.Fatalf("%q: ожидалась ошибка %q, получено %v", tc.prev, tc.wantErr, err)
		}
	}
}

// group_by_previous_before: только вместе с group_by_previous и в разбираемом формате.
func TestGroupByPreviousBeforeValidation(t *testing.T) {
	for _, tc := range []struct{ prev, before, wantErr string }{
		{"attrs.peer", "2026-11-01 17:56:44", ""},
		{"attrs.peer", "2026-11-01T17:56:44Z", ""},
		{"attrs.peer", "вчера", "group_by_previous_before"},
		{"", "2026-11-01 17:56:44", "без group_by_previous"},
	} {
		yml := "title: t\nid: t-before\nlevel: low\ndetection:\n  selection: {action: x}\n  condition: selection\n  group_by: attrs.peer, attrs.source\n"
		if tc.prev != "" {
			yml += "  group_by_previous: " + tc.prev + "\n"
		}
		yml += "  group_by_previous_before: \"" + tc.before + "\"\n"
		path := filepath.Join(t.TempDir(), "r.yml")
		if err := os.WriteFile(path, []byte(yml), 0o600); err != nil {
			t.Fatal(err)
		}
		r, err := LoadFile(path)
		switch {
		case tc.wantErr == "" && (err != nil || r.GroupByPreviousBefore().IsZero()):
			t.Fatalf("%q: %v", tc.before, err)
		case tc.wantErr != "" && (err == nil || !strings.Contains(err.Error(), tc.wantErr)):
			t.Fatalf("%q: ожидалась ошибка %q, получено %v", tc.before, tc.wantErr, err)
		}
	}
}

// Схема полей: неизвестное поле детекта — отказ правила (движок, который поле не
// знает, не применит правило частично: живой случай argus1 2026-11-01 — rc33
// перечитал правило с новым group_by, пропустил group_by_previous и завёл INC-5370
// рядом с открытым INC-5312). Неизвестное поле верхнего уровня и метаданные —
// правило загружается.
func TestLoadFieldSchema(t *testing.T) {
	base := "title: t\nid: t-strict\nlevel: low\ndetection:\n  selection: {action: x}\n  condition: selection\n"
	for _, tc := range []struct {
		extra  string
		reject bool
	}{
		{"  group_by_next: attrs.peer\n", true},
		{"  threshold: {count: 1, window: 5m, kind_next: x}\n", true},
		{"respond: {action: block_ip, ttl_next: 1h}\n", true},
		{"analyst: {profile: mock, mode: x}\n", true},
		{"unknown_top: 1\n", false},
		{"description: SOC rule\nauthor: SOC\nreferences: [x]\nfalsepositives: [y]\n", false},
	} {
		path := filepath.Join(t.TempDir(), "r.yml")
		if err := os.WriteFile(path, []byte(base+tc.extra), 0o600); err != nil {
			t.Fatal(err)
		}
		_, err := LoadFile(path)
		if tc.reject != (err != nil) || (tc.reject && !strings.Contains(err.Error(), "неизвестно этой версии движка")) {
			t.Fatalf("%q: reject=%v, ошибка %v", tc.extra, tc.reject, err)
		}
	}
}

// Отвергнутое правило не роняет остальные в LoadAll; Load (CLI) — ошибка с файлом.
func TestLoadAllRejectsOnlyBadRule(t *testing.T) {
	dir := t.TempDir()
	good := "title: g\nid: t-good\nlevel: low\ndetection:\n  selection: {action: x}\n  condition: selection\n"
	bad := "title: b\nid: t-bad\nlevel: low\ndetection:\n  selection: {action: x}\n  condition: selection\n  group_by_next: x\n"
	for name, body := range map[string]string{"a.yml": good, "b.yml": bad} {
		if err := os.WriteFile(filepath.Join(dir, name), []byte(body), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	rs, rejected, err := LoadAll(dir)
	if err != nil || len(rs) != 1 || rs[0].ID != "t-good" || len(rejected) != 1 || rejected[0].File != "b.yml" {
		t.Fatalf("LoadAll: rules=%d rejected=%+v err=%v", len(rs), rejected, err)
	}
	if _, err := Load(dir); err == nil || !strings.Contains(err.Error(), "b.yml") {
		t.Fatalf("Load должен отвергнуть каталог с плохим правилом: %v", err)
	}
}
