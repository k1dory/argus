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

// Неизвестное поле правила — ошибка загрузки: движок, который поля не знает (rc33 и
// group_by_previous), не применяет новый набор частично. Живой случай argus1
// 2026-11-01: rc33 перечитал правило с новым group_by и пропущенным group_by_previous
// и завёл INC-5370 рядом с открытым INC-5312.
func TestLoadRejectsUnknownFields(t *testing.T) {
	for _, extra := range []string{"  group_by_next: attrs.peer\n", "unknown_top: 1\n"} {
		yml := "title: t\nid: t-strict\nlevel: low\ndetection:\n  selection: {action: x}\n  condition: selection\n" + extra
		path := filepath.Join(t.TempDir(), "r.yml")
		if err := os.WriteFile(path, []byte(yml), 0o600); err != nil {
			t.Fatal(err)
		}
		if _, err := LoadFile(path); err == nil || !strings.Contains(err.Error(), "not found") {
			t.Fatalf("%q: неизвестное поле принято: %v", extra, err)
		}
	}
}
