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
