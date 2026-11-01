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
