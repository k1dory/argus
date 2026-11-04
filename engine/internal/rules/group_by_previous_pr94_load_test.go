package rules

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// Exercise the directory loader, including the effective threshold grouping
// and the implicit actor grouping, rather than only calling LoadFile directly.
func TestPR94GroupByPreviousDirectoryValidation(t *testing.T) {
	for _, tc := range []struct {
		name, group, thresholdGroup, previous, wantErr string
	}{
		{"absent opt-in", "object, attrs.detail", "", "", ""},
		{"scalar change", "object, attrs.detail", "", "object", ""},
		{"composite change", "object, attrs.detail, node", "", " object , attrs.detail ", ""},
		{"unknown scalar", "object", "", "nosuch.field", "group_by_previous: неизвестное поле"},
		{"unknown component", "object", "", "attrs.detail, nosuch.field", "group_by_previous: неизвестное поле"},
		{"empty component", "object", "", "attrs.detail,", "group_by_previous: неизвестное поле"},
		{"equal scalar", "object", "", "object", "совпадает с group_by"},
		{"equal normalized composite", "object, attrs.detail", "", " object ,attrs.detail ", "совпадает с group_by"},
		{"equal implicit grouping", "", "", "actor.name", "совпадает с group_by"},
		{"equal effective threshold", "object", "object, attrs.detail", "object ,attrs.detail", "совпадает с group_by"},
		{"threshold overrides detection", "object", "object, attrs.detail", "object", ""},
	} {
		t.Run(tc.name, func(t *testing.T) {
			dir := t.TempDir()
			if err := os.Mkdir(filepath.Join(dir, "ops"), 0o700); err != nil {
				t.Fatal(err)
			}
			yml := fmt.Sprintf("title: Migration validation\nid: pr94-load-review\nlevel: high\ndetection:\n  selection: {action: test.failure}\n  group_by: %q\n", tc.group)
			if tc.thresholdGroup != "" {
				yml += fmt.Sprintf("  condition: selection and threshold\n  threshold:\n    count: 1\n    window: 5m\n    group_by: %q\n", tc.thresholdGroup)
			}
			if tc.previous != "" {
				yml += fmt.Sprintf("  group_by_previous: %q\n", tc.previous)
			}
			if err := os.WriteFile(filepath.Join(dir, "ops", "migration.yml"), []byte(yml), 0o600); err != nil {
				t.Fatal(err)
			}
			loaded, err := Load(dir)
			if tc.wantErr != "" {
				if err == nil || !strings.Contains(err.Error(), tc.wantErr) || !strings.Contains(err.Error(), "ops/migration.yml") {
					t.Fatalf("want contextual validation error %q; rules=%+v err=%v", tc.wantErr, loaded, err)
				}
				if loaded != nil {
					t.Fatalf("an invalid migration must not produce a usable rule set: %+v", loaded)
				}
				return
			}
			if err != nil || len(loaded) != 1 {
				t.Fatalf("valid migration rejected: rules=%+v err=%v", loaded, err)
			}
			if loaded[0].Detection.GroupByPrevious != tc.previous {
				t.Fatalf("loader lost the explicit opt-in: got %q want %q", loaded[0].Detection.GroupByPrevious, tc.previous)
			}
		})
	}
}
