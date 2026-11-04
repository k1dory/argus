package model

import (
	"fmt"
	"reflect"
	"strings"
	"testing"
)

// После удаления NUL каждый проход удаляет только одну внутреннюю пару C2 80.
// Восемь вложенных пар требуют девяти проходов: ограничение cleanStable не
// должно оставлять ключ или значение, меняющиеся при следующем Sanitize.
func TestPR110Round2SanitizeAttrsReachesFixedPoint(t *testing.T) {
	for _, depth := range []int{7, 8, 9, 15, 32} {
		for _, field := range []string{"key", "value"} {
			t.Run(fmt.Sprintf("%s/depth_%d", field, depth), func(t *testing.T) {
				dirty := "a" + strings.Repeat("\xc2", depth) + "\x00" + strings.Repeat("\x80", depth) + "b"
				e := Event{Raw: dirty, Attrs: map[string]string{"payload": dirty}}
				want := map[string]string{"payload": "ab"}
				if field == "key" {
					e.Attrs = map[string]string{dirty: "payload"}
					want = map[string]string{"ab": "payload"}
				}

				e.Sanitize()
				if !reflect.DeepEqual(e.Attrs, want) {
					t.Errorf("Sanitize left an unstable attribute: got %q, want %q", e.Attrs, want)
				}
				before := make(map[string]string, len(e.Attrs))
				for k, v := range e.Attrs {
					before[k] = v
				}
				e.Sanitize()
				if !reflect.DeepEqual(e.Attrs, before) {
					t.Errorf("a second Sanitize changed attrs: before=%q after=%q", before, e.Attrs)
				}
				if e.Raw != dirty {
					t.Fatal("sanitizing attributes changed raw evidence")
				}
			})
		}
	}
}
