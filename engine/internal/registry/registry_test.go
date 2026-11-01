package registry

import (
	"bufio"
	"bytes"
	"encoding/json"
	"io/fs"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/devitex-soft/argus/engine/internal/rules"
)

const root = "../../.."

// exact — точные значения поля key (без модификаторов |contains и т. п.).
func exact(m map[string]any, key string, into map[string]bool) {
	for k, v := range m {
		if k != key {
			continue
		}
		switch x := v.(type) {
		case string:
			into[x] = true
		case []any:
			for _, s := range x {
				if s, ok := s.(string); ok {
					into[s] = true
				}
			}
		}
	}
}

func build(t *testing.T) Shipped {
	t.Helper()
	out := Shipped{Rules: map[string]Rule{}}
	src, act := map[string]bool{}, map[string]bool{}
	err := filepath.WalkDir(filepath.Join(root, "rules"), func(p string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			if d.Name() == "tests" {
				return filepath.SkipDir
			}
			return nil
		}
		if !strings.HasSuffix(p, ".yml") {
			return nil
		}
		r, err := rules.LoadFile(p)
		if err != nil {
			return err
		}
		out.Rules[r.ID] = Rule{Title: r.Title, Tags: r.Tags}
		for _, m := range []map[string]any{r.Detection.Selection, r.Detection.Filter, r.Detection.Reset, r.CloseOn} {
			exact(m, "source", src)
			exact(m, "action", act)
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	files, _ := filepath.Glob(filepath.Join(root, "fixtures", "events", "*.ndjson"))
	for _, f := range files {
		b, err := os.ReadFile(f)
		if err != nil {
			t.Fatal(err)
		}
		sc := bufio.NewScanner(bytes.NewReader(b))
		sc.Buffer(make([]byte, 1<<20), 1<<24)
		for sc.Scan() {
			var e struct{ Source, Action string }
			if json.Unmarshal(sc.Bytes(), &e) == nil {
				if e.Source != "" {
					src[e.Source] = true
				}
				if e.Action != "" {
					act[e.Action] = true
				}
			}
		}
	}
	for s := range src {
		out.Sources = append(out.Sources, s)
	}
	for a := range act {
		out.Actions = append(out.Actions, a)
	}
	slices.Sort(out.Sources)
	slices.Sort(out.Actions)
	return out
}

func TestShippedRegistry(t *testing.T) {
	want := build(t)
	got, _ := json.MarshalIndent(want, "", " ")
	got = append(got, '\n')
	if os.Getenv("UPDATE_GOLDEN") == "1" {
		if err := os.WriteFile("shipped.json", got, 0o644); err != nil {
			t.Fatal(err)
		}
		return
	}
	if !bytes.Equal(got, raw) {
		t.Fatal("shipped.json не совпадает с rules/ и fixtures/events — перегенерируйте: UPDATE_GOLDEN=1 go test ./internal/registry")
	}
}

func TestLookups(t *testing.T) {
	if r, ok := LookupRule("a41c-auth-031"); !ok || r.Title == "" {
		t.Fatal("поставляемое правило")
	}
	if _, ok := LookupRule("pr64-rule-title"); ok {
		t.Fatal("пользовательское правило не в реестре")
	}
	if !Source("host.sshd") || Source("edr.alice-pc") || !Action("auth.ssh") || Action("event.alice_smirnov") {
		t.Fatal("source/action")
	}
	if !Tag("attack.t1110.001") || !Tag("attack.credential_access") || Tag("owner:alice@example.invalid") || Tag("owner:alice") {
		t.Fatal("теги")
	}
}
