package registry

import (
	"os"
	"path/filepath"
	"testing"
)

func TestEmptyUntilLoaded(t *testing.T) {
	current.Store(nil)
	if Loaded() {
		t.Fatal("без Load реестр пуст")
	}
	if _, ok := LookupRule("a41c-auth-031"); ok || Source("host.sshd") {
		t.Fatal("пустой реестр: любое правило — пользовательское")
	}
	if !Tag("attack.t1110.001") || Tag("owner:alice") {
		t.Fatal("теги ATT&CK распознаются и без реестра")
	}
}

func TestLoadRepoLookups(t *testing.T) {
	if err := LoadRepo(); err != nil {
		t.Fatal(err)
	}
	if !Loaded() {
		t.Fatal("реестр не загружен")
	}
	if r, ok := LookupRule("a41c-auth-031"); !ok || r.Title == "" {
		t.Fatal("поставляемое правило")
	}
	if _, ok := LookupRule("pr64-rule-title"); ok {
		t.Fatal("пользовательское правило не в реестре")
	}
	if !Source("host.sshd") || Source("edr.alice-pc") || !Action("auth.ssh") || Action("event.alice_smirnov") {
		t.Fatal("source/action")
	}
	if !Tag("attack.credential_access") || Tag("owner:alice@example.invalid") {
		t.Fatal("теги")
	}
}

// Образ движка кладёт копию как DefaultDir/{rules,fixtures} — Load(dir).
func TestLoadImageLayout(t *testing.T) {
	dir := t.TempDir()
	if err := os.MkdirAll(filepath.Join(dir, "rules"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(filepath.Join(dir, "fixtures"), 0o755); err != nil {
		t.Fatal(err)
	}
	rule := "id: x-1\ntitle: Shipped\nlevel: high\ntags: [attack.t1110]\ndetection:\n  selection:\n    source: host.sshd\n    action: auth.ssh\n  condition: selection\n"
	if err := os.WriteFile(filepath.Join(dir, "rules", "x.yml"), []byte(rule), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "fixtures", "a.ndjson"), []byte(`{"source":"edr.kaspersky","action":"file.read"}`+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := Load(dir); err != nil {
		t.Fatal(err)
	}
	if r, ok := LookupRule("x-1"); !ok || r.Title != "Shipped" || !Source("host.sshd") || !Source("edr.kaspersky") || !Action("file.read") {
		t.Fatal("раскладка образа")
	}
	if err := Load(t.TempDir()); err == nil {
		t.Fatal("пустой каталог — ошибка, а не пустой реестр")
	}
	_ = LoadRepo()
}

func TestStats(t *testing.T) {
	if err := LoadRepo(); err != nil {
		t.Fatal(err)
	}
	r, s, a := Stats()
	if r == 0 || s == 0 || a == 0 {
		t.Fatalf("stats: %d %d %d", r, s, a)
	}
}
