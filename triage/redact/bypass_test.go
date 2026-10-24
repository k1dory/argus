package redact

import (
	"strings"
	"testing"
)

// Обходы редакции, найденные на ревью безопасности. Каждый случай — «ловится шаблоном»:
// после Text в профиле triage (Pseudonymize+Defang) утёкшей подстроки нет.
// Что закрыто политикой (поле не выдаётся, вход отклоняется), проверяют
// mcp/triage_test.go и triage/filter.
func TestBypassesFromReview(t *testing.T) {
	r := New(Options{Key: []byte("k"), Pseudonymize: true, Defang: true, Names: []string{"a.sidorova", "Сидорова Анна"}})
	for _, tc := range []struct {
		name string
		in   string
		leak []string
	}{
		// Секреты
		{"PGP-ключ", "-----BEGIN PGP PRIVATE KEY BLOCK-----\nlQOYBGXXXXsecretbody\n-----END PGP PRIVATE KEY BLOCK-----", []string{"lQOYBGXXXXsecretbody"}},
		{"зашифрованный PEM", "-----BEGIN ENCRYPTED PRIVATE KEY-----\\nMIIFHzBJBgkq\\n-----END ENCRYPTED PRIVATE KEY-----", []string{"MIIFHzBJBgkq"}},
		{"JWT alg:none", "auth eyJhbGciOiJub25lIn0.eyJzdWIiOiJhZG1pbiJ9.", []string{"eyJzdWIiOiJhZG1pbiJ9"}},
		{"DB_PASS", "DB_PASS=Hunter2Hunter2", []string{"Hunter2Hunter2"}},
		{"pass в JSON", `{"pass":"letmein99"}`, []string{"letmein99"}},
		{"pw в JSON", `{"pw": "letmein99"}`, []string{"letmein99"}},
		{"mysql -p", "mysql -u root -pS3cr3tPass db", []string{"S3cr3tPass"}},
		{"пароль с , и ;", `{"password":"p,ss;w0rd123"}`, []string{"p,ss", "ss;w0rd123", "w0rd123"}},
		{"пароль с пробелами", `{"password":"correct horse battery"}`, []string{"correct horse", "battery"}},
		{"пароль в одинарных кавычках", `{'password':'a b,c'}`, []string{"a b,c"}},
		{"короткий Bearer", "Authorization: Bearer abc123", []string{"abc123"}},
		{"base64 без имени", "payload dGhpc0lzQVNlY3JldEtleVZhbHVlMTIzNDU2Nzg5MEFCQ0RFRg== end", []string{"dGhpc0lzQVNlY3JldEtleVZhbHVlMTIzNDU2Nzg5MEFCQ0RFRg"}},
		// E-mail
		{"[at] [dot]", "mail ivan.petrov [at] example [dot] org", []string{"ivan.petrov"}},
		{"(at)", "ivan.petrov(at)example.org", []string{"ivan.petrov"}},
		{"пробелы вокруг @", "ivan.petrov @ example.org", []string{"ivan.petrov"}},
		{"кириллица и IDN", "иван@почта.рф", []string{"иван"}},
		// Телефоны
		{"7 без +", "тел 7 916 123-45-67", []string{"916 123-45-67", "123-45-67"}},
		{"городской 8 (495)", "8 (495) 123-45-67", []string{"123-45-67"}},
		{"8-800", "8-800-555-35-35", []string{"555-35-35"}},
		{"10 цифр без префикса", "call 9161234567", []string{"9161234567"}},
		// Субъекты в атрибутах и тексте
		{"TargetUserName", "{'TargetUserName':'a.petrova','SubjectUserName':'b.ivanova'}", []string{"a.petrova", "b.ivanova"}},
		{"ECS user.name", `{"user.name":"c.smirnov","userPrincipalName":"d.kuznetsov@corp"}`, []string{"c.smirnov", "d.kuznetsov"}},
		{"principal*", "principalId=e.popov principal_name=f.orlov", []string{"e.popov", "f.orlov"}},
		{"Failed password for", "Failed password for invalid user g.volkov from 10.0.0.1", []string{"g.volkov"}},
		{"Accepted publickey for", "Accepted publickey for h.lebedev from 10.0.0.1", []string{"h.lebedev"}},
		{"~login", "cat ~k.morozov/.bashrc", []string{"k.morozov"}},
		{"Names без учёта регистра", "owner A.Sidorova and СИДОРОВА АННА", []string{"Sidorova", "СИДОРОВА"}},
		// Ссылки
		{"//host в картинке", "![x](//evil.example/x.png)", []string{"](//evil", "(//evil"}},
		{"<img src=//>", `<img src=//evil.example/p.png>`, []string{"<img", "=//evil"}},
		{"ссылка без схемы", "[y](evil.example/z)", []string{"](evil"}},
		{"www", "see www.evil.example now", []string{"www.evil"}},
		{"https:/\\", `https:/\evil.example/x`, []string{`https:`}},
		// Метка PEM не портится keyValueRe (п. 8)
		{"метка PEM", "key -----BEGIN RSA PRIVATE KEY-----\nAAAA\n-----END RSA PRIVATE KEY----- tail", []string{"AAAA", "[REDACTED:[REDACTED"}},
	} {
		out := r.Text(tc.in)
		for _, l := range tc.leak {
			if strings.Contains(out, l) {
				t.Errorf("%s: осталось %q: %q", tc.name, l, out)
			}
		}
	}
}

func TestErrorTextHidesQuotedData(t *testing.T) {
	r := New(Options{Key: []byte("k"), Pseudonymize: true, Defang: true})
	for _, in := range []string{
		"Code: 27. DB::Exception: Cannot parse input: expected ',' before: 'a.sidorova,Hunter2Hunter2,+79161234567\n...'",
		"Code: 62. DB::Exception: Syntax error: failed at position 10 ('ivan.petrov'): ...",
		`консоль ответила 400: {"error":"неизвестное поле «a.sidorova»"}`,
	} {
		out := r.ErrorText(in)
		for _, l := range []string{"a.sidorova", "Hunter2", "ivan.petrov", "9161234567"} {
			if strings.Contains(out, l) {
				t.Errorf("ошибка: осталось %q: %q", l, out)
			}
		}
	}
}

func TestHostPseudonym(t *testing.T) {
	r := New(Options{Key: []byte("k"), Pseudonymize: true, Names: []string{"sidorova"}})
	for _, h := range []string{"ws-ivanov", "ivanov-pc", "SIDOROVA-01", "laptop.petrov"} {
		if out := r.Host(h); !IsHostPseudonym(out) {
			t.Errorf("%s → %q: узел человека — псевдонимом", h, out)
		}
	}
	if out := r.Host("srv-k.lebedev-01", "k.lebedev"); !IsHostPseudonym(out) {
		t.Errorf("логин субъекта в имени узла: %q", out)
	}
	for _, h := range []string{"web-01", "runner-07", "db-prod-2", "pc-01"} {
		if out := r.Host(h); out != h {
			t.Errorf("%s → %q: серверный узел не трогаем", h, out)
		}
	}
	p := r.Host("ws-ivanov")
	if v, ok := r.Resolve(p); !ok || v != "ws-ivanov" {
		t.Fatal("псевдоним узла разрешается для точного фильтра")
	}
}

// Ложные срабатывания новых шаблонов на обычных данных SIEM.
func TestNewPatternsKeepOrdinaryData(t *testing.T) {
	r := New(Options{Key: []byte("k"), Pseudonymize: true, Defang: true})
	for _, in := range []string{
		"2026-08-14 04:01:38.000",
		"docker run -p8080:80 nginx",
		"compass=north",
		"sha256 9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08",
		"pid 1234567890 port 8443",
		"10.0.5.5 → 203.0.113.5",
		"gitlab.project_access_token_rotated",
		"token_id=4711 secret_name=REGISTRY_TOKEN",
	} {
		if out := r.Text(in); out != in {
			t.Errorf("лишняя редакция: %q → %q", in, out)
		}
	}
}

// Обходы из повторного ревью (кириллические ключи, порядок слов в именах,
// e-mail и телефоны словами): каждый случай ловится шаблоном.
// Что сознательно не ловится — в doc.go.
func TestBypassesFromReview27(t *testing.T) {
	r := New(Options{Key: []byte("k"), Pseudonymize: true, Defang: true, Names: []string{"Сидорова Анна"}})
	for _, tc := range []struct {
		name string
		in   string
		leak []string
	}{
		// H1: кириллические ключи, параметры URL, X-Auth
		{"пароль:", "пароль: Hunter2Hunter2", []string{"Hunter2"}},
		{"Пароль=", "Пароль=Hunter2Hunter2", []string{"Hunter2"}},
		{"токен в JSON", `{"токен":"Zx9qWm3Lp0Rt"}`, []string{"Zx9qWm3Lp0Rt"}},
		{"ключ доступа", "ключ_доступа=Zx9qWm3Lp0Rt", []string{"Zx9qWm3Lp0Rt"}},
		{"?key=", "GET /api?key=Zx9qWm3Lp0Rt", []string{"Zx9qWm3Lp0Rt"}},
		{"&sig=", "GET /dl?file=a.txt&sig=Ab12Cd34Ef56", []string{"Ab12Cd34Ef56"}},
		{"X-Amz-Signature", "GET /b/o?X-Amz-Credential=AKIDEXAMPLE/20260101/s3&X-Amz-Signature=fe5f80f77d5fa3be", []string{"AKIDEXAMPLE", "fe5f80f77d5fa3be"}},
		{"X-Auth:", "X-Auth: q8Zr7Tn2Lk", []string{"q8Zr7Tn2Lk"}},
		// словоформы и составные имена ключей
		{"с паролем", "вошёл с паролем Hunter2Hunter2", []string{"Hunter2"}},
		{"токены:", "токены: glzz-Abc123def456", []string{"Abc123def456"}},
		{"ключ API:", "ключ API: Zx9qWm3Lp0Rt", []string{"Zx9qWm3Lp0Rt"}},
		{"ключ доступа=", "ключ доступа=Zx9qWm3Lp0Rt", []string{"Zx9qWm3Lp0Rt"}},
		// h2 — &amp; в HTML и markdown
		{"&amp;sig=", `<a href="/dl?f=a&amp;sig=Ab12Cd34Ef56">`, []string{"Ab12Cd34Ef56"}},
		// h3 — код в скобках
		{"(916) 123-45-67", "тел (916) 123-45-67", []string{"123-45-67", "(916)"}},
		// H3: порядок слов и фамилия отдельно
		{"Имя Фамилия", "звонила Анна Сидорова", []string{"Анна", "Сидорова"}},
		{"фамилия отдельно", "владелец СИДОРОВА", []string{"СИДОРОВА"}},
		// H4: e-mail словами, телефоны с точками и без префикса
		{"собака", "ivan.petrov собака example.org", []string{"ivan.petrov"}},
		{"at … dot", "ivan.petrov at example dot org", []string{"ivan.petrov"}},
		{"at без точки в логине, домен словами", "ivan at example dot org", []string{"ivan "}},
		{"10 цифр с разделителями", "тел. 916 123-45-67", []string{"916 123", "123-45-67"}},
		{"точки", "8.916.123.45.67", []string{"916.123", "123.45.67"}},
	} {
		out := r.Text(tc.in)
		for _, l := range tc.leak {
			if strings.Contains(out, l) {
				t.Errorf("%s: осталось %q: %q", tc.name, l, out)
			}
		}
	}
	// H4: обратные кавычки ClickHouse в тексте ошибки.
	if out := r.ErrorText("Code: 47. DB::Exception: Missing columns: `a.sidorova_Hunter2` while processing query"); strings.Contains(out, "Hunter2") || strings.Contains(out, "sidorova") {
		t.Errorf("обратные кавычки: %q", out)
	}
}

// Ложные срабатывания шаблонов: обычные данные журналов остаются на месте.
func TestReview27PatternsKeepOrdinaryData(t *testing.T) {
	r := New(Options{Key: []byte("k"), Pseudonymize: true})
	for _, in := range []string{
		// H5: каталог из строки sudo — не пароль
		"sudo: TTY=pts/0 ; PWD=/root ; COMMAND=/bin/ls",
		"OLDPWD=/srv/app",
		// «at» в обычном тексте
		"uploaded at storage.internal",
		"failed at position 10",
		// IP и версии — не телефоны
		"10.0.0.53 → 192.168.100.200",
		"version 8.0.36.1",
		// ключевые слова, похожие на ключи
		"ключевой: параметр",
		"ключевой момент 2024",
		"ключ найден",
		"секретарь: приёмная",
		// не ловится (doc.go): hex-хеш без имени ключа = SHA-1/коммит
		"commit 3f786850e387550fdab836ed7e6dc881de23001b",
	} {
		if out := r.Text(in); out != in {
			t.Errorf("лишняя редакция: %q → %q", in, out)
		}
	}
	if out := r.Text("PWD=hunter2pass"); strings.Contains(out, "hunter2pass") {
		t.Errorf("PWD без пути — по-прежнему пароль: %q", out)
	}
}

// H2: узел с логином субъекта внутри выдаётся псевдонимом и в ShownHost не
// попадает; серверный узел, выданный открытым, — попадает.
func TestShownHost(t *testing.T) {
	r := New(Options{Key: []byte("k"), Pseudonymize: true})
	if out := r.Host("srv-sidorova", "a.sidorova"); !IsHostPseudonym(out) {
		t.Fatalf("узел с фамилией субъекта: %q", out)
	}
	if r.ShownHost("srv-sidorova") {
		t.Error("узел, выданный псевдонимом, не принимается открытым")
	}
	if r.ShownHost("runner-01") {
		t.Error("невыданный узел не принимается")
	}
	if out := r.Host("runner-01", "a.sidorova"); out != "runner-01" || !r.ShownHost(" runner-01 ") {
		t.Errorf("серверный узел выдан открытым и принимается: %q", out)
	}
}

// Токены известных форматов — секреты даже без имени ключа; Leaks видит
// секрет, канарейку и субъект словом, но не псевдоним и не обезвреженную ссылку.
func TestKnownTokensAndLeaks(t *testing.T) {
	r := New(Options{Key: []byte("k"), Pseudonymize: true, Defang: true, Canaries: []string{"zebra-canary-77"}, Names: []string{"Сидорова Анна"}})
	for _, in := range []string{"glpat-0123456789abcdefghij", "project=ghp_0123456789abcdefghij0123456789", "токен xoxb-0123456789-abcdef"} {
		if out := r.Text(in); strings.Contains(out, "0123456789") || strings.Contains(out, "abcdef") {
			t.Errorf("токен не вырезан: %q → %q", in, out)
		}
	}
	if out := r.Text("glpat-short"); out != "glpat-short" {
		t.Errorf("короткое слово с префиксом — не токен: %q", out)
	}
	leaks := []struct {
		in       string
		subjects []string
	}{
		{"ключ glpat-0123456789abcdefghij", nil},
		{"в данных zebra-canary-77", nil},
		{"вход i.petrov с узла", []string{"i.petrov"}},
		{"звонила Сидорова", nil},
	}
	for _, c := range leaks {
		if !r.Leaks(c.in, c.subjects...) {
			t.Errorf("Leaks не увидел: %q", c.in)
		}
	}
	for _, in := range []string{"субъект subj-0123456789 на host-0123456789", "[INC-24](https://argus.example/incidents/INC-24)", "petrovsky и xi.petrov — другие слова"} {
		if r.Leaks(in, "i.petrov") {
			t.Errorf("лишнее срабатывание Leaks: %q", in)
		}
	}
}
