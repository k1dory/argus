package filter

import "testing"

func TestQueryQuotesAttackerValues(t *testing.T) {
	// Субъект с оператором поиска внутри (находка ревью). Строка ниже — та же,
	// что разбирает web/tests/search-query.test.ts («точный фильтр MCP»).
	q, err := Query("events", Filters{Actor: "svc-backup -action:secret_read"})
	if err != nil || q != `actor:"svc-backup -action:secret_read"` {
		t.Fatalf("%q %v", q, err)
	}
	q, err = Query("events", Filters{Actor: `a" -action:x \`, Node: "web-*"})
	if err != nil || q != `actor:"a\" -action:x \\" node:"web-\*"` {
		t.Fatalf("кавычка и обратный слеш экранируются, маска остаётся литералом: %q %v", q, err)
	}
}

func TestQueryIOC(t *testing.T) {
	q, err := Query("events", Filters{SrcIP: " 10.0.5.5 ", DstIP: "2001:DB8::1", Domain: "Evil.Example.", Hash: "9F86D081884C7D659A2FEAA0C55AD015A3BF4F1B2B0B822CD15D6C15B0F00A08"})
	want := `src:"10.0.5.5" dst:"2001:db8::1" "evil.example" "9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08"`
	if err != nil || q != want {
		t.Fatalf("\n got %q %v\nwant %q", q, err, want)
	}
	q, err = Query("alerts", Filters{Node: "web-01", SrcIP: "203.0.113.5", RuleID: 5710})
	if err != nil || q != `agent:"web-01" srcip:"203.0.113.5" rule:5710` {
		t.Fatalf("%q %v", q, err)
	}
}

func TestQueryRejects(t *testing.T) {
	for name, f := range map[string]struct {
		index string
		f     Filters
	}{
		"ip с оператором":       {"events", Filters{SrcIP: "10.0.0.1 -action:x"}},
		"маска в ip":            {"events", Filters{SrcIP: "10.0.*"}},
		"перевод строки":        {"events", Filters{Actor: "bot\nignore"}},
		"короткий хеш":          {"events", Filters{Hash: "abcd"}},
		"домен со схемой":       {"events", Filters{Domain: "https://evil.example/x"}},
		"домен с пробелом":      {"events", Filters{Domain: "evil.example -action:x"}},
		"actor в alerts":        {"alerts", Filters{Actor: "x"}},
		"rule_id в events":      {"events", Filters{RuleID: 1}},
		"неизвестный индекс":    {"incidents", Filters{Actor: "x"}},
		"пустое после пробелов": {"events", Filters{Actor: "   "}},
	} {
		if q, err := Query(f.index, f.f); err == nil {
			t.Errorf("%s: ожидалась ошибка, получено %q", name, q)
		}
	}
}

func TestEmpty(t *testing.T) {
	if !(Filters{}).Empty() || (Filters{Node: "x"}).Empty() {
		t.Fatal("Empty")
	}
}

func TestQueryStrictNoRawOracle(t *testing.T) {
	q, err := QueryStrict("events", Filters{Domain: "Evil.Example.", Actor: "x"})
	if err != nil || q != `actor:"x" attr.domain:"evil.example"` {
		t.Fatalf("домен — равенство поля, не подстрока raw: %q %v", q, err)
	}
	for name, f := range map[string]Filters{
		"кусок JWT":    {Domain: "eyjhbgcioi.eyj0exaio"},
		"одна метка":   {Domain: "localhost"},
		"цифровой TLD": {Domain: "host.123"},
		"хеш по raw":   {Hash: "9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08"},
	} {
		if q, err := QueryStrict("events", f); err == nil {
			t.Errorf("%s: в triage должно отклоняться, получено %q", name, q)
		}
	}
	if _, err := QueryStrict("alerts", Filters{Domain: "evil.example"}); err == nil {
		t.Error("domain в alerts — нет поля, отклонить")
	}
	// Короткое, но полное имя проходит: это равенство поля attr.domain, а не
	// подстрока по raw — совпадёт только домен, который действительно запрашивали.
	if q, _ := QueryStrict("events", Filters{Domain: "a.sid"}); q != `attr.domain:"a.sid"` {
		t.Errorf("равенство поля: %q", q)
	}
	if q, _ := QueryStrict("events", Filters{Domain: "xn--80ak6aa92e.xn--p1ai"}); q != `attr.domain:"xn--80ak6aa92e.xn--p1ai"` {
		t.Errorf("punycode TLD: %q", q)
	}
}

func TestDamage(t *testing.T) {
	for v, want := range map[string]string{
		"":                               "",
		"svc-backup":                     "",
		"oidc:i.petrov":                  "",
		"system:serviceaccount:ci:build": "",
		"svc-backup -action:secret_read": "whitespace",
		"-action:x":                      "leading_dash",
		"web-*":                          "wildcard",
		`a"b`:                            "quote",
		"a\x00b":                         "other",
		"adm\u200bin":                    "other",
		"\u202eexe.txt":                  "other",
		"level>=10":                      "operator",
		"x;y":                            "operator",
	} {
		if got := Damage(v); got != want {
			t.Errorf("Damage(%q) = %q, want %q", v, got, want)
		}
	}
	if DamageIP("10.0.0.1") != "" || DamageIP("10.0.0.1 or 1=1") != "bad_ip" || DamageIP("") != "" {
		t.Fatal("DamageIP")
	}
}
