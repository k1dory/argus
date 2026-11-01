package analyst

import (
	"fmt"
	"strings"
	"testing"

	"github.com/devitex-soft/argus/engine/internal/incidents"
)

func chainRow(ts, src, node, action, detail string) string {
	return fmt.Sprintf("%s  %-16s %-14s %-24s %s", ts, src, node, action, detail)
}

func TestPseudonymsStablePerSalt(t *testing.T) {
	a, b := NewPseudonyms([]byte("salt-a")), NewPseudonyms([]byte("salt-b"))
	if a.Host("web-01") != a.Host("WEB-01") || a.User("ivan") != a.User("ivan") {
		t.Fatal("в одной выгрузке один узел — один псевдоним")
	}
	if a.Host("web-01") == b.Host("web-01") {
		t.Fatal("между выгрузками псевдонимы не сопоставляются")
	}
	if a.User("root") != "root" || a.User("Administrator") != "administrator" {
		t.Fatal("служебные учётки — как есть")
	}
	n1, n2, other := a.IP("203.0.113.7"), a.IP("203.0.113.200"), a.IP("203.0.114.7")
	if n1[:strings.LastIndex(n1, ".")] != n2[:strings.LastIndex(n2, ".")] || n1 == n2 ||
		n1[:strings.LastIndex(n1, ".")] == other[:strings.LastIndex(other, ".")] {
		t.Fatalf("сеть /24 видна, адрес — нет: %s %s %s", n1, n2, other)
	}
	if !strings.HasPrefix(a.IP("10.1.2.3"), "ip-private-") || !strings.HasPrefix(a.IP("fd12::1"), "ip-private-") ||
		!strings.HasPrefix(a.IP("8.8.8.8"), "ip-public-") {
		t.Fatal("область адреса")
	}
}

func TestDetailKinds(t *testing.T) {
	p := NewPseudonyms([]byte("s"))
	cases := map[string]string{
		"/etc/shadow":                      "/etc/shadow",
		"/var/lib/clickhouse 91.5 percent": "/var/lib/clickhouse 91.5 percent",
		"/home/ivan.petrov/secret.docx":    "/home/" + p.User("ivan.petrov") + "/[path].docx",
		"/root/.ssh/id_rsa":                "/root/[path]",
		"/data/clients/acme/report.pdf":    "[path].pdf",
		`C:\Users\ivan\Desktop\a.xlsx`:     "[path].xlsx",
		"10.0.0.5:3389":                    p.IP("10.0.0.5") + ":3389",
		"https://intranet.corp/x?token=1":  "https://" + p.Host("intranet.corp") + "/[path]",
		"ivan.petrov":                      p.User("ivan.petrov"),
		"Тестов Тест Тестович":             "[text]",
		"/etc/ivan@corp/x":                 "/etc/[x]/x",
	}
	for in, want := range cases {
		if got := p.Detail(in); got != want {
			t.Errorf("%q → %q, ждали %q", in, got, want)
		}
	}
}

func TestDecisionStateWhitelist(t *testing.T) {
	p := NewPseudonyms([]byte("s"))
	inc := &incidents.Incident{
		IncidentID: "INC-9", RuleID: "a41c-auth-031", RuleTitle: "SSH brute force", Level: "high",
		Tags: []string{"attack.t1110.001"}, Status: incidents.StatusClosed, Owner: "anna", Note: "это пентест",
		ActorName: "203.0.113.7", Node: "db-prod-01", Sources: []string{"journald"}, EventCount: 3,
		Chain: []string{
			chainRow("10:00:01", "journald", "db-prod-01", "auth.ssh.failure", "alice"),
			chainRow("10:00:02", "journald", "db-prod-01", "auth.ssh.failure", "root"),
			"→ 25 попыток за 1m0s (порог 20) с host.corp.local",
			"произвольная строка alice",
		},
		Enrichment: []string{
			"cmdb: db-prod-01 — владелец anna, команда dba, критичность high Контакт: Анна",
			"edr.process_tree: 1 событий за окно",
			fmt.Sprintf("  %s  %-14s %-22s %s", "10:00:03", "edr", "process.start", "/home/alice/run.sh"),
			"ngfw.sessions: ошибка запроса — dial tcp 10.0.0.1: secret",
		},
		Similar: []string{"INC-3 · 2026-10-30 · closed · SSH · ложное, это Анна"},
	}
	s := DecisionStateWith(inc, p)
	for _, leak := range []string{"INC-", "anna", "Анна", "пентест", "alice", "db-prod-01", "203.0.113.7", "dba", "host.corp.local", "secret", "10.0.0.1", "closed"} {
		if strings.Contains(s, leak) {
			t.Errorf("в состоянии %q:\n%s", leak, s)
		}
	}
	for _, want := range []string{"a41c-auth-031", "attack.t1110.001", "auth.ssh.failure", "root", "cmdb: criticality high",
		"edr.process_tree: 1 событий за окно", "process.start", ".sh", "25 попыток", "(порог 20)", "1 lines of unrecognized format omitted",
		p.Host("db-prod-01"), p.IP("203.0.113.7")} {
		if !strings.Contains(s, want) {
			t.Errorf("в состоянии нет %q:\n%s", want, s)
		}
	}
}
