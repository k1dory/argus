package dataset

import (
	"fmt"
	"strings"
	"testing"

	"github.com/devitex-soft/argus/engine/internal/incidents"
	"github.com/devitex-soft/argus/engine/internal/store"
	"github.com/devitex-soft/argus/engine/internal/systemone"
)

func bp(v bool) *bool { return &v }

func secIncident(id, actor string) incidents.Incident {
	return incidents.Incident{
		IncidentID: id, RuleID: "a41c-auth-031", RuleTitle: "Host: SSH brute force", Level: "high",
		Tags: []string{"attack.credential_access", "attack.t1110.001"}, Status: incidents.StatusClosed,
		Owner: "ivan.petrov", Note: "это пентест Ивана, закрыто", ActorName: actor, Node: "db-prod-01.corp.local",
		Sources: []string{"journald"}, EventCount: 12,
		Chain: []string{
			fmt.Sprintf("%s  %-16s %-14s %-24s %s", "10:00:01", "host.sshd", "db-prod-01.co…", "auth.ssh", "192.168.0.44:22"),
			fmt.Sprintf("%s  %-16s %-14s %-24s %s", "10:00:02", "host.sshd", "db-prod-01.co…", "auth.ssh", "ivan.petrov"),
			"10:00 free text ivan.petrov@corp.local phone +7 912 345-67-89",
		},
	}
}

func human(inc incidents.Incident, l store.ClosureLabel) store.LabeledIncident {
	l.LabeledByHuman = true
	return store.LabeledIncident{Incident: inc, Label: l, ChangedAt: "2026-11-01 10:00:00.000"}
}

func TestBuildSecurityRecord(t *testing.T) {
	r := Build(human(secIncident("INC-1", "ivan.petrov"), store.ClosureLabel{
		Disposition: "benign_authorized", Escalate: bp(false), SeverityCorrect: bp(true), Blind: true,
	}), "prod")
	if r == nil {
		t.Fatal("запись не построена")
	}
	if r.Schema != Schema || r.Scenario != Security || !r.Blind || r.Source != "prod" {
		t.Fatalf("поля: %+v", r)
	}
	want := map[string]string{"disposition": "benign_authorized", "escalate": "false", "severity_correct": "true"}
	for k, v := range want {
		if r.Labels[k] != v {
			t.Fatalf("метка %s = %q, ждали %q", k, r.Labels[k], v)
		}
	}
	if _, ok := r.Labels["tactic"]; ok {
		t.Fatal("у тактики метки человека нет")
	}
	if len(r.Questions) != 4 || r.Questions["disposition"].Type != systemone.Choice || r.Questions["escalate"].Type != systemone.Noul {
		t.Fatalf("вопросы: %+v", r.Questions)
	}
	// Состояние: ни ответа человека, ни ПДн.
	for _, leak := range []string{"INC-1", "пентест", "ivan", "db-prod-01", "192.168.0.44", "912 345", "closed", "corp.local"} {
		if strings.Contains(r.State, leak) {
			t.Fatalf("в состоянии %q:\n%s", leak, r.State)
		}
	}
	if !strings.Contains(r.State, "a41c-auth-031") || !strings.Contains(r.State, "auth.ssh") ||
		!strings.Contains(r.State, "ip-private-") || !strings.Contains(r.State, ":22") || !strings.Contains(r.State, "user-") ||
		!strings.Contains(r.State, "1 lines omitted") {
		t.Fatalf("состояние без правила или сети:\n%s", r.State)
	}
}

func TestBuildSkipsAutomationAndEmpty(t *testing.T) {
	auto := human(secIncident("INC-2", "1.2.3.4"), store.ClosureLabel{Disposition: "false_positive"})
	auto.Label.LabeledByHuman = false
	if Build(auto, "prod") != nil {
		t.Fatal("автозакрытие — не метка")
	}
	if Build(human(secIncident("INC-3", "1.2.3.4"), store.ClosureLabel{}), "prod") != nil {
		t.Fatal("пустая метка — не запись")
	}
}

func TestBuildOpsRecord(t *testing.T) {
	inc := secIncident("INC-4", "")
	inc.RuleID, inc.Tags = "ops-disk-high", []string{"ops.disk"}
	r := Build(human(inc, store.ClosureLabel{OpsCause: "planned_work", OpsAction: "no_action"}), "prod")
	if r == nil || r.Scenario != Ops || r.Labels["ops_cause"] != "planned_work" || r.Labels["ops_action"] != "no_action" || len(r.Labels) != 2 {
		t.Fatalf("ops: %+v", r)
	}
	if _, ok := r.Questions["disposition"]; ok || len(r.Questions) != 2 {
		t.Fatalf("вопросы ops: %+v", r.Questions)
	}
}

// Вопросы — те же значения, что принимает форма завершения.
func TestQuestionOptionsMatchClosureForm(t *testing.T) {
	check := func(q systemone.Question, want []string) {
		t.Helper()
		got := q.Options()
		if len(got) != len(want) {
			t.Fatalf("%s: %v против %v", q.Instructions, got, want)
		}
		for _, w := range want {
			if _, ok := q.Criteria.(map[string]string)[w]; !ok {
				t.Fatalf("%s: нет %q", q.Instructions, w)
			}
		}
	}
	check(Questions(Security)["disposition"], []string{"malicious", "benign_authorized", "false_positive"})
	check(Questions(Ops)["ops_cause"], []string{"real_failure", "planned_work", "monitoring_noise", "wrong_threshold"})
	check(Questions(Ops)["ops_action"], []string{"fixed", "no_action", "rule_tuned", "handed_over"})
	if len(Tactics) != 15 {
		t.Fatalf("14 тактик ATT&CK + other: %d", len(Tactics))
	}
}

func TestGroupIDCollapsesSubnetAndSplitIsStable(t *testing.T) {
	a, b := secIncident("INC-5", "203.0.113.7"), secIncident("INC-6", "203.0.113.200")
	c := secIncident("INC-7", "203.0.114.7")
	if GroupID(&a) != GroupID(&b) {
		t.Fatal("соседние адреса одной /24 — один случай")
	}
	if GroupID(&a) == GroupID(&c) {
		t.Fatal("другая сеть — другой случай")
	}
	d := c
	d.RuleID = "other"
	if GroupID(&c) == GroupID(&d) {
		t.Fatal("другое правило — другой случай")
	}
	ra := Build(human(a, store.ClosureLabel{Disposition: "malicious", Escalate: bp(true), SeverityCorrect: bp(true)}), "prod")
	rb := Build(human(b, store.ClosureLabel{Disposition: "malicious", Escalate: bp(true), SeverityCorrect: bp(true)}), "prod")
	if ra.Split != rb.Split {
		t.Fatal("один случай — по одну сторону разбиения")
	}
	// Доля отложенных групп близка к HoldoutPercent.
	hold := 0
	for i := 0; i < 2000; i++ {
		if splitBucket(fmt.Sprintf("g-%d", i)) < HoldoutPercent {
			hold++
		}
	}
	if hold < 400 || hold > 600 {
		t.Fatalf("отложенных групп %d из 2000", hold)
	}
}

func TestCapPrefersDistinctGroups(t *testing.T) {
	var recs []*Record
	// 3 группы правила scan: 50 + 50 + 2 инцидента; правило other — 3.
	for g, n := range []int{50, 50, 2} {
		for i := 0; i < n; i++ {
			recs = append(recs, &Record{RuleID: "scan", GroupID: fmt.Sprintf("g%d", g), IncidentID: fmt.Sprintf("INC-%d-%d", g, i)})
		}
	}
	for i := 0; i < 3; i++ {
		recs = append(recs, &Record{RuleID: "other", GroupID: "o", IncidentID: fmt.Sprintf("INC-o-%d", i)})
	}
	out := Cap(recs, 10)
	groups := map[string]int{}
	rules := map[string]int{}
	for _, r := range out {
		rules[r.RuleID]++
		if r.RuleID == "scan" {
			groups[r.GroupID]++
		}
	}
	if rules["scan"] != 10 || rules["other"] != 3 {
		t.Fatalf("по правилам: %v", rules)
	}
	if groups["g2"] != 2 || groups["g0"] != 4 || groups["g1"] != 4 {
		t.Fatalf("сначала разные группы: %v", groups)
	}
	again := Cap(recs, 10)
	for i := range out {
		if out[i].IncidentID != again[i].IncidentID {
			t.Fatal("выбор не детерминирован")
		}
	}
	if len(Cap(recs, 0)) != len(recs) {
		t.Fatal("0 — без потолка")
	}
}
