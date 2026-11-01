package dataset

import (
	"fmt"
	"slices"
	"strings"
	"testing"

	"github.com/devitex-soft/argus/engine/internal/attack"
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

func u8(v uint8) *uint8 { return &v }

func TestBuildSecurityRecord(t *testing.T) {
	r := Build(human(secIncident("INC-1", "ivan.petrov"), store.ClosureLabel{
		Disposition: "benign_authorized", Escalate: bp(false), SeverityLevel: u8(2), SeverityCorrect: bp(false),
		AttackTactic: "credential-access", AttackTechnique: "T1110.001", AttackVersion: "20.0", Blind: true,
	}), "prod")
	if r == nil {
		t.Fatal("запись не построена")
	}
	if r.Schema != Schema || r.Scenario != Security || !r.Blind || r.Source != "prod" {
		t.Fatalf("поля: %+v", r)
	}
	want := map[string]string{"disposition": "benign_authorized", "escalate": "false", "severity_level": "1",
		"attack_tactic": "credential-access", "attack_technique": "T1110.001"}
	if len(r.Labels) != len(want) {
		t.Fatalf("метки: %+v", r.Labels)
	}
	for k, v := range want {
		if r.Labels[k] != v {
			t.Fatalf("метка %s = %q, ждали %q", k, r.Labels[k], v)
		}
	}
	if len(r.Questions) != 5 || r.Questions["disposition"].Type != systemone.Choice || r.Questions["escalate"].Type != systemone.Noul ||
		r.Questions["severity_level"].Type != systemone.Score || len(r.Questions["severity_level"].Options()) != 4 {
		t.Fatalf("вопросы: %+v", r.Questions)
	}
	tech := r.Questions["attack_technique"].Criteria.(map[string]string)
	if _, ok := tech["T1110.001"]; !ok || len(tech) > 21 {
		t.Fatalf("кандидаты техники: %v", tech)
	}
	if _, ok := tech[AttackOther]; !ok {
		t.Fatal("в кандидатах нет «другого»")
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

// Кандидаты в записи — по тактике человека (как в форме); без неё — по
// тактике из тегов правила. Метка другой версии справочника не берётся.
func TestBuildTechniqueCandidatesFollowTactic(t *testing.T) {
	inc := secIncident("INC-8", "1.2.3.4")
	byHuman := Build(human(inc, store.ClosureLabel{Disposition: "malicious", Escalate: bp(true), SeverityLevel: u8(4),
		AttackTactic: "initial-access", AttackTechnique: "T1078"}), "prod")
	byTags := Build(human(inc, store.ClosureLabel{Disposition: "false_positive", Escalate: bp(false), SeverityLevel: u8(1)}), "prod")
	if !slices.Equal(sorted(byHuman.Questions["attack_technique"].Options()), optionsOf(attack.Candidates(inc.Tags, "initial-access"))) {
		t.Fatalf("по тактике человека: %v", byHuman.Questions["attack_technique"].Options())
	}
	if !slices.Equal(sorted(byTags.Questions["attack_technique"].Options()), optionsOf(attack.Candidates(inc.Tags, "credential-access"))) {
		t.Fatalf("по тактике тегов: %v", byTags.Questions["attack_technique"].Options())
	}
	if _, ok := byTags.Labels["attack_tactic"]; ok {
		t.Fatal("у ложного срабатывания без тактики нет метки тактики")
	}
	old := Build(human(inc, store.ClosureLabel{Disposition: "malicious", Escalate: bp(true), SeverityLevel: u8(3),
		AttackTactic: "defense-evasion", AttackTechnique: "T1070", AttackVersion: "19.0"}), "prod")
	if _, ok := old.Labels["attack_tactic"]; ok || old.Labels["disposition"] != "malicious" {
		t.Fatalf("метка ATT&CK другой версии справочника: %+v", old.Labels)
	}
}

func sorted(v []string) []string { slices.Sort(v); return v }

// optionsOf — варианты choice в отсортированном виде (порядок map не задан).
func optionsOf(ids []string) []string {
	out := append(slices.Clone(ids), AttackOther)
	slices.Sort(out)
	return out
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
	r := Build(human(inc, store.ClosureLabel{OpsCause: "disk", OpsActNow: bp(true), OpsUrgency: u8(3), OpsAction: "fixed"}), "prod")
	want := map[string]string{"ops_cause": "disk", "ops_act_now": "true", "ops_urgency": "2"}
	if r == nil || r.Scenario != Ops || len(r.Labels) != len(want) {
		t.Fatalf("ops: %+v", r)
	}
	for k, v := range want {
		if r.Labels[k] != v {
			t.Fatalf("метка %s = %q, ждали %q", k, r.Labels[k], v)
		}
	}
	if _, ok := r.Questions["disposition"]; ok || len(r.Questions) != 3 || r.Questions["ops_urgency"].Type != systemone.Score {
		t.Fatalf("вопросы ops: %+v", r.Questions)
	}
}

// Вопросы — те же значения, что принимает форма завершения.
func TestQuestionOptionsMatchClosureForm(t *testing.T) {
	check := func(q systemone.Question, want []string) {
		t.Helper()
		got := q.Options()
		slices.Sort(got)
		want = slices.Clone(want)
		slices.Sort(want)
		if !slices.Equal(got, want) {
			t.Fatalf("%s: %v против %v", q.Instructions, got, want)
		}
	}
	check(Questions(Security, nil, "")["disposition"], []string{"malicious", "benign_authorized", "false_positive"})
	check(Questions(Ops, nil, "")["ops_cause"], []string{"disk", "memory", "network", "process_crash", "config", "deploy", "external_dependency", "false_positive"})
	tactics := []string{AttackOther}
	for _, tc := range attack.Tactics() {
		tactics = append(tactics, tc.Shortname)
	}
	check(TacticQuestion(), tactics)
	if len(tactics) != 16 {
		t.Fatalf("15 тактик ATT&CK v20 + other: %d", len(tactics))
	}
	for _, id := range TacticQuestion().Options() {
		if !attack.Tactic(id) {
			t.Fatalf("тактика %q не принимается формой", id)
		}
	}
	for _, id := range TechniqueQuestion([]string{"attack.t1110.001"}, "").Options() {
		if !attack.Technique(id) {
			t.Fatalf("техника %q не принимается формой", id)
		}
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
	ra := Build(human(a, store.ClosureLabel{Disposition: "malicious", Escalate: bp(true), SeverityLevel: u8(3)}), "prod")
	rb := Build(human(b, store.ClosureLabel{Disposition: "malicious", Escalate: bp(true), SeverityLevel: u8(3)}), "prod")
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
