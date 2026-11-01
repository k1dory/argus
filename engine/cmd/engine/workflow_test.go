package main

import (
	"fmt"
	"strings"
	"testing"

	"github.com/devitex-soft/argus/engine/internal/incidents"
	"github.com/devitex-soft/argus/engine/internal/store"
)

func TestWorkflowDecision(t *testing.T) {
	inc := &incidents.Incident{Status: incidents.StatusNew}
	status, owner, err := workflowDecision(inc, workflowRequest{Actor: "admin", Role: "admin", Kind: "assign", Owner: "anna"})
	if err != nil || status != incidents.StatusNew || owner != "anna" {
		t.Fatalf("первое назначение: %q %q %v", status, owner, err)
	}
	inc.Owner = owner
	if _, _, err := workflowDecision(inc, workflowRequest{Actor: "anna", Role: "analyst", Kind: "status", Status: incidents.StatusClosed}); err == nil {
		t.Fatal("статус до принятия")
	}
	status, owner, err = workflowDecision(inc, workflowRequest{Actor: "anna", Role: "analyst", Kind: "take"})
	if err != nil || status != incidents.StatusInProgress || owner != "anna" {
		t.Fatalf("принятие: %q %q %v", status, owner, err)
	}
	inc.Status = status
	if _, _, err := workflowDecision(inc, workflowRequest{Actor: "bob", Role: "analyst", Kind: "take"}); err == nil {
		t.Fatal("чужой аналитик взял занятый инцидент")
	}
	if _, _, err := workflowDecision(inc, workflowRequest{Actor: "anna", Role: "analyst", Kind: "assign", Owner: "bob"}); err == nil {
		t.Fatal("аналитик передал инцидент")
	}
	status, owner, err = workflowDecision(inc, workflowRequest{Actor: "admin", Role: "admin", Kind: "assign", Owner: "bob"})
	if err != nil || status != incidents.StatusWaitingOwner || owner != "bob" {
		t.Fatalf("передача: %q %q %v", status, owner, err)
	}
	inc.Status, inc.Owner = status, owner
	if _, _, err := workflowDecision(inc, workflowRequest{Actor: "bob", Role: "analyst", Kind: "status", Status: incidents.StatusClosed}); err == nil {
		t.Fatal("получатель закрыл до принятия")
	}
	inc.Status = incidents.StatusInProgress
	if _, _, err := workflowDecision(inc, workflowRequest{Actor: "bob", Role: "analyst", Kind: "status", Status: incidents.StatusClosed}); err == nil {
		t.Fatal("закрытие без причины")
	}
	status, _, err = workflowDecision(inc, workflowRequest{Actor: "bob", Role: "analyst", Kind: "status", Status: incidents.StatusClosed, Reason: "Проверены события, угрозы нет", Label: secLabel("benign_authorized")})
	if err != nil || status != incidents.StatusClosed {
		t.Fatalf("закрытие: %q %v", status, err)
	}
	if _, _, err := workflowDecision(inc, workflowRequest{Actor: "bob", Role: "analyst", Kind: "status", Status: incidents.StatusClosed, Reason: strings.Repeat("Я", 2000), Label: secLabel("malicious")}); err != nil {
		t.Fatalf("причина из 2000 кириллических символов отклонена: %v", err)
	}
	if _, _, err := workflowDecision(inc, workflowRequest{Actor: "bob", Role: "analyst", Kind: "status", Status: incidents.StatusClosed, Reason: strings.Repeat("Я", 2001), Label: secLabel("malicious")}); err == nil {
		t.Fatal("причина длиннее 2000 символов принята")
	}
}

func secLabel(disposition string) *closureLabel {
	no, level := false, 3
	l := &closureLabel{Disposition: disposition, Escalate: &no, SeverityLevel: &level}
	if disposition != "false_positive" {
		l.AttackTactic, l.AttackTechnique = "credential-access", "T1110.001"
	}
	return l
}

func opsLabel(cause string) *closureLabel {
	yes, urgency := true, 2
	return &closureLabel{OpsCause: cause, OpsActNow: &yes, OpsUrgency: &urgency}
}

func TestWorkflowClosureLabel(t *testing.T) {
	sec := &incidents.Incident{Status: incidents.StatusInProgress, Owner: "anna", Tags: []string{"attack.t1110"}}
	ops := &incidents.Incident{Status: incidents.StatusInProgress, Owner: "anna", Tags: []string{"argus.system", "ops.storage"}}
	req := func(status string, l *closureLabel) workflowRequest {
		return workflowRequest{Actor: "anna", Role: "analyst", Kind: "status", Status: status, Reason: "проверено по журналу", Label: l}
	}
	no, level, zero, five := false, 2, 0, 5
	with := func(edit func(*closureLabel)) *closureLabel { l := secLabel("malicious"); edit(l); return l }
	withOps := func(edit func(*closureLabel)) *closureLabel { l := opsLabel("disk"); edit(l); return l }
	for name, c := range map[string]struct {
		inc *incidents.Incident
		in  workflowRequest
		ok  bool
	}{
		"ИБ: полная метка":              {sec, req(incidents.StatusClosed, secLabel("malicious")), true},
		"ИБ: без метки":                 {sec, req(incidents.StatusClosed, nil), false},
		"ИБ: неизвестный вердикт":       {sec, req(incidents.StatusClosed, secLabel("maybe")), false},
		"ИБ: эскалация не указана":      {sec, req(incidents.StatusClosed, &closureLabel{Disposition: "malicious", SeverityLevel: &level, AttackTactic: "other", AttackTechnique: "other"}), false},
		"ИБ: уровень не указан":         {sec, req(incidents.StatusClosed, &closureLabel{Disposition: "malicious", Escalate: &no, AttackTactic: "other", AttackTechnique: "other"}), false},
		"ИБ: уровень 0":                 {sec, req(incidents.StatusClosed, with(func(l *closureLabel) { l.SeverityLevel = &zero })), false},
		"ИБ: уровень 5":                 {sec, req(incidents.StatusClosed, with(func(l *closureLabel) { l.SeverityLevel = &five })), false},
		"ИБ: «другое»":                  {sec, req(incidents.StatusClosed, with(func(l *closureLabel) { l.AttackTactic, l.AttackTechnique = "other", "other" })), true},
		"ИБ: без тактики":               {sec, req(incidents.StatusClosed, with(func(l *closureLabel) { l.AttackTactic = "" })), false},
		"ИБ: без техники":               {sec, req(incidents.StatusClosed, with(func(l *closureLabel) { l.AttackTechnique = "" })), false},
		"ИБ: тактика не из справочника": {sec, req(incidents.StatusClosed, with(func(l *closureLabel) { l.AttackTactic = "credential_access" })), false},
		"ИБ: техника не из справочника": {sec, req(incidents.StatusClosed, with(func(l *closureLabel) { l.AttackTechnique = "T9999" })), false},
		"ИБ: техника в нижнем регистре": {sec, req(incidents.StatusClosed, with(func(l *closureLabel) { l.AttackTechnique = "t1110" })), false},
		"ИБ: ложное без тактики":        {sec, req(incidents.StatusFalsePositive, secLabel("false_positive")), true},
		"ИБ: ложное с тактикой": {sec, req(incidents.StatusFalsePositive, func() *closureLabel {
			l := secLabel("false_positive")
			l.AttackTactic, l.AttackTechnique = "discovery", "other"
			return l
		}()), true},
		"ИБ: техника без тактики":          {sec, req(incidents.StatusFalsePositive, func() *closureLabel { l := secLabel("false_positive"); l.AttackTechnique = "T1046"; return l }()), false},
		"ИБ: ложное без false_positive":    {sec, req(incidents.StatusFalsePositive, secLabel("benign_authorized")), false},
		"ИБ: закрыт как false_positive":    {sec, req(incidents.StatusClosed, secLabel("false_positive")), false},
		"ИБ: ложное срабатывание":          {sec, req(incidents.StatusFalsePositive, secLabel("false_positive")), true},
		"ИБ: поля DevOps":                  {sec, req(incidents.StatusClosed, with(func(l *closureLabel) { l.OpsCause = "disk" })), false},
		"DevOps: полная метка":             {ops, req(incidents.StatusClosed, withOps(func(l *closureLabel) { l.OpsAction = "fixed" })), true},
		"DevOps: без действия":             {ops, req(incidents.StatusClosed, opsLabel("disk")), true},
		"DevOps: неизвестное действие":     {ops, req(incidents.StatusClosed, withOps(func(l *closureLabel) { l.OpsAction = "rebooted" })), false},
		"DevOps: старая причина":           {ops, req(incidents.StatusClosed, opsLabel("planned_work")), false},
		"DevOps: без «сейчас»":             {ops, req(incidents.StatusClosed, withOps(func(l *closureLabel) { l.OpsActNow = nil })), false},
		"DevOps: без срочности":            {ops, req(incidents.StatusClosed, withOps(func(l *closureLabel) { l.OpsUrgency = nil })), false},
		"DevOps: срочность 5":              {ops, req(incidents.StatusClosed, withOps(func(l *closureLabel) { l.OpsUrgency = &five })), false},
		"DevOps: уровень ИБ":               {ops, req(incidents.StatusClosed, withOps(func(l *closureLabel) { l.SeverityLevel = &level })), false},
		"DevOps: ложное срабатывание":      {ops, req(incidents.StatusFalsePositive, opsLabel("false_positive")), true},
		"DevOps: ложное с другой причиной": {ops, req(incidents.StatusFalsePositive, opsLabel("disk")), false},
		"DevOps: закрыт как ложное":        {ops, req(incidents.StatusClosed, opsLabel("false_positive")), false},
		"DevOps: вердикт ИБ":               {ops, req(incidents.StatusClosed, secLabel("malicious")), false},
		"метка без завершения":             {sec, req(incidents.StatusObserving, secLabel("malicious")), false},
		"метка во взятии в работу":         {sec, workflowRequest{Actor: "anna", Role: "analyst", Kind: "take", Label: secLabel("malicious")}, false},
	} {
		_, _, err := workflowDecision(c.inc, c.in)
		if (err == nil) != c.ok {
			t.Errorf("%s: ok=%v, err=%v", name, c.ok, err)
		}
	}
}

// Те же векторы проверяет консоль (web/tests/closure-label.test.ts): выборка обязана
// совпадать, иначе консоль скроет вердикт не у тех инцидентов, что пометит движок.
func TestBlindIncident(t *testing.T) {
	want := map[string]bool{"INC-1": false, "INC-2": false, "INC-3": false, "INC-4": true, "INC-6": true, "INC-8": true, "INC-12": false}
	for id, w := range want {
		if got := blindIncident(id); got != w {
			t.Errorf("%s: %v, ожидалось %v", id, got, w)
		}
	}
	n := 0
	for i := 1; i <= 10000; i++ {
		if blindIncident(fmt.Sprintf("INC-%d", i)) {
			n++
		}
	}
	if n != 2502 {
		t.Fatalf("доля слепых на 10 000 инцидентов: %d", n)
	}
	inc := func(id string) *incidents.Incident { return &incidents.Incident{IncidentID: id, Level: "high"} }
	l := storeLabel(inc("INC-4"), secLabel("malicious"))
	if !l.Blind || !l.LabeledByHuman || storeLabel(inc("INC-1"), secLabel("malicious")).Blind {
		t.Fatalf("blind считает движок: %+v", l)
	}
	if (storeLabel(inc("INC-4"), nil) != store.ClosureLabel{}) {
		t.Fatal("переход без метки — нулевая метка")
	}
}

// severity_correct вычисляет движок: ответ «какой уровень правильный» против уровня
// правила; уровень вне шкалы — null, а не «неверно».
func TestStoreLabelSeverityCorrectAndAttackVersion(t *testing.T) {
	for _, c := range []struct {
		level  string
		answer int
		want   *bool
	}{{"high", 3, ptr(true)}, {"high", 4, ptr(false)}, {"low", 1, ptr(true)}, {"critical", 1, ptr(false)}, {"", 3, nil}, {"warning", 2, nil}} {
		l := secLabel("malicious")
		l.SeverityLevel = &c.answer
		got := storeLabel(&incidents.Incident{IncidentID: "INC-1", Level: c.level}, l)
		if got.SeverityLevel == nil || int(*got.SeverityLevel) != c.answer {
			t.Errorf("%s/%d: severity_level %v", c.level, c.answer, got.SeverityLevel)
		}
		if (got.SeverityCorrect == nil) != (c.want == nil) || (c.want != nil && *got.SeverityCorrect != *c.want) {
			t.Errorf("%s/%d: severity_correct %v, ожидалось %v", c.level, c.answer, got.SeverityCorrect, c.want)
		}
		if got.AttackVersion == "" || got.AttackTactic != "credential-access" || got.AttackTechnique != "T1110.001" {
			t.Errorf("тактика, техника и версия справочника: %+v", got)
		}
	}
	fp := storeLabel(&incidents.Incident{IncidentID: "INC-1", Level: "high"}, secLabel("false_positive"))
	if fp.AttackVersion != "" {
		t.Error("без тактики и техники версия справочника не пишется")
	}
	ops := storeLabel(&incidents.Incident{IncidentID: "INC-1", Level: "high"}, opsLabel("disk"))
	if ops.OpsUrgency == nil || *ops.OpsUrgency != 2 || ops.OpsActNow == nil || !*ops.OpsActNow || ops.SeverityCorrect != nil {
		t.Errorf("DevOps: %+v", ops)
	}
}

func ptr[T any](v T) *T { return &v }
