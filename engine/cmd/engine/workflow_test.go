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
	yes, no := true, false
	return &closureLabel{Disposition: disposition, Escalate: &no, SeverityCorrect: &yes}
}

func TestWorkflowClosureLabel(t *testing.T) {
	sec := &incidents.Incident{Status: incidents.StatusInProgress, Owner: "anna", Tags: []string{"attack.t1110"}}
	ops := &incidents.Incident{Status: incidents.StatusInProgress, Owner: "anna", Tags: []string{"argus.system", "ops.storage"}}
	req := func(status string, l *closureLabel) workflowRequest {
		return workflowRequest{Actor: "anna", Role: "analyst", Kind: "status", Status: status, Reason: "проверено по журналу", Label: l}
	}
	yes := true
	for name, c := range map[string]struct {
		inc *incidents.Incident
		in  workflowRequest
		ok  bool
	}{
		"ИБ: полная метка":              {sec, req(incidents.StatusClosed, secLabel("malicious")), true},
		"ИБ: без метки":                 {sec, req(incidents.StatusClosed, nil), false},
		"ИБ: неизвестный вердикт":       {sec, req(incidents.StatusClosed, secLabel("maybe")), false},
		"ИБ: эскалация не указана":      {sec, req(incidents.StatusClosed, &closureLabel{Disposition: "malicious", SeverityCorrect: &yes}), false},
		"ИБ: ложное без false_positive": {sec, req(incidents.StatusFalsePositive, secLabel("benign_authorized")), false},
		"ИБ: закрыт как false_positive": {sec, req(incidents.StatusClosed, secLabel("false_positive")), false},
		"ИБ: ложное срабатывание":       {sec, req(incidents.StatusFalsePositive, secLabel("false_positive")), true},
		"ИБ: поля DevOps":               {sec, req(incidents.StatusClosed, &closureLabel{OpsCause: "planned_work", OpsAction: "no_action"}), false},
		"DevOps: причина и действие":    {ops, req(incidents.StatusClosed, &closureLabel{OpsCause: "planned_work", OpsAction: "no_action"}), true},
		"DevOps: без действия":          {ops, req(incidents.StatusClosed, &closureLabel{OpsCause: "planned_work"}), false},
		"DevOps: вердикт ИБ":            {ops, req(incidents.StatusClosed, secLabel("malicious")), false},
		"метка без завершения":          {sec, req(incidents.StatusObserving, secLabel("malicious")), false},
		"метка во взятии в работу":      {sec, workflowRequest{Actor: "anna", Role: "analyst", Kind: "take", Label: secLabel("malicious")}, false},
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
	l := storeLabel("INC-4", secLabel("malicious"))
	if !l.Blind || !l.LabeledByHuman || storeLabel("INC-1", secLabel("malicious")).Blind {
		t.Fatalf("blind считает движок: %+v", l)
	}
	if (storeLabel("INC-4", nil) != store.ClosureLabel{}) {
		t.Fatal("переход без метки — нулевая метка")
	}
}
