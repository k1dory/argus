package main

import (
	"strings"
	"testing"

	"github.com/devitex-soft/argus/engine/internal/incidents"
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
	status, _, err = workflowDecision(inc, workflowRequest{Actor: "bob", Role: "analyst", Kind: "status", Status: incidents.StatusClosed, Reason: "Проверены события, угрозы нет"})
	if err != nil || status != incidents.StatusClosed {
		t.Fatalf("закрытие: %q %v", status, err)
	}
	if _, _, err := workflowDecision(inc, workflowRequest{Actor: "bob", Role: "analyst", Kind: "status", Status: incidents.StatusClosed, Reason: strings.Repeat("Я", 2000)}); err != nil {
		t.Fatalf("причина из 2000 кириллических символов отклонена: %v", err)
	}
	if _, _, err := workflowDecision(inc, workflowRequest{Actor: "bob", Role: "analyst", Kind: "status", Status: incidents.StatusClosed, Reason: strings.Repeat("Я", 2001)}); err == nil {
		t.Fatal("причина длиннее 2000 символов принята")
	}
}
