package main

import (
	"context"
	"errors"
	"strings"
	"unicode/utf8"

	"github.com/devitex-soft/argus/engine/internal/incidents"
	"github.com/devitex-soft/argus/engine/internal/store"
	"github.com/devitex-soft/argus/engine/internal/webhook"
)

type workflowRequest struct {
	Actor  string `json:"actor"`
	Role   string `json:"role"`
	Kind   string `json:"kind"` // take | assign | status
	Status string `json:"status"`
	Owner  string `json:"owner"`
	Reason string `json:"reason"`
	// Label — ответ человека, только при завершении (closed, false_positive).
	Label *closureLabel `json:"label,omitempty"`
}

var errIncidentMissing = errors.New("инцидент не найден")

type workflowUserError string

func (e workflowUserError) Error() string { return string(e) }
func isWorkflowUserError(err error) bool {
	var userErr workflowUserError
	return errors.As(err, &userErr)
}

func workflowDecision(inc *incidents.Incident, in workflowRequest) (status, owner string, err error) {
	if inc == nil {
		return "", "", errIncidentMissing
	}
	if in.Actor == "" || len(in.Actor) > 120 || (in.Role != "analyst" && in.Role != "admin") {
		return "", "", workflowUserError("некорректный пользователь")
	}
	if inc.Status == incidents.StatusClosed || inc.Status == incidents.StatusFalsePositive {
		return "", "", workflowUserError("инцидент уже завершён")
	}
	if in.Kind != "status" && in.Label != nil {
		return "", "", workflowUserError("метка ставится только при завершении")
	}
	switch in.Kind {
	case "take":
		if inc.Owner != "" && inc.Owner != in.Actor {
			return "", "", workflowUserError("инцидент назначен другому аналитику")
		}
		if inc.Owner == in.Actor && inc.Status == incidents.StatusInProgress {
			return "", "", workflowUserError("инцидент уже в работе")
		}
		return incidents.StatusInProgress, in.Actor, nil
	case "assign":
		if in.Role != "admin" {
			return "", "", workflowUserError("назначение доступно администратору")
		}
		if in.Owner == "" || len(in.Owner) > 120 || in.Owner == inc.Owner || strings.ContainsAny(in.Owner, "\r\n") {
			return "", "", workflowUserError("некорректный новый ответственный")
		}
		if inc.Status == incidents.StatusNew {
			return incidents.StatusNew, in.Owner, nil
		}
		return incidents.StatusWaitingOwner, in.Owner, nil
	case "status":
		if inc.Owner != in.Actor || inc.Status == incidents.StatusNew || inc.Status == incidents.StatusWaitingOwner {
			return "", "", workflowUserError("сначала возьмите инцидент на себя")
		}
		switch in.Status {
		case incidents.StatusEscalated, incidents.StatusInProgress, incidents.StatusObserving, incidents.StatusClosed, incidents.StatusFalsePositive:
			if in.Status == incidents.StatusClosed || in.Status == incidents.StatusFalsePositive {
				reason := strings.TrimSpace(in.Reason)
				if size := utf8.RuneCountInString(reason); size < 10 || size > 2000 {
					return "", "", workflowUserError("для завершения укажите причину от 10 до 2000 символов")
				}
			}
			if inc.Status == in.Status {
				return "", "", workflowUserError("статус не изменился")
			}
			if err := validateLabel(inc, in.Status, in.Label); err != nil {
				return "", "", err
			}
			return in.Status, in.Actor, nil
		default:
			return "", "", workflowUserError("некорректный статус")
		}
	default:
		return "", "", workflowUserError("неизвестная операция")
	}
}

func (e *engine) transitionIncident(ctx context.Context, id string, in workflowRequest) (store.IncidentStateEvent, error) {
	e.workflowMu.Lock()
	defer e.workflowMu.Unlock()
	inc, err := e.ch.CurrentIncident(ctx, id)
	if err != nil {
		return store.IncidentStateEvent{}, err
	}
	status, owner, err := workflowDecision(inc, in)
	if err != nil {
		return store.IncidentStateEvent{}, err
	}
	event, err := e.ch.AppendIncidentState(ctx, id, in.Actor, in.Kind, status, owner, strings.TrimSpace(in.Reason), storeLabel(id, in.Label))
	if err == nil && status == incidents.StatusEscalated && inc.Status != incidents.StatusEscalated {
		esc := *inc
		esc.Status, esc.Owner = status, owner
		e.hooks.Notify(webhook.EventEscalated, &esc)
	}
	return event, err
}
