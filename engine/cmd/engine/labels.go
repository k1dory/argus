package main

import (
	"crypto/sha256"
	"encoding/binary"
	"slices"
	"strings"

	"github.com/devitex-soft/argus/engine/internal/incidents"
	"github.com/devitex-soft/argus/engine/internal/store"
)

// closureLabel — ответ человека при завершении инцидента, приходит из консоли
// вместе со статусом. Свободная причина (reason) остаётся для людей; обучать и
// считать долю ложных срабатываний можно только по этим полям.
type closureLabel struct {
	Disposition     string `json:"disposition"`
	Escalate        *bool  `json:"escalate"`
	SeverityCorrect *bool  `json:"severity_correct"`
	OpsCause        string `json:"ops_cause"`
	OpsAction       string `json:"ops_action"`
}

// Значения меток. Набор общий с консолью (web/src/lib/shared/closure-label.ts).
var (
	dispositions = []string{"malicious", "benign_authorized", "false_positive"}
	opsCauses    = []string{"real_failure", "planned_work", "monitoring_noise", "wrong_threshold"}
	opsActions   = []string{"fixed", "no_action", "rule_tuned", "handed_over"}
)

// blindPercent — доля инцидентов, которые консоль разбирает вслепую: вердикт
// агента и анализ модели скрыты до закрытия. Выбор детерминирован по
// incident_id (blindIncident), консоль считает его той же функцией.
const blindPercent = 25

// blindIncident — входит ли инцидент в слепую выборку: первые два байта
// SHA-256 от incident_id по модулю 100 меньше blindPercent. Не зависит от
// содержимого и времени — выборка не смещена ни к правилам, ни к уровню.
func blindIncident(id string) bool {
	sum := sha256.Sum256([]byte(id))
	return int(binary.BigEndian.Uint16(sum[:2]))%100 < blindPercent
}

// opsIncident — эксплуатационное правило (теги ops.*): у него вместо вердикта
// ИБ — причина и действие DevOps.
func opsIncident(inc *incidents.Incident) bool {
	return slices.ContainsFunc(inc.Tags, func(t string) bool { return strings.HasPrefix(t, "ops.") })
}

// validateLabel — метка обязательна при завершении и запрещена в остальных
// переходах; набор полей зависит от типа правила.
func validateLabel(inc *incidents.Incident, status string, l *closureLabel) error {
	final := status == incidents.StatusClosed || status == incidents.StatusFalsePositive
	if !final {
		if l != nil {
			return workflowUserError("метка ставится только при завершении")
		}
		return nil
	}
	if l == nil {
		return workflowUserError("для завершения заполните метку ответа")
	}
	if opsIncident(inc) {
		if l.Disposition != "" || l.Escalate != nil || l.SeverityCorrect != nil {
			return workflowUserError("для эксплуатационного правила указываются причина и действие")
		}
		if !slices.Contains(opsCauses, l.OpsCause) || !slices.Contains(opsActions, l.OpsAction) {
			return workflowUserError("укажите причину и действие")
		}
		return nil
	}
	if l.OpsCause != "" || l.OpsAction != "" {
		return workflowUserError("причина и действие DevOps — только для эксплуатационных правил")
	}
	if !slices.Contains(dispositions, l.Disposition) || l.Escalate == nil || l.SeverityCorrect == nil {
		return workflowUserError("укажите характер срабатывания, нужна ли эскалация и верен ли уровень")
	}
	// Статус «ложное срабатывание» и вердикт не должны противоречить друг другу.
	if (status == incidents.StatusFalsePositive) != (l.Disposition == "false_positive") {
		return workflowUserError("статус «ложное срабатывание» ставится вместе с меткой false_positive и только с ней")
	}
	return nil
}

// storeLabel — метка для записи: blind считает движок, а не консоль.
func storeLabel(id string, l *closureLabel) store.ClosureLabel {
	if l == nil {
		return store.ClosureLabel{}
	}
	return store.ClosureLabel{
		Disposition: l.Disposition, Escalate: l.Escalate, SeverityCorrect: l.SeverityCorrect,
		OpsCause: l.OpsCause, OpsAction: l.OpsAction,
		Blind: blindIncident(id), LabeledByHuman: true,
	}
}
