package main

import (
	"crypto/sha256"
	"encoding/binary"
	"slices"
	"strings"

	"github.com/devitex-soft/argus/engine/internal/attack"
	"github.com/devitex-soft/argus/engine/internal/incidents"
	"github.com/devitex-soft/argus/engine/internal/store"
)

// closureLabel — ответ человека при завершении инцидента, приходит из консоли
// вместе со статусом. Свободная причина (reason) остаётся для людей; обучать и
// считать долю ложных срабатываний можно только по этим полям. Вопросы — план
// разметки (вики argus-laya-данные-и-разметка). severity_correct консоль не
// присылает: движок вычисляет его из severity_level и уровня правила.
type closureLabel struct {
	Disposition     string `json:"disposition"`
	Escalate        *bool  `json:"escalate"`
	SeverityLevel   *int   `json:"severity_level"`
	AttackTactic    string `json:"attack_tactic"`
	AttackTechnique string `json:"attack_technique"`
	OpsCause        string `json:"ops_cause"`
	OpsActNow       *bool  `json:"ops_act_now"`
	OpsUrgency      *int   `json:"ops_urgency"`
	OpsAction       string `json:"ops_action"`
}

// Значения меток. Набор общий с консолью (web/src/lib/shared/closure-label.ts) и
// конвейером датасета; тактики и техники — справочник internal/attack.
var (
	dispositions   = []string{"malicious", "benign_authorized", "false_positive"}
	severityLevels = []string{"low", "medium", "high", "critical"} // severity_level 1–4
	opsCauses      = []string{"disk", "memory", "network", "process_crash", "config", "deploy", "external_dependency", "false_positive"}
	opsActions     = []string{"fixed", "no_action", "rule_tuned", "handed_over"}
)

func score(p *int) bool { return p != nil && *p >= 1 && *p <= 4 }

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
		if l.Disposition != "" || l.Escalate != nil || l.SeverityLevel != nil || l.AttackTactic != "" || l.AttackTechnique != "" {
			return workflowUserError("для эксплуатационного правила указываются причина, срочность и действие")
		}
		if !slices.Contains(opsCauses, l.OpsCause) || l.OpsActNow == nil || !score(l.OpsUrgency) {
			return workflowUserError("укажите причину, нужно ли действовать сейчас и срочность")
		}
		if l.OpsAction != "" && !slices.Contains(opsActions, l.OpsAction) {
			return workflowUserError("неизвестное действие")
		}
		if (status == incidents.StatusFalsePositive) != (l.OpsCause == "false_positive") {
			return workflowUserError("статус «ложное срабатывание» ставится вместе с причиной false_positive и только с ней")
		}
		return nil
	}
	if l.OpsCause != "" || l.OpsActNow != nil || l.OpsUrgency != nil || l.OpsAction != "" {
		return workflowUserError("причина и срочность DevOps — только для эксплуатационных правил")
	}
	if !slices.Contains(dispositions, l.Disposition) || l.Escalate == nil || !score(l.SeverityLevel) {
		return workflowUserError("укажите характер срабатывания, нужна ли эскалация и правильный уровень")
	}
	// Статус «ложное срабатывание» и вердикт не должны противоречить друг другу.
	if (status == incidents.StatusFalsePositive) != (l.Disposition == "false_positive") {
		return workflowUserError("статус «ложное срабатывание» ставится вместе с меткой false_positive и только с ней")
	}
	// У ложного срабатывания тактики может не быть; у остальных — обязательна.
	if l.Disposition != "false_positive" && (l.AttackTactic == "" || l.AttackTechnique == "") {
		return workflowUserError("укажите тактику и технику ATT&CK (или «другое»)")
	}
	if (l.AttackTactic != "" && !attack.Tactic(l.AttackTactic)) || (l.AttackTechnique != "" && !attack.Technique(l.AttackTechnique)) ||
		(l.AttackTechnique != "" && l.AttackTactic == "") {
		return workflowUserError("тактика и техника — из справочника ATT&CK или «другое»")
	}
	return nil
}

// storeLabel — метка для записи: blind и severity_correct считает движок, а не
// консоль; версия справочника ATT&CK — рядом с тактикой и техникой.
func storeLabel(inc *incidents.Incident, l *closureLabel) store.ClosureLabel {
	if l == nil {
		return store.ClosureLabel{}
	}
	out := store.ClosureLabel{
		Disposition: l.Disposition, Escalate: l.Escalate,
		AttackTactic: l.AttackTactic, AttackTechnique: l.AttackTechnique,
		OpsCause: l.OpsCause, OpsActNow: l.OpsActNow, OpsAction: l.OpsAction,
		Blind: blindIncident(inc.IncidentID), LabeledByHuman: true,
	}
	if l.SeverityLevel != nil {
		level := uint8(*l.SeverityLevel)
		out.SeverityLevel = &level
		if i := slices.Index(severityLevels, inc.Level); i >= 0 {
			correct := i+1 == *l.SeverityLevel
			out.SeverityCorrect = &correct
		}
	}
	if l.OpsUrgency != nil {
		urgency := uint8(*l.OpsUrgency)
		out.OpsUrgency = &urgency
	}
	if l.AttackTactic != "" || l.AttackTechnique != "" {
		out.AttackVersion = attack.Version()
	}
	return out
}
