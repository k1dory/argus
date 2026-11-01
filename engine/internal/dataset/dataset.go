// Package dataset — записи датасета для обучения и замеров моделей решений
// (Laya, Jev): состояние инцидента → фиксированные вопросы → ответы моделей →
// ответ человека при завершении (метка из incident_state_events, миграции 0033, 0036).
//
// Правила записи (вики argus-laya-данные-и-разметка, решение-argus-laya-классификатор-2026-10):
//   - истина — только ответ человека (labeled_by_human), автозакрытия не попадают;
//   - состояние обезличено всегда (analyst.DecisionState), имя аналитика не пишется;
//   - вопросы — дословно одни и те же при обучении и в работе (Questions);
//   - ответы других моделей хранятся рядом для сравнения, на вход Laya не идут;
//   - разбиение — по group_id: все инциденты одного случая по одну сторону;
//   - сканы и другие массовые правила ограничены MaxPerRule на правило.
package dataset

import (
	"crypto/sha256"
	"encoding/binary"
	"net"
	"slices"
	"sort"
	"strconv"
	"strings"

	"github.com/devitex-soft/argus/engine/internal/analyst"
	"github.com/devitex-soft/argus/engine/internal/attack"
	"github.com/devitex-soft/argus/engine/internal/incidents"
	"github.com/devitex-soft/argus/engine/internal/store"
	"github.com/devitex-soft/argus/engine/internal/systemone"
)

// Schema — версия формата записи. Меняется при изменении вопросов или полей:
// записи разных версий не смешиваются в одном обучении. v2 — форма закрытия по
// плану разметки (миграция 0036): severity_level, attack_tactic,
// attack_technique, ops_cause из 8 причин, ops_act_now, ops_urgency.
const Schema = "argus-dataset/v2"

// Сценарии.
const (
	Security = "security"
	Ops      = "ops"
)

// Варианты ответов — те же, что в форме завершения (engine/cmd/engine/labels.go,
// web/src/lib/shared/closure-label.ts). Тексты фиксированы: правка — новая Schema.
var (
	Dispositions = map[string]string{
		"malicious":         "Real malicious or unauthorized activity that required a response",
		"benign_authorized": "The activity really happened but was legitimate and authorized (admin work, tests, known service)",
		"false_positive":    "The rule fired on events that do not match what it is meant to detect",
	}
	// SeverityLevels — шкала severity_level 1–4; в ответе Score — индекс 0–3.
	SeverityLevels = []string{
		"low: no impact, informational",
		"medium: needs a look during working hours",
		"high: needs a response today",
		"critical: needs an immediate response",
	}
	OpsCauses = map[string]string{
		"disk":                "Disk full, failing or slow",
		"memory":              "Out of memory or memory pressure",
		"network":             "Network problem: link, routing, DNS, firewall",
		"process_crash":       "A process or service crashed or stopped",
		"config":              "Wrong or changed configuration",
		"deploy":              "A deploy or update caused it",
		"external_dependency": "An external dependency failed: upstream service, provider, certificate",
		"false_positive":      "The rule fired but nothing is actually wrong",
	}
	// OpsUrgency — шкала ops_urgency 1–4; в ответе Score — индекс 0–3.
	OpsUrgency = []string{
		"low: can wait for planned work",
		"medium: fix within days",
		"high: fix today",
		"critical: fix now, users are affected",
	}
)

// Ключ «другое» для тактики и техники ATT&CK.
const AttackOther = attack.Other

// TacticQuestion — тактика ATT&CK: 15 тактик справочника и «другое».
func TacticQuestion() systemone.Question {
	crit := map[string]string{AttackOther: "None of the above or not an attack"}
	for _, t := range attack.Tactics() {
		crit[t.Shortname] = t.Name
	}
	return systemone.Question{Type: systemone.Choice, Instructions: "Which MITRE ATT&CK tactic best describes the activity", Criteria: crit}
}

// TechniqueQuestion — техника ATT&CK среди кандидатов для тактики (теги правила,
// соседние техники тактики — attack.Candidates, как в форме закрытия) и «другое».
// Пустая или «другое» тактика — область по тактикам техник из тегов.
func TechniqueQuestion(tags []string, tactic string) systemone.Question {
	crit := map[string]string{AttackOther: "None of the listed techniques fits"}
	for _, id := range attack.Candidates(tags, tactic) {
		t, _ := attack.TechniqueByID(id)
		crit[id] = id + " " + t.Name
	}
	return systemone.Question{Type: systemone.Choice, Instructions: "Which MITRE ATT&CK technique best describes the activity", Criteria: crit}
}

// Questions — набор вопросов сценария. Кандидаты техники зависят от тактики:
// в записи — тактика человека (кандидаты, которые видел аналитик), а без неё —
// тактика по умолчанию из тегов. Моделям техника задаётся вторым шагом по их
// собственной тактике (cmd/engine: askModel), чтобы ответ человека не попадал
// в вопрос.
func Questions(scenario string, tags []string, tactic string) map[string]systemone.Question {
	if scenario == Ops {
		return map[string]systemone.Question{
			"ops_cause": {Type: systemone.Choice, Instructions: "What caused this operations alert", Criteria: OpsCauses},
			"ops_act_now": {Type: systemone.Noul, Instructions: "Someone has to act on this alert right now",
				Criteria: map[string]string{"true": "Act now", "false": "Can wait or needs no action"}},
			"ops_urgency": {Type: systemone.Score, Instructions: "How urgent is this operations alert", Criteria: OpsUrgency},
		}
	}
	if tactic == "" {
		tactic = attack.DefaultTactic(tags)
	}
	return map[string]systemone.Question{
		"disposition": {Type: systemone.Choice, Instructions: "What is the nature of this security incident", Criteria: Dispositions},
		"escalate": {Type: systemone.Noul, Instructions: "This incident needs escalation to a senior analyst or the system owner",
			Criteria: map[string]string{"true": "Needs escalation", "false": "The on-call analyst can close it alone"}},
		"severity_level":   {Type: systemone.Score, Instructions: "Which severity level is right for this incident", Criteria: SeverityLevels},
		"attack_tactic":    TacticQuestion(),
		"attack_technique": TechniqueQuestion(tags, tactic),
	}
}

// Scenario — эксплуатационное правило (теги ops.*) или ИБ.
func Scenario(inc *incidents.Incident) string {
	if slices.ContainsFunc(inc.Tags, func(t string) bool { return strings.HasPrefix(t, "ops.") }) {
		return Ops
	}
	return Security
}

// ModelAnswers — ответы одной модели.
type ModelAnswers struct {
	Model   string                      `json:"model"`
	Answers map[string]systemone.Answer `json:"answers,omitempty"`
	// Questions — вопросы, заданные этой модели иначе, чем в записи:
	// attack_technique с кандидатами по тактике, которую ответила модель.
	Questions map[string]systemone.Question `json:"questions,omitempty"`
	Error     string                        `json:"error,omitempty"`
}

// Question — вопрос, на который ответила модель: свой, если был, иначе из записи.
func (r *Record) Question(model, id string) systemone.Question {
	if q, ok := r.Models[model].Questions[id]; ok {
		return q
	}
	return r.Questions[id]
}

// Record — строка JSONL.
type Record struct {
	Schema     string                        `json:"schema"`
	IncidentID string                        `json:"incident_id"`
	GroupID    string                        `json:"group_id"`
	Split      string                        `json:"split"` // train | holdout
	Scenario   string                        `json:"scenario"`
	Source     string                        `json:"source"` // prod | emulation | honeypot | chaos | public | synthetic | augmented
	RuleID     string                        `json:"rule_id"`
	Level      string                        `json:"level"`
	Tags       []string                      `json:"tags"`
	PII        bool                          `json:"pii"`
	Blind      bool                          `json:"blind"`
	LabeledAt  string                        `json:"labeled_at"`
	State      string                        `json:"state"`
	Questions  map[string]systemone.Question `json:"questions"`
	Labels     map[string]string             `json:"labels"`
	Models     map[string]ModelAnswers       `json:"models,omitempty"`
	// OmittedLabels — метки человека, не выгруженные потому, что их нет среди
	// вариантов вопроса (техника группового закрытия вне кандидатов инцидента).
	OmittedLabels []string `json:"omitted_labels,omitempty"`
}

// HoldoutPercent — доля групп в отложенной выборке.
const HoldoutPercent = 25

// Build — запись по инциденту и метке человека. Nil — метки нет или она
// поставлена не человеком (автозакрытие): такие инциденты не обучают.
func Build(l store.LabeledIncident, source string) *Record {
	inc := &l.Incident
	if !l.Label.LabeledByHuman || Legacy(l) {
		return nil
	}
	scenario := Scenario(inc)
	labels := map[string]string{}
	tactic := ""
	if scenario == Ops {
		put(labels, "ops_cause", l.Label.OpsCause)
		putBool(labels, "ops_act_now", l.Label.OpsActNow)
		putScore(labels, "ops_urgency", l.Label.OpsUrgency)
	} else {
		put(labels, "disposition", l.Label.Disposition)
		putBool(labels, "escalate", l.Label.Escalate)
		putScore(labels, "severity_level", l.Label.SeverityLevel)
		// Метка ATT&CK — только той же версии справочника, что у вопросов.
		if l.Label.AttackVersion == "" || l.Label.AttackVersion == attack.Version() {
			tactic = l.Label.AttackTactic
			put(labels, "attack_tactic", l.Label.AttackTactic)
			put(labels, "attack_technique", l.Label.AttackTechnique)
		}
	}
	if len(labels) == 0 {
		return nil
	}
	group := GroupID(inc)
	split := "train"
	// Разбиение — HMAC ключа случая с секретом выгрузки (ARGUS_DATASET_SECRET):
	// одна группа по одну сторону во всех выгрузках с тем же секретом, а без
	// секрета биты split не сопоставить со словарём адресов и учёток.
	if splitBucket(groupKey(inc)) < HoldoutPercent {
		split = "holdout"
	}
	qs := Questions(scenario, inc.Tags, tactic)
	// Групповое закрытие (#65) предлагает технику по объединению тегов группы,
	// а она может не попасть в кандидаты этого инцидента. Добавить её в
	// варианты нельзя: в работе движок строит кандидатов по тегам самого
	// инцидента, и лишний вариант подсказал бы модели ответ. Такая метка
	// техники не выгружается (тактика и остальные метки остаются).
	var omitted []string
	if tech, ok := labels["attack_technique"]; ok && !slices.Contains(qs["attack_technique"].Options(), tech) {
		delete(labels, "attack_technique")
		omitted = append(omitted, "attack_technique: outside incident candidates")
	}
	return &Record{
		Schema: Schema, IncidentID: inc.IncidentID, GroupID: group, Split: split,
		Scenario: scenario, Source: source, RuleID: recordRuleID(inc), Level: inc.Level, Tags: ruleTags(inc),
		PII: inc.PII != 0, Blind: l.Label.Blind, LabeledAt: l.ChangedAt,
		State: analyst.DecisionState(inc), Questions: qs, Labels: labels, OmittedLabels: omitted,
	}
}

// Legacy — метка закрытия из формы до 0036 (ops_cause из прежних четырёх
// вариантов: real_failure, planned_work, …): в вопросы v2 она не входит, такие
// записи не выгружаются (datasetStats.SkippedLegacy).
func Legacy(l store.LabeledIncident) bool {
	if Scenario(&l.Incident) != Ops || l.Label.OpsCause == "" {
		return false
	}
	_, ok := OpsCauses[l.Label.OpsCause]
	return !ok
}

func put(m map[string]string, k, v string) {
	if v != "" {
		m[k] = v
	}
}

func putBool(m map[string]string, k string, v *bool) {
	if v != nil {
		m[k] = strconv.FormatBool(*v)
	}
}

// putScore — шкала 1–4 в индекс варианта Score ("0".."3"), как в probabilities.
func putScore(m map[string]string, k string, v *uint8) {
	if v != nil && *v >= 1 && *v <= 4 {
		m[k] = strconv.Itoa(int(*v) - 1)
	}
}

// GroupID — исходный случай: правило и субъект. Адрес субъекта схлопывается
// до сети (/24, /48): сканер, перебирающий соседние адреса, — один случай,
// иначе варианты одного скана окажутся по обе стороны разбиения.
//
// В JSONL — HMAC с солью выгрузки (analyst.Process): по открытому хешу
// правила и субъекта словарём восстанавливались бы учётки, узлы и подсети.
func GroupID(inc *incidents.Incident) string {
	return "g-" + analyst.Process().Key("group", groupKey(inc))
}

// groupKey — «правило|субъект» до хеширования; наружу не выдаётся.
func groupKey(inc *incidents.Incident) string {
	subject := inc.ActorName
	if subject == "" {
		subject = inc.Node
	}
	if ip := net.ParseIP(subject); ip != nil {
		if v4 := ip.To4(); v4 != nil {
			subject = v4.Mask(net.CIDRMask(24, 32)).String() + "/24"
		} else {
			subject = ip.Mask(net.CIDRMask(48, 128)).String() + "/48"
		}
	} else {
		subject = strings.ToLower(subject)
	}
	return inc.RuleID + "|" + subject
}

// splitBucket — корзина 0–99 разбиения train/holdout с секретом выгрузки.
func splitBucket(key string) int {
	h := analyst.Process().Key("split", key)
	n, _ := strconv.ParseUint(h[:8], 16, 32)
	return int(n % 100)
}

// recordRuleID — id поставляемого правила как есть, пользовательского —
// псевдоним (в id оператор пишет что угодно, в том числе имена).
func recordRuleID(inc *incidents.Incident) string {
	if id, _, _ := analyst.Rule(inc); id != "[rule]" {
		return id
	}
	return "rule-" + analyst.Process().Key("rule", inc.RuleID)
}

// ruleTags — теги, как в состоянии: поставляемого правила — из реестра,
// пользовательского — только ATT&CK. Сырые теги в запись не попадают.
func ruleTags(inc *incidents.Incident) []string {
	_, _, tags := analyst.Rule(inc)
	return tags
}

// MaxPerRule — потолок записей одного правила: без него тысячи сканов
// научат модель одному правилу «скан = шум» (DECISIONS §5).
const MaxPerRule = 100

// capOrder — порядок выбора групп под потолком. Хеш с другой солью, чем
// bucket (разбиение train/holdout): иначе первыми шли бы группы с малым
// bucket, то есть только holdout, и при сотне групп train оставался пустым.
func capOrder(group string) uint64 {
	sum := sha256.Sum256([]byte("cap|" + group))
	return binary.BigEndian.Uint64(sum[:8])
}

// Cap оставляет не больше max записей на правило. Выбор детерминирован (по
// хешу group_id, независимому от разбиения, затем incident_id) и не зависит
// от порядка входа; сначала берёт разные группы: из сотни записей одного
// правила — как можно больше разных случаев.
func Cap(recs []*Record, max int) []*Record {
	if max <= 0 {
		return recs
	}
	byRule := map[string][]*Record{}
	var order []string
	for _, r := range recs {
		if _, ok := byRule[r.RuleID]; !ok {
			order = append(order, r.RuleID)
		}
		byRule[r.RuleID] = append(byRule[r.RuleID], r)
	}
	sort.Strings(order)
	var out []*Record
	for _, rule := range order {
		rs := byRule[rule]
		sort.SliceStable(rs, func(i, j int) bool {
			bi, bj := capOrder(rs[i].GroupID), capOrder(rs[j].GroupID)
			if bi != bj {
				return bi < bj
			}
			if rs[i].GroupID != rs[j].GroupID {
				return rs[i].GroupID < rs[j].GroupID
			}
			return rs[i].IncidentID < rs[j].IncidentID
		})
		// Круговой обход групп: сначала по одной записи из каждой группы.
		groups := map[string][]*Record{}
		var gorder []string
		for _, r := range rs {
			if _, ok := groups[r.GroupID]; !ok {
				gorder = append(gorder, r.GroupID)
			}
			groups[r.GroupID] = append(groups[r.GroupID], r)
		}
		taken := 0
		for round := 0; taken < max; round++ {
			progressed := false
			for _, g := range gorder {
				if round < len(groups[g]) && taken < max {
					out = append(out, groups[g][round])
					taken++
					progressed = true
				}
			}
			if !progressed {
				break
			}
		}
	}
	return out
}
