// Package dataset — записи датасета для обучения и замеров моделей решений
// (Laya, Jev): состояние инцидента → фиксированные вопросы → ответы моделей →
// ответ человека при завершении (метка из incident_state_events, миграция 0033).
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
	"github.com/devitex-soft/argus/engine/internal/incidents"
	"github.com/devitex-soft/argus/engine/internal/store"
	"github.com/devitex-soft/argus/engine/internal/systemone"
)

// Schema — версия формата записи. Меняется при изменении вопросов или полей:
// записи разных версий не смешиваются в одном обучении.
const Schema = "argus-dataset/v1"

// Сценарии.
const (
	Security = "security"
	Ops      = "ops"
)

// Варианты ответов — те же, что в форме завершения (engine/cmd/engine/labels.go,
// web/src/lib/shared/closure-label.ts).
var (
	Dispositions = map[string]string{
		"malicious":         "Real malicious or unauthorized activity that required a response",
		"benign_authorized": "The activity really happened but was legitimate and authorized (admin work, tests, known service)",
		"false_positive":    "The rule fired on events that do not match what it is meant to detect",
	}
	OpsCauses = map[string]string{
		"real_failure":     "A real failure: disk, memory, network, crashed process, bad config or deploy, external dependency",
		"planned_work":     "Planned maintenance or deploy that was expected",
		"monitoring_noise": "Monitoring noise: a transient blip with no impact",
		"wrong_threshold":  "The rule threshold does not fit this host or service",
	}
	OpsActions = map[string]string{
		"fixed":       "Someone fixed the cause",
		"no_action":   "No action was needed",
		"rule_tuned":  "The rule or its threshold was changed",
		"handed_over": "Handed over to the owner of the system",
	}
	// Tactics — тактики MITRE ATT&CK Enterprise и «другое». Метки человека у
	// тактики пока нет (форма завершения её не спрашивает): ответы моделей
	// пишутся для сравнения с тегом правила attack.<тактика>.
	Tactics = map[string]string{
		"reconnaissance":       "Reconnaissance (TA0043)",
		"resource_development": "Resource Development (TA0042)",
		"initial_access":       "Initial Access (TA0001)",
		"execution":            "Execution (TA0002)",
		"persistence":          "Persistence (TA0003)",
		"privilege_escalation": "Privilege Escalation (TA0004)",
		"defense_evasion":      "Defense Evasion (TA0005)",
		"credential_access":    "Credential Access (TA0006)",
		"discovery":            "Discovery (TA0007)",
		"lateral_movement":     "Lateral Movement (TA0008)",
		"collection":           "Collection (TA0009)",
		"command_and_control":  "Command and Control (TA0011)",
		"exfiltration":         "Exfiltration (TA0010)",
		"impact":               "Impact (TA0040)",
		"other":                "None of the above or not an attack",
	}
)

// Questions — набор вопросов сценария. Тексты фиксированы: правка текста —
// новая Schema.
func Questions(scenario string) map[string]systemone.Question {
	if scenario == Ops {
		return map[string]systemone.Question{
			"ops_cause":  {Type: systemone.Choice, Instructions: "What caused this operations alert", Criteria: OpsCauses},
			"ops_action": {Type: systemone.Choice, Instructions: "What should be done about this alert", Criteria: OpsActions},
		}
	}
	return map[string]systemone.Question{
		"disposition": {Type: systemone.Choice, Instructions: "What is the nature of this security incident", Criteria: Dispositions},
		"escalate": {Type: systemone.Noul, Instructions: "This incident needs escalation to a senior analyst or the system owner",
			Criteria: map[string]string{"true": "Needs escalation", "false": "The on-call analyst can close it alone"}},
		"severity_correct": {Type: systemone.Noul, Instructions: "The severity level assigned by the rule is right for this incident",
			Criteria: map[string]string{"true": "The level fits", "false": "The level is too high or too low"}},
		"tactic": {Type: systemone.Choice, Instructions: "Which MITRE ATT&CK tactic best describes the activity", Criteria: Tactics},
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
	Error   string                      `json:"error,omitempty"`
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
}

// HoldoutPercent — доля групп в отложенной выборке.
const HoldoutPercent = 25

// Build — запись по инциденту и метке человека. Nil — метки нет или она
// поставлена не человеком (автозакрытие): такие инциденты не обучают.
func Build(l store.LabeledIncident, source string) *Record {
	inc := &l.Incident
	if !l.Label.LabeledByHuman {
		return nil
	}
	scenario := Scenario(inc)
	labels := map[string]string{}
	if scenario == Ops {
		put(labels, "ops_cause", l.Label.OpsCause)
		put(labels, "ops_action", l.Label.OpsAction)
	} else {
		put(labels, "disposition", l.Label.Disposition)
		if l.Label.Escalate != nil {
			labels["escalate"] = strconv.FormatBool(*l.Label.Escalate)
		}
		if l.Label.SeverityCorrect != nil {
			labels["severity_correct"] = strconv.FormatBool(*l.Label.SeverityCorrect)
		}
	}
	if len(labels) == 0 {
		return nil
	}
	group := GroupID(inc)
	split := "train"
	if bucket(group) < HoldoutPercent {
		split = "holdout"
	}
	return &Record{
		Schema: Schema, IncidentID: inc.IncidentID, GroupID: group, Split: split,
		Scenario: scenario, Source: source, RuleID: inc.RuleID, Level: inc.Level, Tags: inc.Tags,
		PII: inc.PII != 0, Blind: l.Label.Blind, LabeledAt: l.ChangedAt,
		State: analyst.DecisionState(inc), Questions: Questions(scenario), Labels: labels,
	}
}

func put(m map[string]string, k, v string) {
	if v != "" {
		m[k] = v
	}
}

// GroupID — исходный случай: правило и субъект. Адрес субъекта схлопывается
// до сети (/24, /48): сканер, перебирающий соседние адреса, — один случай,
// иначе варианты одного скана окажутся по обе стороны разбиения.
func GroupID(inc *incidents.Incident) string {
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
	sum := sha256.Sum256([]byte(inc.RuleID + "|" + subject))
	return "g-" + hexPrefix(sum[:6])
}

func hexPrefix(b []byte) string {
	const digits = "0123456789abcdef"
	out := make([]byte, 0, len(b)*2)
	for _, c := range b {
		out = append(out, digits[c>>4], digits[c&0xf])
	}
	return string(out)
}

func bucket(s string) int {
	sum := sha256.Sum256([]byte("split|" + s))
	return int(binary.BigEndian.Uint16(sum[:2])) % 100
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
