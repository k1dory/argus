// Package registry — постоянный реестр поставляемого набора ARGUS: правила из
// rules/ (id, заголовок, теги) и значения source/action, на которые эти правила
// и фикстуры fixtures/events совпадают точно. shipped.json собирает
// TestShippedRegistry из каталогов репозитория (UPDATE_GOLDEN=1 —
// перегенерировать); без перегенерации тест падает при любой правке правил.
//
// Нужен состоянию моделей решений (analyst.DecisionState) и датасету: туда
// попадают только значения из реестра, остальное — «[rule]», «[source]»,
// «[action]». Пользовательские правила и источники могут называть людей и узлы.
package registry

import (
	_ "embed"
	"encoding/json"
	"regexp"
)

//go:embed shipped.json
var raw []byte

// Rule — поставляемое правило.
type Rule struct {
	Title string   `json:"title"`
	Tags  []string `json:"tags"`
}

// Shipped — содержимое shipped.json.
type Shipped struct {
	Rules   map[string]Rule `json:"rules"`
	Sources []string        `json:"sources"`
	Actions []string        `json:"actions"`
}

var (
	shipped          Shipped
	sources, actions = map[string]bool{}, map[string]bool{}
	tags             = map[string]bool{}
)

func init() {
	if err := json.Unmarshal(raw, &shipped); err != nil {
		panic("registry: shipped.json: " + err.Error())
	}
	for _, s := range shipped.Sources {
		sources[s] = true
	}
	for _, a := range shipped.Actions {
		actions[a] = true
	}
	for _, r := range shipped.Rules {
		for _, t := range r.Tags {
			tags[t] = true
		}
	}
	if len(shipped.Rules) == 0 || len(sources) == 0 || len(actions) == 0 {
		panic("registry: shipped.json пуст")
	}
}

// LookupRule — поставляемое правило по id.
func LookupRule(id string) (Rule, bool) {
	r, ok := shipped.Rules[id]
	return r, ok
}

// Source, Action — значение из реестра.
func Source(s string) bool { return sources[s] }
func Action(s string) bool { return actions[s] }

// attackTagRe — теги ATT&CK по форме (тактика snake_case или техника).
var attackTagRe = regexp.MustCompile(`^attack\.(t\d{4}(\.\d{3})?|[a-z]+(_[a-z]+){0,3})$`)

// Tag — тег поставляемых правил или тег ATT&CK.
func Tag(t string) bool { return tags[t] || attackTagRe.MatchString(t) }

// AttackTag — тег ATT&CK (для пользовательских правил остаются только они).
func AttackTag(t string) bool { return attackTagRe.MatchString(t) }
