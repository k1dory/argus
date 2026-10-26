package identity

import (
	"fmt"
	"path"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/devitex-soft/argus/engine/internal/model"
)

// Политики алиасов — ограничения на алиасы, которые приходят событиями
// identity.alias (source = event:<источник>). Файл и API консоли пишет
// администратор, и к ним политики не применяются: они сторожат автоматику —
// экспортер, который вдруг раздаёт адреса не тем, перебирает устройства или
// шлёт алиасы вида, для которого ему не доверяют. Формат — в identities.yml:
//
//	policies:
//	  ip:    { sources: ["event:vpn.*"], max_open: 2, churn: { max: 20, window: 24h }, on_violation: flag }
//	  host:  { sources: ["event:mdm.*"], max_open: 1, churn: { max: 1, window: 30d }, on_violation: hold }
//	  email: { sources: [], churn: { max: 1, window: 90d }, on_violation: reject }
//
// Ключ — вид алиаса; вид без политики не ограничен. Правила проверяются по
// порядку sources → max_open → churn, фиксируется первое нарушение.

// Правила политики (attrs.rule события нарушения).
const (
	RuleSources = "sources"
	RuleMaxOpen = "max_open"
	RuleChurn   = "churn"
)

// Действия при нарушении (on_violation).
const (
	ActionFlag   = "flag"   // записать как есть, note с префиксом policy:<rule>
	ActionHold   = "hold"   // записать с confidence 0.3 и note policy:hold:<rule>: консоль показывает, но в склейке не участвует
	ActionReject = "reject" // не записывать
)

// HoldConfidence — доверие алиаса, записанного по on_violation: hold. Ниже
// порога 0.5, по которому консоль отличает «удержанные» алиасы.
const HoldConfidence float32 = 0.3

// Событие нарушения политики в журнале argus.events.
const (
	ViolationSource   = "argus.identity"
	ViolationAction   = "identity.policy.violation"
	ViolationSeverity = 6
)

// Policy — ограничения одного вида алиасов.
type Policy struct {
	Kind string
	// Sources — глобы допустимых источников событий (сравнение с
	// «event:<source>»); nil — любой источник, пустой список — событиям
	// алиасы этого вида запрещены (только yaml и api).
	Sources []string
	// MaxOpen — не больше одновременно действующих (valid_to NULL) алиасов
	// вида у персоны; 0 — без предела.
	MaxOpen int
	// ChurnMax новых интервалов за ChurnWindow у персоны (считая входящий);
	// 0 — без предела. ChurnRaw — окно как записано в файле (для событий).
	ChurnMax    int
	ChurnWindow time.Duration
	ChurnRaw    string
	OnViolation string // flag | hold | reject
}

// Policies — политики по виду алиаса.
type Policies map[string]Policy

// Decision — итог проверки алиаса: Rule пустое — нарушения нет.
type Decision struct {
	Rule   string // sources | max_open | churn
	Action string // flag | hold | reject
	Limit  int    // предел нарушенного правила (0 у sources)
	Window string // окно churn как в файле; пусто у остальных
	Count  int    // наблюдаемое: открытых (max_open), интервалов в окне (churn), 1 у sources
}

// filePolicy — политика в identities.yml.
type filePolicy struct {
	Sources *[]string `yaml:"sources"`
	MaxOpen int       `yaml:"max_open"`
	Churn   *struct {
		Max    int    `yaml:"max"`
		Window string `yaml:"window"`
	} `yaml:"churn"`
	OnViolation string `yaml:"on_violation"`
}

// parsePolicies — проверка блока policies; path — для сообщений об ошибках.
func parsePolicies(raw map[string]filePolicy) (Policies, error) {
	if len(raw) == 0 {
		return nil, nil
	}
	kinds := make([]string, 0, len(raw))
	for k := range raw {
		kinds = append(kinds, k)
	}
	sort.Strings(kinds)
	out := Policies{}
	for _, kind := range kinds {
		fp := raw[kind]
		p := "policies." + kind
		if !ValidKind(kind) {
			return nil, fmt.Errorf("%s: неизвестный вид алиаса (ожидается %s)", p, strings.Join(Kinds, " | "))
		}
		pol := Policy{Kind: kind, MaxOpen: fp.MaxOpen, OnViolation: strings.TrimSpace(fp.OnViolation)}
		if fp.MaxOpen < 0 {
			return nil, fmt.Errorf("%s.max_open: %d (ожидается 0 или больше)", p, fp.MaxOpen)
		}
		if fp.Sources != nil {
			pol.Sources = make([]string, 0, len(*fp.Sources))
			for i, g := range *fp.Sources {
				g = strings.TrimSpace(g)
				if g == "" {
					return nil, fmt.Errorf("%s.sources[%d]: пустой глоб", p, i)
				}
				if !strings.HasPrefix(g, SourceEventPrefix) {
					g = SourceEventPrefix + g
				}
				if _, err := path.Match(g, ""); err != nil {
					return nil, fmt.Errorf("%s.sources[%d]: глоб %q не разбирается", p, i, g)
				}
				pol.Sources = append(pol.Sources, g)
			}
		}
		if fp.Churn != nil {
			if fp.Churn.Max < 1 {
				return nil, fmt.Errorf("%s.churn.max: %d (ожидается 1 или больше)", p, fp.Churn.Max)
			}
			w, err := ParseWindow(fp.Churn.Window)
			if err != nil {
				return nil, fmt.Errorf("%s.churn.window: %w", p, err)
			}
			pol.ChurnMax, pol.ChurnWindow, pol.ChurnRaw = fp.Churn.Max, w, strings.TrimSpace(fp.Churn.Window)
		}
		switch pol.OnViolation {
		case "":
			pol.OnViolation = ActionFlag
		case ActionFlag, ActionHold, ActionReject:
		default:
			return nil, fmt.Errorf("%s.on_violation: %q (ожидается flag | hold | reject)", p, fp.OnViolation)
		}
		if pol.Sources == nil && pol.MaxOpen == 0 && pol.ChurnMax == 0 {
			return nil, fmt.Errorf("%s: политика без ограничений (нужно sources, max_open или churn)", p)
		}
		out[kind] = pol
	}
	return out, nil
}

// ParseWindow — длительность окна: как у time.ParseDuration (24h, 90m) плюс
// суффиксы d (сутки) и w (недели): 30d, 2w. Нуль и отрицательные — ошибка.
func ParseWindow(s string) (time.Duration, error) {
	s = strings.TrimSpace(s)
	if s == "" {
		return 0, fmt.Errorf("пустое окно (ожидается 24h, 30d, 2w)")
	}
	var d time.Duration
	var err error
	switch {
	case strings.HasSuffix(s, "d"), strings.HasSuffix(s, "w"):
		n, perr := strconv.Atoi(s[:len(s)-1])
		if perr != nil {
			return 0, fmt.Errorf("окно %q: ожидается целое число суток или недель", s)
		}
		d = time.Duration(n) * 24 * time.Hour
		if strings.HasSuffix(s, "w") {
			d *= 7
		}
	default:
		d, err = time.ParseDuration(s)
		if err != nil {
			return 0, fmt.Errorf("окно %q: ожидается 24h, 30d, 2w", s)
		}
	}
	if d <= 0 {
		return 0, fmt.Errorf("окно %q: ожидается положительная длительность", s)
	}
	return d, nil
}

// Evaluate — проверка входящего алиаса из события на фоне state: алиасов
// той же персоны и вида, уже записанных или ожидающих записи в этом же
// батче. Алиасы не из событий (yaml, api) и виды без политики проходят без
// проверки. Повтор уже известного интервала (тот же ключ) ни открытых, ни
// новых не добавляет — снимки экспортеры шлют повторно.
func (ps Policies) Evaluate(a Alias, state []Alias) Decision {
	pol, ok := ps[a.Kind]
	if !ok || !strings.HasPrefix(a.Source, SourceEventPrefix) {
		return Decision{}
	}
	d := Decision{Action: pol.OnViolation}
	if pol.Sources != nil && !matchAny(pol.Sources, a.Source) {
		d.Rule, d.Count = RuleSources, 1
		return d
	}
	open, inWindow := 0, 0
	start := a.ValidFrom.Add(-pol.ChurnWindow)
	for _, s := range state {
		if s.PersonID != a.PersonID || s.Kind != a.Kind {
			continue
		}
		if s.Key() == a.Key() {
			// Повтор известного интервала: открытых и новых не прибавляет,
			// max_open и churn к нему не применяются.
			return Decision{}
		}
		if s.ValidTo == nil {
			open++
		}
		// Окно (from - window, from]: интервал ровно на границе — вне окна.
		if pol.ChurnMax > 0 && s.ValidFrom.After(start) && !s.ValidFrom.After(a.ValidFrom) {
			inWindow++
		}
	}
	if a.ValidTo == nil {
		open++
	}
	inWindow++ // входящий
	if pol.MaxOpen > 0 && open > pol.MaxOpen {
		d.Rule, d.Limit, d.Count = RuleMaxOpen, pol.MaxOpen, open
		return d
	}
	if pol.ChurnMax > 0 && inWindow > pol.ChurnMax {
		d.Rule, d.Limit, d.Window, d.Count = RuleChurn, pol.ChurnMax, pol.ChurnRaw, inWindow
		return d
	}
	return Decision{}
}

func matchAny(globs []string, source string) bool {
	for _, g := range globs {
		if ok, _ := path.Match(g, source); ok {
			return true
		}
	}
	return false
}

// Apply — алиас после решения: flag — note с префиксом policy:<rule>, hold —
// ещё и confidence = HoldConfidence; reject — ok = false, писать нечего.
func (d Decision) Apply(a Alias) (out Alias, ok bool) {
	if d.Rule == "" {
		return a, true
	}
	switch d.Action {
	case ActionReject:
		return a, false
	case ActionHold:
		a.Confidence = HoldConfidence
		a.Note = joinNote("policy:hold:"+d.Rule, a.Note)
	default:
		a.Note = joinNote("policy:"+d.Rule, a.Note)
	}
	return a, true
}

// joinNote — префикс политики перед исходной заметкой; повторное решение по
// тому же алиасу префикс не дублирует.
func joinNote(prefix, note string) string {
	if note == "" {
		return prefix
	}
	if note == prefix || strings.HasPrefix(note, prefix+"; ") {
		return note
	}
	return prefix + "; " + note
}

// ViolationEvent — событие нарушения для журнала: ts — время события-алиаса,
// actor_name — персона, object — вид:значение, value — наблюдаемое число
// (открытых или интервалов в окне), attrs — политика, правило, пределы,
// источник события и принятое действие. Правила rules/ops/identity-*.yml
// заводят по нему инциденты.
func (d Decision) ViolationEvent(ev *model.Event, a Alias) *model.Event {
	attrs := map[string]string{
		"policy": a.Kind, "rule": d.Rule, "source": strings.TrimSpace(ev.Source), "action_taken": d.Action,
	}
	if d.Limit > 0 {
		attrs["limit"] = strconv.Itoa(d.Limit)
	}
	if d.Window != "" {
		attrs["window"] = d.Window
	}
	out := &model.Event{
		TS: ev.TS, Source: ViolationSource, SourceClass: "identity", Action: ViolationAction, Outcome: "failure",
		Severity: ViolationSeverity, ActorName: a.PersonID, ActorKind: ev.ActorKind, Object: a.Kind + ":" + a.Value,
		Value: float64(d.Count), Unit: "count", Attrs: attrs,
	}
	out.Ensure()
	return out
}
