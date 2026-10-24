// Package eval — оценка правил над потоком событий в памяти. Один и тот же
// код работает вживую (буфер из ClickHouse) и на replay записанного трафика,
// поэтому тест правила и продакшн не расходятся.
package eval

import (
	"math"
	"sort"
	"time"

	"github.com/devitex-soft/argus/engine/internal/model"
	"github.com/devitex-soft/argus/engine/internal/rules"
)

// Detection — сработка: правило, ключ группы и события в окне.
type Detection struct {
	Rule   *rules.Rule
	Key    string
	Events []*model.Event
	First  time.Time
	Last   time.Time
	Reason string // для absence/periodic — человекочитаемое основание
}

// Closer — событие close_on: открытый инцидент правила по этому ключу закрыть.
type Closer struct {
	Rule  *rules.Rule
	Key   string
	Event *model.Event
}

// Exception — исключение из правила (обратная связь «ложное срабатывание»).
type Exception struct {
	Field string
	Value string
}

type Input struct {
	Rules      []*rules.Rule
	Events     []*model.Event
	Now        time.Time              // точка «сейчас» для absence; zero → max ts событий
	Exceptions map[string][]Exception // rule_id → исключения
}

// Run — совместимая обёртка: правила по событиям, без исключений и closers.
func Run(rs []*rules.Rule, events []*model.Event) []Detection {
	dets, _ := Evaluate(Input{Rules: rs, Events: events})
	return dets
}

func Evaluate(in Input) ([]Detection, []Closer) {
	events := in.Events
	sort.SliceStable(events, func(i, j int) bool { return events[i].Time().Before(events[j].Time()) })
	now := in.Now
	if now.IsZero() && len(events) > 0 {
		now = events[len(events)-1].Time()
	}
	var dets []Detection
	var closers []Closer
	for _, r := range in.Rules {
		exc := in.Exceptions[r.ID]
		filtered := events
		if len(exc) > 0 {
			filtered = filtered[:0:0]
			for _, e := range events {
				if !excluded(e, exc) {
					filtered = append(filtered, e)
				}
			}
		}
		dets = append(dets, runRule(r, filtered, now)...)
		if len(r.CloseOn) > 0 {
			keyOf := rules.Getter(r.GroupBy())
			for _, e := range filtered {
				if r.MatchClose(e) {
					closers = append(closers, Closer{Rule: r, Key: groupKey(keyOf, e), Event: e})
				}
			}
		}
	}
	return dets, closers
}

// exceptionFields — по каким полям консоль может исключать события из правила.
// Остальные (severity, action, source…) вырезали бы целые классы событий
// одним кликом «ложное» — такие исключения игнорируются с записью в лог.
// dst.ip — риск тот же, что у src.ip (один адрес), консоль его уже предлагает.
// Единый источник правды для консоли — GET /rules/exception_fields движка.
var exceptionFields = map[string]bool{"src.ip": true, "dst.ip": true, "actor.name": true, "node": true, "object": true}

// ExceptionFieldAllowed — поле входит в whitelist исключений.
func ExceptionFieldAllowed(field string) bool { return exceptionFields[field] }

// ExceptionFields — whitelist полей исключений в стабильном порядке (для API и логов).
func ExceptionFields() []string {
	out := make([]string, 0, len(exceptionFields))
	for f := range exceptionFields {
		out = append(out, f)
	}
	sort.Strings(out)
	return out
}

// SanitizeExceptions оставляет только исключения по разрешённым полям с
// непустым значением; про каждое отброшенное зовёт warn (nil — молча).
func SanitizeExceptions(exc map[string][]Exception, warn func(ruleID, field, value string)) map[string][]Exception {
	out := make(map[string][]Exception, len(exc))
	for rule, list := range exc {
		for _, x := range list {
			if !exceptionFields[x.Field] || x.Value == "" {
				if warn != nil {
					warn(rule, x.Field, x.Value)
				}
				continue
			}
			out[rule] = append(out[rule], x)
		}
	}
	return out
}

func excluded(e *model.Event, exc []Exception) bool {
	for _, x := range exc {
		if !exceptionFields[x.Field] || x.Value == "" {
			continue
		}
		if g := rules.Getter(x.Field); g != nil && g(e) == x.Value {
			return true
		}
	}
	return false
}

func groupKey(keyOf func(*model.Event) string, e *model.Event) string {
	key := ""
	if keyOf != nil {
		key = keyOf(e)
	}
	if key == "" {
		key = firstNonEmpty(e.ActorName, e.Node, e.SrcIP, "-")
	}
	return key
}

type window struct {
	events []*model.Event
	fired  bool
}

func runRule(r *rules.Rule, events []*model.Event, now time.Time) []Detection {
	keyOf := rules.Getter(r.GroupBy())
	th := r.Detection.Threshold
	win := r.Window()
	groups := map[string]*window{}
	var out []Detection

	kind := ""
	if r.UsesThreshold() {
		kind = th.KindResolved()
	}
	var valueOf func(*model.Event) string
	if kind == "distinct" {
		valueOf = rules.Getter(th.Field)
	}

	for _, e := range events {
		if !r.Match(e) {
			continue
		}
		key := groupKey(keyOf, e)
		g := groups[key]
		if g == nil {
			g = &window{}
			groups[key] = g
		}
		t := e.Time()
		cut := t.Add(-win)
		i := 0
		for i < len(g.events) && g.events[i].Time().Before(cut) {
			i++
		}
		if i > 0 {
			g.events = g.events[i:]
			g.fired = false
		}
		g.events = append(g.events, e)

		switch kind {
		case "": // без порога: первое событие в окне заводит сработку, остальные склеиваются
			if !g.fired {
				g.fired = true
				out = append(out, Detection{Rule: r, Key: key, Events: []*model.Event{e}, First: t, Last: t})
			} else {
				appendTo(out, r, key, e, t)
			}
		case "distinct", "count":
			if g.fired {
				appendTo(out, r, key, e, t)
				continue
			}
			if reached(th, g.events, valueOf) {
				g.fired = true
				evs := make([]*model.Event, len(g.events))
				copy(evs, g.events)
				out = append(out, Detection{Rule: r, Key: key, Events: evs, First: evs[0].Time(), Last: t})
			}
		case "periodic":
			if g.fired {
				appendTo(out, r, key, e, t)
				continue
			}
			if ok, reason := periodic(th, g.events); ok {
				g.fired = true
				evs := make([]*model.Event, len(g.events))
				copy(evs, g.events)
				out = append(out, Detection{Rule: r, Key: key, Events: evs, First: evs[0].Time(), Last: t, Reason: reason})
			}
		case "absence":
			// накапливаем; решение — после прохода, относительно now
		}
	}

	if kind == "absence" {
		keys := make([]string, 0, len(groups))
		for k := range groups {
			keys = append(keys, k)
		}
		sort.Strings(keys)
		for _, k := range keys {
			g := groups[k]
			last := g.events[len(g.events)-1]
			silence := now.Sub(last.Time())
			if silence >= win {
				out = append(out, Detection{Rule: r, Key: k, Events: []*model.Event{last}, First: last.Time(), Last: last.Time(),
					Reason: "нет событий " + silence.Truncate(time.Second).String() + " (порог " + win.String() + ")"})
			}
		}
	}
	return out
}

func appendTo(out []Detection, r *rules.Rule, key string, e *model.Event, t time.Time) {
	for j := len(out) - 1; j >= 0; j-- {
		if out[j].Rule == r && out[j].Key == key {
			out[j].Events = append(out[j].Events, e)
			out[j].Last = t
			return
		}
	}
}

func reached(th *rules.Threshold, evs []*model.Event, valueOf func(*model.Event) string) bool {
	if th.Distinct > 0 && valueOf != nil {
		seen := map[string]struct{}{}
		for _, e := range evs {
			if v := valueOf(e); v != "" {
				seen[v] = struct{}{}
			}
		}
		if len(seen) < th.Distinct {
			return false
		}
	}
	if th.Count > 0 && len(evs) < th.Count {
		return false
	}
	return true
}

// periodic: ≥ count событий, интервалы между ними почти одинаковые
// (коэффициент вариации ≤ jitter) и не слишком частые — маячок C2.
func periodic(th *rules.Threshold, evs []*model.Event) (bool, string) {
	if len(evs) < th.Count {
		return false, ""
	}
	tail := evs[len(evs)-th.Count:]
	var ivals []float64
	for i := 1; i < len(tail); i++ {
		ivals = append(ivals, tail[i].Time().Sub(tail[i-1].Time()).Seconds())
	}
	var sum float64
	for _, v := range ivals {
		sum += v
	}
	mean := sum / float64(len(ivals))
	if mean < 10 {
		return false, ""
	}
	var ss float64
	for _, v := range ivals {
		ss += (v - mean) * (v - mean)
	}
	cv := math.Sqrt(ss/float64(len(ivals))) / mean
	jitter := th.Jitter
	if jitter <= 0 {
		jitter = 0.05
	}
	if cv > jitter {
		return false, ""
	}
	return true, "интервал " + (time.Duration(mean) * time.Second).String() + " ± " + formatPct(cv)
}

func formatPct(v float64) string {
	return time.Duration(0).String()[:0] + fmtFloat(v*100) + " %"
}

func fmtFloat(v float64) string {
	i := int(math.Round(v * 10))
	return itoa(i/10) + "." + itoa(i%10)
}

func itoa(i int) string {
	if i == 0 {
		return "0"
	}
	neg := i < 0
	if neg {
		i = -i
	}
	var b []byte
	for i > 0 {
		b = append([]byte{byte('0' + i%10)}, b...)
		i /= 10
	}
	if neg {
		b = append([]byte{'-'}, b...)
	}
	return string(b)
}

func firstNonEmpty(v ...string) string {
	for _, s := range v {
		if s != "" {
			return s
		}
	}
	return ""
}
