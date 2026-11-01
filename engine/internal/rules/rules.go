// Package rules — правила корреляции как файлы в репозитории: Sigma-подобный
// YAML с selection / filter / threshold и блоком analyst для LLM-разбора.
package rules

import (
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"

	"gopkg.in/yaml.v3"

	"github.com/devitex-soft/argus/engine/internal/model"
)

type Threshold struct {
	Kind     string  `yaml:"kind"`     // distinct | count | consecutive | absence | periodic (по умолчанию из полей)
	Field    string  `yaml:"field"`    // distinct по этому полю
	Distinct int     `yaml:"distinct"` // сколько разных значений
	Count    int     `yaml:"count"`    // или просто N событий; consecutive — N подряд без события detection.reset между ними
	Window   string  `yaml:"window"`   // 6m, 1h
	GroupBy  string  `yaml:"group_by"` // по умолчанию actor.name
	Jitter   float64 `yaml:"jitter"`   // periodic: допустимый коэффициент вариации интервалов (0.05 = 5 %)
}

// KindResolved — вид порога с учётом умолчаний.
func (t *Threshold) KindResolved() string {
	switch {
	case t.Kind != "":
		return t.Kind
	case t.Distinct > 0:
		return "distinct"
	default:
		return "count"
	}
}

type Analyst struct {
	Profile string   `yaml:"profile"`
	Redact  []string `yaml:"redact"`
}

type Rule struct {
	Title     string   `yaml:"title"`
	ID        string   `yaml:"id"`
	Level     string   `yaml:"level"` // low | medium | high | critical
	Tags      []string `yaml:"tags"`
	Detection struct {
		Selection map[string]any `yaml:"selection"`
		Filter    map[string]any `yaml:"filter"`
		Threshold *Threshold     `yaml:"threshold"`
		Condition string         `yaml:"condition"`
		// Reset — событие группы, обрывающее серию threshold.kind: consecutive
		// (нормальный замер между нарушениями). Такие события движок держит в
		// буфере наравне с selection и close_on.
		Reset map[string]any `yaml:"reset"`
		// GroupBy — ключ склейки правила без порога (у порога — threshold.group_by),
		// по умолчанию actor.name. Составной ключ — поля через запятую: «node, object».
		GroupBy string `yaml:"group_by"`
	} `yaml:"detection"`
	Enrich    []any          `yaml:"enrich"` // edr.process_tree: 120s | ngfw.sessions: 120s | cmdb.owner
	Analyst   Analyst        `yaml:"analyst"`
	Dedupe    string         `yaml:"dedupe"`     // окно склейки без threshold, по умолчанию 10m
	AutoClose string         `yaml:"auto_close"` // закрыть автоматикой, если новых событий нет столько времени
	CloseOn   map[string]any `yaml:"close_on"`   // событие того же субъекта, закрывающее инцидент (ротация токена и т.п.)
	// CloseMatch — поля, которые у события close_on должны совпасть с
	// событиями инцидента (непусто, без учёта регистра): они только находят
	// инцидент (тот же секрет в том же проекте). Закрывает его лишь успешный
	// отзыв доказанно того же токена (incidents.CloseMatched: token_id,
	// провайдер, экземпляр, аудит), иначе — эскалация с «нужна проверка».
	// Пусто — по ключу группы.
	CloseMatch []string `yaml:"close_match"`
	// AutoCloseAction — что делать по истечении auto_close: close (по
	// умолчанию) или escalate — тишина не доказывает устранение (утечка
	// секрета остаётся открытой и уходит дежурному).
	AutoCloseAction string    `yaml:"auto_close_action"`
	Respond         *Respond  `yaml:"respond"`  // автоответ: block_ip по адресу из событий (режим — у движка)
	Collapse        *Collapse `yaml:"collapse"` // склейка сработок по подсети источника (collapse.go)
	File            string    `yaml:"-"`

	selection []matcher
	filter    []matcher
	closeOn   []matcher
	reset     []matcher // detection.reset
}

// Respond — что делать автоматически при создании инцидента этим правилом.
// Реальное действие зависит от режима движка: ids — ничего, simulate — журнал,
// ips — блокировка на TTL. Адреса из allowlist не блокируются никогда.
type Respond struct {
	Action     string `yaml:"action"`      // block_ip
	Target     string `yaml:"target"`      // поле события с адресом: src.ip (по умолчанию) | dst.ip | actor.name | attrs.<ключ>
	MinLevel   string `yaml:"min_level"`   // блокировать, если уровень инцидента не ниже (по умолчанию high)
	TTL        string `yaml:"ttl"`         // срок блокировки, по умолчанию из конфига движка
	MaxTargets int    `yaml:"max_targets"` // не больше адресов на инцидент (по умолчанию 3): threshold distinct по адресам иначе заблокирует всех
	// MinEvents — блокировать, только когда в инциденте накопилось не меньше
	// событий (по умолчанию 1). Для правил без threshold это защита от одного
	// подделанного события: инцидент заводится сразу, блок — со второго.
	MinEvents int `yaml:"min_events"`
}

// RespondMinEvents — порог событий для автоблокировки с учётом умолчания.
func (r *Rule) RespondMinEvents() int {
	if r.Respond == nil || r.Respond.MinEvents < 1 {
		return 1
	}
	return r.Respond.MinEvents
}

// respondTargetOK — поля, из которых разрешено брать адрес для блокировки.
func respondTargetOK(field string) bool {
	switch field {
	case "", "src.ip", "source.ip", "dst.ip", "target.ip", "actor.name", "actor":
		return true
	}
	return strings.HasPrefix(field, "attrs.")
}

var levelRank = map[string]int{"low": 0, "medium": 1, "high": 2, "critical": 3}

// LevelRank — порядок уровней для сравнений (неизвестный = low).
func LevelRank(level string) int { return levelRank[strings.ToLower(level)] }

// RespondTargets — адреса из событий сработки по полю respond.target (без дублей,
// в порядке появления), не больше max_targets; truncated — сколько отброшено.
func (r *Rule) RespondTargets(events []*model.Event) (targets []string, truncated int) {
	if r.Respond == nil {
		return nil, 0
	}
	get := Getter(strings.TrimSpace(r.Respond.Target))
	if get == nil {
		get = Getter("src.ip")
	}
	limit := r.Respond.MaxTargets
	if limit <= 0 {
		limit = 3
	}
	seen := map[string]bool{}
	for _, e := range events {
		v := strings.TrimSpace(get(e))
		if v == "" || seen[v] {
			continue
		}
		seen[v] = true
		if len(targets) < limit {
			targets = append(targets, v)
		} else {
			truncated++
		}
	}
	return targets, truncated
}

// AutoCloseAfter — 0, если авто-закрытие не задано.
func (r *Rule) AutoCloseAfter() time.Duration {
	d, err := time.ParseDuration(r.AutoClose)
	if err != nil || d <= 0 {
		return 0
	}
	return d
}

// AutoCloseEscalates — по тишине эскалировать, а не закрывать.
func (r *Rule) AutoCloseEscalates() bool { return r.AutoCloseAction == "escalate" }

// CloseMatchKey — значения полей close_match события через \x00; ok=false,
// если правило их не задаёт или хотя бы одно пусто (сопоставить нельзя).
func (r *Rule) CloseMatchKey(e *model.Event) (key string, ok bool) {
	if len(r.CloseMatch) == 0 {
		return "", false
	}
	parts := make([]string, 0, len(r.CloseMatch))
	for _, f := range r.CloseMatch {
		v := strings.ToLower(strings.TrimSpace(Getter(f)(e)))
		if v == "" {
			return "", false
		}
		parts = append(parts, v)
	}
	return strings.Join(parts, "\x00"), true
}

// UsesReset — у правила есть detection.reset (серия consecutive обрывается).
func (r *Rule) UsesReset() bool { return len(r.reset) > 0 }

// MatchReset — событие обрывает серию consecutive своей группы.
func (r *Rule) MatchReset(e *model.Event) bool {
	if len(r.reset) == 0 {
		return false
	}
	for _, m := range r.reset {
		if !m(e) {
			return false
		}
	}
	return true
}

// MatchClose — событие закрывает открытый инцидент этого правила.
func (r *Rule) MatchClose(e *model.Event) bool {
	if len(r.closeOn) == 0 {
		return false
	}
	for _, m := range r.closeOn {
		if !m(e) {
			return false
		}
	}
	return true
}

func (r *Rule) Window() time.Duration {
	if r.Detection.Threshold != nil {
		if d, err := time.ParseDuration(r.Detection.Threshold.Window); err == nil {
			return d
		}
		return 15 * time.Minute
	}
	if d, err := time.ParseDuration(r.Dedupe); err == nil {
		return d
	}
	return 10 * time.Minute
}

func (r *Rule) GroupBy() string {
	if r.Detection.Threshold != nil && r.Detection.Threshold.GroupBy != "" {
		return r.Detection.Threshold.GroupBy
	}
	if r.Detection.GroupBy != "" {
		return r.Detection.GroupBy
	}
	return "actor.name"
}

// IsAbsence — правило «молчание группы дольше window».
func (r *Rule) IsAbsence() bool {
	return r.UsesThreshold() && r.Detection.Threshold.KindResolved() == "absence"
}

func (r *Rule) UsesThreshold() bool {
	return r.Detection.Threshold != nil && strings.Contains(r.Detection.Condition, "threshold")
}

func (r *Rule) UsesFilter() bool {
	return len(r.Detection.Filter) > 0 && strings.Contains(r.Detection.Condition, "not filter")
}

// Match — событие проходит selection (и не попадает под filter).
func (r *Rule) Match(e *model.Event) bool {
	for _, m := range r.selection {
		if !m(e) {
			return false
		}
	}
	if r.UsesFilter() {
		all := true
		for _, m := range r.filter {
			if !m(e) {
				all = false
				break
			}
		}
		if all {
			return false
		}
	}
	return true
}

// TestsDir — подкаталог с тестами правил (rules/tests/*.yml): это не правила,
// Load его пропускает.
const TestsDir = "tests"

// Files — пути всех файлов правил в каталоге и его подкаталогах (кроме
// tests/), отсортированные. Подкаталоги группируют правила по источнику или
// назначению (wazuh/, ops/); на смысл правила путь не влияет.
func Files(dir string) ([]string, error) {
	var paths []string
	err := filepath.WalkDir(dir, func(p string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			if p != dir && d.Name() == TestsDir {
				return filepath.SkipDir
			}
			return nil
		}
		if ext := filepath.Ext(d.Name()); ext == ".yml" || ext == ".yaml" {
			paths = append(paths, p)
		}
		return nil
	})
	if err != nil {
		return nil, err
	}
	sort.Strings(paths)
	return paths, nil
}

// Load читает все правила каталога (рекурсивно, без tests/), компилирует
// матчеры. Rule.File — путь относительно каталога (wazuh/ssh-bruteforce.yml).
func Load(dir string) ([]*Rule, error) {
	paths, err := Files(dir)
	if err != nil {
		return nil, err
	}
	var out []*Rule
	for _, p := range paths {
		rel, err := filepath.Rel(dir, p)
		if err != nil {
			rel = filepath.Base(p)
		}
		rel = filepath.ToSlash(rel)
		r, err := LoadFile(p)
		if err != nil {
			return nil, fmt.Errorf("%s: %w", rel, err)
		}
		r.File = rel
		out = append(out, r)
	}
	if err := checkCollapseGroups(out); err != nil {
		return nil, err
	}
	return out, nil
}

func LoadFile(path string) (*Rule, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var r Rule
	if err := yaml.Unmarshal(raw, &r); err != nil {
		return nil, err
	}
	if r.Respond != nil {
		if r.Respond.Action != "block_ip" {
			return nil, fmt.Errorf("respond.action: поддерживается только block_ip, получено %q", r.Respond.Action)
		}
		if t := strings.TrimSpace(r.Respond.Target); !respondTargetOK(t) || (t != "" && Getter(t) == nil) {
			return nil, fmt.Errorf("respond.target: допустимы src.ip, dst.ip, actor.name, attrs.<ключ>; получено %q", t)
		}
		if ml := strings.ToLower(r.Respond.MinLevel); ml != "" {
			if _, ok := levelRank[ml]; !ok {
				return nil, fmt.Errorf("respond.min_level: %q", r.Respond.MinLevel)
			}
		}
		if r.Respond.TTL != "" {
			if _, err := time.ParseDuration(r.Respond.TTL); err != nil {
				return nil, fmt.Errorf("respond.ttl: %w", err)
			}
		}
		if r.Respond.MinEvents < 0 {
			return nil, fmt.Errorf("respond.min_events: %d, ожидалось ≥ 0", r.Respond.MinEvents)
		}
		if r.Respond.MaxTargets < 0 {
			return nil, fmt.Errorf("respond.max_targets: %d, ожидалось ≥ 0", r.Respond.MaxTargets)
		}
	}
	r.File = filepath.Base(path)
	if r.ID == "" || r.Title == "" {
		return nil, fmt.Errorf("нужны id и title")
	}
	if len(r.Detection.Selection) == 0 {
		return nil, fmt.Errorf("пустой detection.selection")
	}
	if r.Detection.Condition == "" {
		r.Detection.Condition = "selection"
	}
	if r.UsesThreshold() {
		t := r.Detection.Threshold
		switch t.KindResolved() {
		case "distinct":
			if t.Field == "" || t.Distinct == 0 {
				return nil, fmt.Errorf("threshold.distinct требует field и distinct > 0")
			}
		case "count":
			if t.Count == 0 {
				return nil, fmt.Errorf("threshold: нужен count, distinct, consecutive, absence или periodic")
			}
		case "consecutive":
			if t.Count < 2 {
				return nil, fmt.Errorf("threshold consecutive: count ≥ 2")
			}
			if len(r.Detection.Reset) == 0 {
				return nil, fmt.Errorf("threshold consecutive требует detection.reset — событие, обрывающее серию")
			}
		case "absence":
			// молчание группы дольше window после активности
		case "periodic":
			if t.Count < 4 {
				return nil, fmt.Errorf("threshold periodic: count ≥ 4 (минимум три интервала)")
			}
			if t.Jitter <= 0 {
				t.Jitter = 0.05
			}
		default:
			return nil, fmt.Errorf("threshold.kind %q неизвестен", t.Kind)
		}
		if _, err := time.ParseDuration(t.Window); err != nil {
			return nil, fmt.Errorf("threshold.window: %w", err)
		}
	}
	if r.AutoClose != "" {
		if _, err := time.ParseDuration(r.AutoClose); err != nil {
			return nil, fmt.Errorf("auto_close: %w", err)
		}
	}
	switch r.AutoCloseAction {
	case "", "close", "escalate":
	default:
		return nil, fmt.Errorf("auto_close_action %q: ожидается close или escalate", r.AutoCloseAction)
	}
	if gb := r.GroupBy(); Getter(gb) == nil {
		return nil, fmt.Errorf("group_by: неизвестное поле %q", gb)
	}
	for _, f := range r.CloseMatch {
		if Getter(f) == nil {
			return nil, fmt.Errorf("close_match: неизвестное поле %q", f)
		}
	}
	if len(r.CloseMatch) > 0 && len(r.CloseOn) == 0 {
		return nil, fmt.Errorf("close_match без close_on")
	}
	if err := r.validateCollapse(); err != nil {
		return nil, err
	}
	if r.selection, err = compile(r.Detection.Selection); err != nil {
		return nil, err
	}
	if r.filter, err = compile(r.Detection.Filter); err != nil {
		return nil, err
	}
	if r.closeOn, err = compile(r.CloseOn); err != nil {
		return nil, fmt.Errorf("close_on: %w", err)
	}
	if r.reset, err = compile(r.Detection.Reset); err != nil {
		return nil, fmt.Errorf("detection.reset: %w", err)
	}
	return &r, nil
}

type matcher func(*model.Event) bool

// compile превращает карту field → значение в матчеры. Поддерживаются
// Sigma-модификаторы field|contains и операторы в строке: '> 90', 'regex x'.
func compile(m map[string]any) ([]matcher, error) {
	var out []matcher
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	for _, k := range keys {
		field, mod := k, "eq"
		if i := strings.IndexByte(k, '|'); i > 0 {
			field, mod = k[:i], k[i+1:]
		}
		get := Getter(field)
		if get == nil {
			return nil, fmt.Errorf("неизвестное поле %q", field)
		}
		values := asList(m[k])
		if len(values) == 0 {
			return nil, fmt.Errorf("пустое значение для %q", field)
		}
		var alts []func(string) bool
		for _, v := range values {
			f, err := valueMatcher(mod, v)
			if err != nil {
				return nil, fmt.Errorf("%s: %w", k, err)
			}
			alts = append(alts, f)
		}
		out = append(out, func(e *model.Event) bool {
			got := get(e)
			for _, f := range alts {
				if f(got) {
					return true
				}
			}
			return false
		})
	}
	return out, nil
}

var opRe = regexp.MustCompile(`^(>=|<=|>|<|!=|contains|startswith|endswith|regex|not)\s+(.+)$`)

func valueMatcher(mod, v string) (func(string) bool, error) {
	if mod == "eq" {
		if m := opRe.FindStringSubmatch(v); m != nil {
			mod, v = m[1], m[2]
		}
	}
	lv := strings.ToLower(v)
	switch mod {
	case "eq":
		return func(s string) bool { return strings.EqualFold(s, v) }, nil
	case "!=", "not":
		return func(s string) bool { return !strings.EqualFold(s, v) }, nil
	case "contains":
		return func(s string) bool { return strings.Contains(strings.ToLower(s), lv) }, nil
	case "startswith":
		return func(s string) bool { return strings.HasPrefix(strings.ToLower(s), lv) }, nil
	case "endswith":
		return func(s string) bool { return strings.HasSuffix(strings.ToLower(s), lv) }, nil
	case "regex", "re":
		re, err := regexp.Compile(v)
		if err != nil {
			return nil, err
		}
		return re.MatchString, nil
	case ">", "<", ">=", "<=", "gt", "lt", "gte", "lte":
		n, err := strconv.ParseFloat(v, 64)
		if err != nil {
			return nil, fmt.Errorf("число ожидалось после %s", mod)
		}
		return func(s string) bool {
			x, err := strconv.ParseFloat(s, 64)
			if err != nil {
				return false
			}
			switch mod {
			case ">", "gt":
				return x > n
			case "<", "lt":
				return x < n
			case ">=", "gte":
				return x >= n
			default:
				return x <= n
			}
		}, nil
	}
	return nil, fmt.Errorf("неизвестный модификатор %q", mod)
}

func asList(v any) []string {
	switch x := v.(type) {
	case nil:
		return nil
	case []any:
		out := make([]string, 0, len(x))
		for _, i := range x {
			out = append(out, fmt.Sprint(i))
		}
		return out
	default:
		return []string{fmt.Sprint(x)}
	}
}

// Getter — доступ к полю события по имени из правила.
func Getter(field string) func(*model.Event) string {
	if strings.Contains(field, ",") {
		// Составной ключ: значения полей через «|»; пустой, только если пусты все поля
		// (тогда groupKey подставит субъект, узел или адрес, как для одного поля).
		var parts []func(*model.Event) string
		for _, f := range strings.Split(field, ",") {
			g := Getter(strings.TrimSpace(f))
			if g == nil {
				return nil
			}
			parts = append(parts, g)
		}
		return func(e *model.Event) string {
			vals, empty := make([]string, len(parts)), true
			for i, g := range parts {
				vals[i] = g(e)
				empty = empty && vals[i] == ""
			}
			if empty {
				return ""
			}
			return strings.Join(vals, "|")
		}
	}
	switch field {
	case "event.action", "action":
		return func(e *model.Event) string { return e.Action }
	case "event.outcome", "outcome":
		return func(e *model.Event) string { return e.Outcome }
	case "event.severity", "severity":
		return func(e *model.Event) string { return strconv.Itoa(int(e.Severity)) }
	case "source":
		return func(e *model.Event) string { return e.Source }
	case "source.class", "source_class":
		return func(e *model.Event) string { return e.SourceClass }
	case "vendor":
		return func(e *model.Event) string { return e.Vendor }
	case "product":
		return func(e *model.Event) string { return e.Product }
	case "actor.name", "actor":
		return func(e *model.Event) string { return e.ActorName }
	case "actor.kind":
		return func(e *model.Event) string { return e.ActorKind }
	case "object", "target.object":
		return func(e *model.Event) string { return e.Object }
	case "node", "target.host", "host":
		return func(e *model.Event) string { return e.Node }
	case "session", "session.id":
		return func(e *model.Event) string { return e.SessionID }
	case "src.ip", "source.ip":
		return func(e *model.Event) string { return e.SrcIP }
	case "src.port":
		return func(e *model.Event) string { return strconv.Itoa(int(e.SrcPort)) }
	case "dst.ip", "target.ip":
		return func(e *model.Event) string { return e.DstIP }
	case "dst.port", "target.port":
		return func(e *model.Event) string { return strconv.Itoa(int(e.DstPort)) }
	case "proto":
		return func(e *model.Event) string { return e.Proto }
	case "bytes":
		return func(e *model.Event) string { return strconv.FormatUint(e.Bytes, 10) }
	case "packets":
		return func(e *model.Event) string { return strconv.FormatUint(e.Packets, 10) }
	case "value":
		return func(e *model.Event) string { return strconv.FormatFloat(e.Value, 'g', -1, 64) }
	case "unit":
		return func(e *model.Event) string { return e.Unit }
	case "pii":
		return func(e *model.Event) string { return strconv.Itoa(int(e.PII)) }
	}
	if strings.HasPrefix(field, "attrs.") {
		key := field[len("attrs."):]
		return func(e *model.Event) string { return e.Attrs[key] }
	}
	return nil
}
