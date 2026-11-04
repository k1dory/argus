// Package rules — правила корреляции как файлы в репозитории: Sigma-подобный
// YAML с selection / filter / threshold и блоком analyst для LLM-разбора.
package rules

import (
	"errors"
	"fmt"
	"io/fs"
	"log/slog"
	"net/netip"
	"os"
	"path/filepath"
	"reflect"
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
		// GroupByPrevious — прежний group_by (или threshold.group_by) при его смене:
		// открытый инцидент, заведённый со старым ключом, продолжает первая группа
		// нового ключа, у событий которой старый ключ совпадает (то же правило,
		// субъект и узел). Без поля смена group_by заводит новые инциденты.
		GroupByPrevious string `yaml:"group_by_previous"`
		// GroupByPreviousBefore — для инцидентов без записанного group_by (строки до
		// миграции 0039): по прежнему group_by заведены только те, что созданы раньше
		// этого момента (UTC, «2006-01-02 15:04:05» или RFC 3339) — например, слияния
		// смены group_by. Без поля такие инциденты не подхватываются.
		GroupByPreviousBefore string `yaml:"group_by_previous_before"`
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
	AutoCloseAction string   `yaml:"auto_close_action"`
	Respond         *Respond `yaml:"respond"` // автоответ: block_ip по адресу из событий (режим — у движка)
	File            string   `yaml:"-"`

	selection []matcher
	filter    []matcher
	closeOn   []matcher
	reset     []matcher // detection.reset

	previousBefore time.Time // detection.group_by_previous_before
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
	// BlockCap / BlockCapWindow — не больше стольких новых адресов одной подсети
	// (/24 IPv4, /48 IPv6) правило блокирует за окно (по умолчанию 32 за 1h): скан с
	// сотни адресов соседей не превращается в сотню блокировок. Дополнительно к
	// max_targets на инцидент.
	BlockCap       int    `yaml:"block_cap"`
	BlockCapWindow string `yaml:"block_cap_window"`
}

// Потолок новых блокировок подсети по правилу за окно (respond.block_cap).
const (
	DefaultBlockCap       = 32
	DefaultBlockCapWindow = time.Hour
)

// RespondCap — потолок новых блокировок подсети и его окно с учётом умолчаний.
func (r *Rule) RespondCap() (n int, window time.Duration) {
	n, window = DefaultBlockCap, DefaultBlockCapWindow
	if r.Respond == nil {
		return n, window
	}
	if r.Respond.BlockCap > 0 {
		n = r.Respond.BlockCap
	}
	if d, err := time.ParseDuration(r.Respond.BlockCapWindow); err == nil && d > 0 {
		window = d
	}
	return n, window
}

// CapSubnet — подсеть адреса для потолка блокировок: /24 у IPv4, /48 у IPv6.
// Адрес — канонический (respond.CanonicalIP); не адрес — false.
func CapSubnet(ip string) (string, bool) {
	a, err := netip.ParseAddr(ip)
	if err != nil {
		return "", false
	}
	a = a.WithZone("").Unmap()
	bits := 48
	if a.Is4() {
		bits = 24
	}
	p, err := a.Prefix(bits)
	if err != nil {
		return "", false
	}
	return p.String(), true
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
		// Адрес — в канонической записи (netip, Unmap, без зоны): иначе ::ffff:a.b.c.d
		// и a.b.c.d — два разных адреса в max_targets и два владельца блокировки.
		if a, err := netip.ParseAddr(v); err == nil {
			v = a.WithZone("").Unmap().String()
		}
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

func parseBefore(s string) (time.Time, error) {
	if t, err := time.ParseInLocation("2006-01-02 15:04:05", s, time.UTC); err == nil {
		return t, nil
	}
	return time.Parse(time.RFC3339, s)
}

// GroupByPreviousBefore — граница group_by_previous_before (нулевое время — не задана).
func (r *Rule) GroupByPreviousBefore() time.Time { return r.previousBefore }

// NormGroupBy — group_by без пробелов вокруг полей, для сравнения и записи в инцидент.
func NormGroupBy(gb string) string {
	parts := strings.Split(gb, ",")
	for i := range parts {
		parts[i] = strings.TrimSpace(parts[i])
	}
	return strings.Join(parts, ",")
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
// Load — все правила каталога; любое отвергнутое правило — ошибка (CLI, rules test,
// проверки). Движок грузит через LoadAll: отвергнутое правило не роняет остальные.
func Load(dir string) ([]*Rule, error) {
	out, rejected, err := LoadAll(dir)
	if err != nil {
		return nil, err
	}
	if len(rejected) > 0 {
		errs := make([]error, len(rejected))
		for i := range rejected {
			errs[i] = rejected[i]
		}
		return nil, errors.Join(errs...)
	}
	return out, nil
}

// RuleError — правило, которое не загрузилось: файл (относительно каталога), id
// (если разобрался), код причины без содержимого правила и полная ошибка для журнала.
type RuleError struct {
	File   string
	ID     string
	Reason string // schema_unknown_field | duplicate_id | parse_error | invalid_value (путь поля — только в Err)
	Err    error
}

func (e RuleError) Error() string { return e.File + ": " + e.Err.Error() }
func (e RuleError) Unwrap() error { return e.Err }

// UnknownFieldError — поле внутри структуры детекта, которого эта версия движка не знает.
type UnknownFieldError struct {
	Path string // detection.group_by_next
	Line int    // строка ключа в файле, 0 — не найдена (алиас, merge)
}

func (e *UnknownFieldError) Error() string {
	at := ""
	if e.Line > 0 {
		at = fmt.Sprintf("line %d: ", e.Line)
	}
	return at + "поле " + e.Path + " неизвестно этой версии движка — правило не применено (обновите движок или уберите поле)"
}

// reasonOf — короткий код причины отказа, без имён полей и значений из правила.
func reasonOf(err error) string {
	var uf *UnknownFieldError
	var te *yaml.TypeError
	switch {
	case errors.As(err, &uf):
		return "schema_unknown_field"
	case errors.As(err, &te), strings.HasPrefix(err.Error(), "yaml:"):
		return "parse_error"
	}
	return "invalid_value"
}

// LoadAll — правила каталога по одному: отвергнутые (ошибка разбора, неизвестное
// поле детекта, неверное значение, повтор id) — в rejected, остальные загружаются.
// err — только если каталог не прочитан.
func LoadAll(dir string) (out []*Rule, rejected []RuleError, err error) {
	out, rejected, err = LoadEach(dir)
	if err != nil {
		return nil, nil, err
	}
	out, dup := DedupeIDs(out, nil)
	return out, append(rejected, dup...), nil
}

// LoadEach — как LoadAll, но без проверки повторов id: её делает вызывающий,
// зная прежний набор (перечитывание движка, DedupeIDs с активными файлами).
func LoadEach(dir string) (out []*Rule, rejected []RuleError, err error) {
	paths, err := Files(dir)
	if err != nil {
		return nil, nil, err
	}
	for _, p := range paths {
		rel, err := filepath.Rel(dir, p)
		if err != nil {
			rel = filepath.Base(p)
		}
		rel = filepath.ToSlash(rel)
		r, err := LoadFile(p)
		if err != nil {
			rejected = append(rejected, RuleError{File: rel, ID: idOf(p), Reason: reasonOf(err), Err: err})
			continue
		}
		r.File = rel
		out = append(out, r)
	}
	return out, rejected, nil
}

// DedupeIDs — у каждого id одно правило: политика (respond, analyst, уровень) ищется
// по id, и второй файл с тем же id молча подменил бы первый. Остаётся правило из того
// файла, что был активен с этим id (activeFile: id → файл прежнего набора); если такого
// нет (старт, оба файла новые) — файл, первый по пути в лексикографическом порядке.
// Остальные отвергаются (duplicate_id): подброшенный zz-*.yml с id штатного правила
// не выключает его.
func DedupeIDs(rs []*Rule, activeFile map[string]string) (kept []*Rule, rejected []RuleError) {
	byID := map[string][]*Rule{}
	for _, r := range rs {
		byID[r.ID] = append(byID[r.ID], r)
	}
	for _, r := range rs {
		same := byID[r.ID]
		if len(same) == 1 {
			kept = append(kept, r)
			continue
		}
		winner := ""
		if f, ok := activeFile[r.ID]; ok {
			for _, o := range same {
				if o.File == f {
					winner = f
				}
			}
		}
		if winner == "" {
			winner = same[0].File
			for _, o := range same[1:] {
				if o.File < winner {
					winner = o.File
				}
			}
		}
		if r.File == winner {
			kept = append(kept, r)
			continue
		}
		files := make([]string, 0, len(same))
		for _, o := range same {
			files = append(files, o.File)
		}
		rejected = append(rejected, RuleError{File: r.File, ID: r.ID, Reason: "duplicate_id",
			Err: fmt.Errorf("id %s повторяется в %s — действует %s, это правило не применено", r.ID, strings.Join(files, ", "), winner)})
	}
	return kept, rejected
}

// idOf — id отвергнутого правила, если файл хотя бы разбирается (для события отказа).
func idOf(path string) string {
	raw, err := os.ReadFile(path)
	if err != nil {
		return ""
	}
	var m map[string]any
	if yaml.Unmarshal(raw, &m) != nil {
		return ""
	}
	id, _ := m["id"].(string)
	return id
}

// metaFields — метаданные правила (в том числе из Sigma): на детект не влияют и
// разрешены без предупреждения.
var metaFields = map[string]bool{
	"description": true, "author": true, "references": true, "status": true, "date": true,
	"modified": true, "falsepositives": true, "license": true, "fields": true, "related": true,
	"notes": true, "comment": true, "owner": true, "version": true,
}

// checkFields — схема полей правила по yaml-тегам структуры, на развёрнутом дереве:
// алиасы и merge («<<») уже применены декодером, поэтому проверяется ровно то, что
// попадёт в правило. Неизвестное поле внутри структур детекта (detection, threshold,
// respond, analyst) — ошибка этого правила: движок, который поле не знает
// (group_by_previous до своего релиза), не применит правило частично — новый
// group_by без миграции завёл бы второй открытый инцидент (argus1, INC-5312/INC-5370).
// Неизвестное поле верхнего уровня — предупреждение (метаданные из metaFields — без него).
func checkFields(raw []byte) (warn []string, err error) {
	var tree map[string]any
	if err := yaml.Unmarshal(raw, &tree); err != nil {
		return nil, err
	}
	var doc yaml.Node
	_ = yaml.Unmarshal(raw, &doc) // только для номеров строк в сообщениях
	top := yamlFields(reflect.TypeOf(Rule{}))
	keys := make([]string, 0, len(tree))
	for k := range tree {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	for _, k := range keys {
		t, ok := top[k]
		if !ok {
			if !metaFields[k] {
				warn = append(warn, fmt.Sprintf("line %d: поле %s неизвестно движку — пропущено", keyLine(&doc, k), k))
			}
			continue
		}
		if err := strictStruct(tree[k], t, k, &doc); err != nil {
			return warn, err
		}
	}
	return warn, nil
}

// strictStruct — у вложенной структуры (не map) все поля известны.
func strictStruct(v any, t reflect.Type, path string, doc *yaml.Node) error {
	for t.Kind() == reflect.Pointer {
		t = t.Elem()
	}
	if t.Kind() != reflect.Struct {
		return nil
	}
	if mm, ok := v.(map[any]any); ok {
		// Отображение с нестроковым ключом (7: …): декодер разложит его в структуру,
		// молча пропустив и такие ключи, и неизвестные строковые — отказ правила.
		for k := range mm {
			if _, str := k.(string); !str {
				return &UnknownFieldError{Path: fmt.Sprintf("%s.%v", path, k), Line: keyLine(doc, fmt.Sprint(k))}
			}
		}
		conv := make(map[string]any, len(mm))
		for k, x := range mm {
			conv[k.(string)] = x
		}
		v = conv
	}
	m, ok := v.(map[string]any)
	if !ok {
		return nil // не отображение: тип проверит декодер
	}
	fields := yamlFields(t)
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	for _, k := range keys {
		ft, ok := fields[k]
		if !ok {
			return &UnknownFieldError{Path: path + "." + k, Line: keyLine(doc, k)}
		}
		if err := strictStruct(m[k], ft, path+"."+k, doc); err != nil {
			return err
		}
	}
	return nil
}

// keyLine — строка первого ключа с таким именем в файле (0 — нет): только для сообщения.
func keyLine(n *yaml.Node, key string) int {
	if n == nil {
		return 0
	}
	if n.Kind == yaml.MappingNode {
		for i := 0; i+1 < len(n.Content); i += 2 {
			if n.Content[i].Value == key {
				return n.Content[i].Line
			}
		}
	}
	for _, c := range n.Content {
		if l := keyLine(c, key); l > 0 {
			return l
		}
	}
	return 0
}

func yamlFields(t reflect.Type) map[string]reflect.Type {
	out := map[string]reflect.Type{}
	for i := 0; i < t.NumField(); i++ {
		f := t.Field(i)
		name, _, _ := strings.Cut(f.Tag.Get("yaml"), ",")
		if name == "" || name == "-" {
			continue
		}
		out[name] = f.Type
	}
	return out
}

func LoadFile(path string) (*Rule, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	warn, err := checkFields(raw)
	if err != nil {
		return nil, err
	}
	for _, w := range warn {
		slog.Warn("rules: "+w, "file", path)
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
		if r.Respond.BlockCap < 0 {
			return nil, fmt.Errorf("respond.block_cap: %d, ожидалось ≥ 0", r.Respond.BlockCap)
		}
		if w := r.Respond.BlockCapWindow; w != "" {
			if d, err := time.ParseDuration(w); err != nil || d <= 0 {
				return nil, fmt.Errorf("respond.block_cap_window: %q", w)
			}
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
	if prev := strings.TrimSpace(r.Detection.GroupByPrevious); prev != "" {
		if Getter(prev) == nil {
			return nil, fmt.Errorf("group_by_previous: неизвестное поле %q", prev)
		}
		if NormGroupBy(prev) == NormGroupBy(r.GroupBy()) {
			return nil, fmt.Errorf("group_by_previous совпадает с group_by %q — миграции ключа нет, поле лишнее", r.GroupBy())
		}
	}
	if b := strings.TrimSpace(r.Detection.GroupByPreviousBefore); b != "" {
		if strings.TrimSpace(r.Detection.GroupByPrevious) == "" {
			return nil, fmt.Errorf("group_by_previous_before без group_by_previous")
		}
		t, err := parseBefore(b)
		if err != nil {
			return nil, fmt.Errorf("group_by_previous_before %q: ожидается «2006-01-02 15:04:05» (UTC) или RFC 3339", b)
		}
		r.previousBefore = t
	}
	for _, f := range r.CloseMatch {
		if Getter(f) == nil {
			return nil, fmt.Errorf("close_match: неизвестное поле %q", f)
		}
	}
	if len(r.CloseMatch) > 0 && len(r.CloseOn) == 0 {
		return nil, fmt.Errorf("close_match без close_on")
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
// Sigma-модификаторы field|contains, свой field|internal (адрес из INTERNAL_NETS)
// и операторы в строке: '> 90', 'regex x'.
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
	case "internal":
		// field|internal: true — адрес из своих сетей (INTERNAL_NETS, как у коллектора для
		// attrs.scope), false — не из своих. Сравнение по netip: регистр, сокращение IPv6 и
		// IPv4-mapped запись не важны; не адрес — не свой.
		want, err := strconv.ParseBool(v)
		if err != nil {
			return nil, fmt.Errorf("internal: ожидалось true или false, получено %q", v)
		}
		nets, err := internalNets()
		if err != nil {
			return nil, err
		}
		return func(s string) bool { return isInternal(nets, s) == want }, nil
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

// defaultInternalNets — свои сети при пустом INTERNAL_NETS; тот же список, что у коллектора.
var defaultInternalNets = []string{"10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16", "100.64.0.0/10", "127.0.0.0/8", "169.254.0.0/16", "fc00::/7", "fe80::/10", "::1/128"}

// internalNets — INTERNAL_NETS на момент загрузки правила; непустой список заменяет умолчания.
func internalNets() ([]netip.Prefix, error) {
	var list []string
	for _, c := range strings.Split(os.Getenv("INTERNAL_NETS"), ",") {
		if c = strings.TrimSpace(c); c != "" {
			list = append(list, c)
		}
	}
	if len(list) == 0 {
		list = defaultInternalNets
	}
	out := make([]netip.Prefix, 0, len(list))
	for _, c := range list {
		p, err := netip.ParsePrefix(c)
		if err != nil {
			return nil, fmt.Errorf("INTERNAL_NETS: %w", err)
		}
		// ::ffff:192.0.2.0/120 — та же сеть, что 192.0.2.0/24: адрес события сравнивается
		// после Unmap, префикс приводим так же. Короче /96 в IPv4 не переводится.
		if p.Addr().Is4In6() {
			if p.Bits() < 96 {
				return nil, fmt.Errorf("INTERNAL_NETS: %s — IPv4-mapped короче /96", c)
			}
			p = netip.PrefixFrom(p.Addr().Unmap(), p.Bits()-96)
		}
		out = append(out, p)
	}
	return out, nil
}

func isInternal(nets []netip.Prefix, s string) bool {
	a, err := netip.ParseAddr(strings.TrimSpace(s))
	if err != nil {
		return false
	}
	// Зона интерфейса (fe80::42%eth0) — не часть адреса: Prefix.Contains её отвергает.
	a = a.WithZone("").Unmap()
	for _, p := range nets {
		if p.Contains(a) {
			return true
		}
	}
	return false
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
