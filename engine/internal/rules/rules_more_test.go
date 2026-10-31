package rules

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/devitex-soft/argus/engine/internal/model"
)

// base — минимальное валидное правило, к которому тесты дописывают блоки.
const base = "title: x\nid: y\nlevel: high\ndetection:\n  selection: {node: a}\n"

// mustFail — файл правила не загружается, ошибка содержит фрагмент.
func mustFail(t *testing.T, name, yml, want string) {
	t.Helper()
	p := filepath.Join(t.TempDir(), "r.yml")
	_ = os.WriteFile(p, []byte(yml), 0o600)
	_, err := LoadFile(p)
	if err == nil {
		t.Errorf("%s: ожидалась ошибка загрузки", name)
		return
	}
	if want != "" && !strings.Contains(err.Error(), want) {
		t.Errorf("%s: ошибка %q не содержит %q", name, err, want)
	}
}

func TestLevelRank(t *testing.T) {
	for in, want := range map[string]int{"low": 0, "medium": 1, "HIGH": 2, "Critical": 3, "": 0, "nosuch": 0} {
		if got := LevelRank(in); got != want {
			t.Errorf("LevelRank(%q) = %d, want %d", in, got, want)
		}
	}
}

func TestKindResolved(t *testing.T) {
	for name, tc := range map[string]struct {
		th   Threshold
		want string
	}{
		"явный kind":    {Threshold{Kind: "absence", Distinct: 5}, "absence"},
		"distinct > 0":  {Threshold{Distinct: 3}, "distinct"},
		"по умолчанию":  {Threshold{Count: 2}, "count"},
		"пустой порог":  {Threshold{}, "count"},
		"kind periodic": {Threshold{Kind: "periodic"}, "periodic"},
		"kind с count":  {Threshold{Kind: "consecutive", Count: 3}, "consecutive"},
	} {
		if got := tc.th.KindResolved(); got != tc.want {
			t.Errorf("%s: %q, want %q", name, got, tc.want)
		}
	}
}

func TestRespondTargets(t *testing.T) {
	events := []*model.Event{
		{SrcIP: "203.0.113.1", DstIP: "10.0.0.1", ActorName: "root", Attrs: map[string]string{"peer": "198.51.100.7"}},
		{SrcIP: " 203.0.113.1 ", DstIP: "10.0.0.2", ActorName: "", Attrs: map[string]string{"peer": ""}},
		{SrcIP: "", DstIP: "10.0.0.3", ActorName: "bob"},
		{SrcIP: "203.0.113.2", DstIP: "10.0.0.4", ActorName: "carol"},
		{SrcIP: "203.0.113.3", DstIP: "10.0.0.5", ActorName: "dave"},
		{SrcIP: "203.0.113.4", DstIP: "10.0.0.6", ActorName: "erin"},
	}
	t.Run("без respond — ничего", func(t *testing.T) {
		r := load(t, base)
		if got, tr := r.RespondTargets(events); got != nil || tr != 0 {
			t.Fatalf("%v %d", got, tr)
		}
	})
	t.Run("умолчание src.ip, дубли и пустые пропущены, лимит 3", func(t *testing.T) {
		r := load(t, base+"respond: {action: block_ip}\n")
		got, tr := r.RespondTargets(events)
		if strings.Join(got, ",") != "203.0.113.1,203.0.113.2,203.0.113.3" || tr != 1 {
			t.Fatalf("%v усечено %d", got, tr)
		}
	})
	t.Run("max_targets и dst.ip", func(t *testing.T) {
		r := load(t, base+"respond: {action: block_ip, target: dst.ip, max_targets: 2}\n")
		got, tr := r.RespondTargets(events)
		if strings.Join(got, ",") != "10.0.0.1,10.0.0.2" || tr != 4 {
			t.Fatalf("%v усечено %d", got, tr)
		}
	})
	t.Run("actor.name без лимита по умолчанию 3", func(t *testing.T) {
		r := load(t, base+"respond: {action: block_ip, target: actor.name, max_targets: 0}\n")
		got, tr := r.RespondTargets(events)
		if strings.Join(got, ",") != "root,bob,carol" || tr != 2 {
			t.Fatalf("%v усечено %d", got, tr)
		}
	})
	t.Run("attrs.<ключ>", func(t *testing.T) {
		r := load(t, base+"respond: {action: block_ip, target: attrs.peer}\n")
		got, tr := r.RespondTargets(events)
		if strings.Join(got, ",") != "198.51.100.7" || tr != 0 {
			t.Fatalf("%v усечено %d", got, tr)
		}
	})
	t.Run("пустые события", func(t *testing.T) {
		r := load(t, base+"respond: {action: block_ip}\n")
		if got, tr := r.RespondTargets(nil); len(got) != 0 || tr != 0 {
			t.Fatalf("%v %d", got, tr)
		}
	})
	t.Run("target без геттера в структуре — откат на src.ip", func(t *testing.T) {
		// LoadFile такое не пропустит; проверяем защиту самого метода.
		r := &Rule{Respond: &Respond{Target: "   "}}
		if got, _ := r.RespondTargets(events[:1]); strings.Join(got, ",") != "203.0.113.1" {
			t.Fatalf("%v", got)
		}
	})
}

func TestAutoCloseAfter(t *testing.T) {
	for in, want := range map[string]time.Duration{"": 0, "junk": 0, "-5m": 0, "0s": 0, "90m": 90 * time.Minute, "2h": 2 * time.Hour} {
		r := &Rule{AutoClose: in}
		if got := r.AutoCloseAfter(); got != want {
			t.Errorf("auto_close %q: %v, want %v", in, got, want)
		}
	}
	if (&Rule{}).AutoCloseEscalates() || !(&Rule{AutoCloseAction: "escalate"}).AutoCloseEscalates() {
		t.Fatal("AutoCloseEscalates")
	}
}

func TestResetMatchers(t *testing.T) {
	plain := load(t, base)
	if plain.UsesReset() || plain.MatchReset(&model.Event{Node: "a"}) {
		t.Fatal("без detection.reset серия не обрывается")
	}
	r := load(t, `
title: x
id: y
level: high
detection:
  selection: {value: '>= 90'}
  reset: {value: '< 90', unit: percent}
  threshold: {kind: consecutive, count: 3, window: 15m}
  condition: selection and threshold
`)
	if !r.UsesReset() {
		t.Fatal("UsesReset")
	}
	if !r.MatchReset(&model.Event{Value: 10, Unit: "percent"}) {
		t.Fatal("оба матчера совпали — reset")
	}
	if r.MatchReset(&model.Event{Value: 10, Unit: "bytes"}) || r.MatchReset(&model.Event{Value: 95, Unit: "percent"}) {
		t.Fatal("частичное совпадение — не reset")
	}
}

func TestWindowAndGroupBy(t *testing.T) {
	for name, tc := range map[string]struct {
		yml    string
		window time.Duration
		group  string
	}{
		"threshold с окном и group_by":  {base + "  threshold: {count: 3, window: 6m, group_by: src.ip}\n  condition: selection and threshold\n", 6 * time.Minute, "src.ip"},
		"threshold без group_by":        {base + "  threshold: {count: 3, window: 1h}\n  condition: selection and threshold\n", time.Hour, "actor.name"},
		"dedupe задан":                  {base + "dedupe: 30m\n", 30 * time.Minute, "actor.name"},
		"dedupe кривой — умолчание 10m": {base + "dedupe: soon\n", 10 * time.Minute, "actor.name"},
		"ничего не задано":              {base, 10 * time.Minute, "actor.name"},
	} {
		r := load(t, tc.yml)
		if got := r.Window(); got != tc.window {
			t.Errorf("%s: окно %v, want %v", name, got, tc.window)
		}
		if got := r.GroupBy(); got != tc.group {
			t.Errorf("%s: group_by %q, want %q", name, got, tc.group)
		}
	}
	// Порог с нечитаемым окном LoadFile не пропускает; сам метод откатывается на 15 минут.
	r := &Rule{}
	r.Detection.Threshold = &Threshold{Window: "later"}
	if r.Window() != 15*time.Minute {
		t.Fatalf("окно порога по умолчанию: %v", r.Window())
	}
}

func TestIsAbsenceAndThresholdFlags(t *testing.T) {
	abs := load(t, base+"  threshold: {kind: absence, window: 10m}\n  condition: selection and threshold\n")
	if !abs.IsAbsence() || !abs.UsesThreshold() {
		t.Fatal("absence")
	}
	cnt := load(t, base+"  threshold: {count: 2, window: 10m}\n  condition: selection and threshold\n")
	if cnt.IsAbsence() {
		t.Fatal("count — не absence")
	}
	// threshold описан, но condition его не упоминает — порог не используется.
	noCond := load(t, base+"  threshold: {count: 2, window: 10m}\n")
	if noCond.UsesThreshold() || noCond.IsAbsence() {
		t.Fatal("threshold без condition не используется")
	}
	if load(t, base).IsAbsence() {
		t.Fatal("без порога")
	}
}

func TestMatchWithFilter(t *testing.T) {
	r := load(t, `
title: x
id: y
level: high
detection:
  selection: {action: login}
  filter: {outcome: success, actor.kind: service}
  condition: selection and not filter
`)
	if !r.UsesFilter() {
		t.Fatal("UsesFilter")
	}
	if r.Match(&model.Event{Action: "login", Outcome: "success", ActorKind: "service"}) {
		t.Fatal("фильтр совпал целиком — событие отсеяно")
	}
	if !r.Match(&model.Event{Action: "login", Outcome: "success", ActorKind: "person"}) {
		t.Fatal("фильтр совпал частично — событие проходит")
	}
	if r.Match(&model.Event{Action: "logout"}) {
		t.Fatal("selection не совпал")
	}
	// condition без «not filter»: блок filter описан, но не применяется.
	ignored := load(t, "title: x\nid: y\nlevel: high\ndetection:\n  selection: {action: login}\n  filter: {outcome: success}\n  condition: selection\n")
	if ignored.UsesFilter() || !ignored.Match(&model.Event{Action: "login", Outcome: "success"}) {
		t.Fatal("filter без условия игнорируется")
	}
}

func TestGetterFields(t *testing.T) {
	e := &model.Event{
		Source: "src", SourceClass: "cls", Vendor: "ven", Product: "prod", Action: "act", Outcome: "ok", Severity: 7,
		ActorName: "alice", ActorKind: "person", Object: "obj", Node: "host-1", SessionID: "sess",
		SrcIP: "10.0.0.1", SrcPort: 1234, DstIP: "10.0.0.2", DstPort: 443, Proto: "tcp", Bytes: 1 << 40, Packets: 12,
		Value: 2.5, Unit: "percent", PII: 1, Attrs: map[string]string{"k": "v"},
	}
	for field, want := range map[string]string{
		"event.action": "act", "action": "act",
		"event.outcome": "ok", "outcome": "ok",
		"event.severity": "7", "severity": "7",
		"source": "src", "source.class": "cls", "source_class": "cls",
		"vendor": "ven", "product": "prod",
		"actor.name": "alice", "actor": "alice", "actor.kind": "person",
		"object": "obj", "target.object": "obj",
		"node": "host-1", "target.host": "host-1", "host": "host-1",
		"session": "sess", "session.id": "sess",
		"src.ip": "10.0.0.1", "source.ip": "10.0.0.1", "src.port": "1234",
		"dst.ip": "10.0.0.2", "target.ip": "10.0.0.2", "dst.port": "443", "target.port": "443",
		"proto": "tcp", "bytes": "1099511627776", "packets": "12",
		"value": "2.5", "unit": "percent", "pii": "1",
		"attrs.k": "v", "attrs.missing": "",
	} {
		get := Getter(field)
		if get == nil {
			t.Errorf("%s: нет геттера", field)
			continue
		}
		if got := get(e); got != want {
			t.Errorf("%s: %q, want %q", field, got, want)
		}
	}
	for _, f := range []string{"", "nosuch", "attrs", "Action", "event"} {
		if Getter(f) != nil {
			t.Errorf("%q: геттера быть не должно", f)
		}
	}
	// attrs у события nil — пустая строка, не паника.
	if Getter("attrs.k")(&model.Event{}) != "" {
		t.Fatal("nil attrs")
	}
}

func TestValueMatcherOperators(t *testing.T) {
	for name, tc := range map[string]struct {
		sel  string
		hit  *model.Event
		miss *model.Event
	}{
		">=":                   {"severity: '>= 5'", &model.Event{Severity: 5}, &model.Event{Severity: 4}},
		"<=":                   {"severity: '<= 5'", &model.Event{Severity: 5}, &model.Event{Severity: 6}},
		"<":                    {"severity: '< 5'", &model.Event{Severity: 4}, &model.Event{Severity: 5}},
		">":                    {"severity: '> 5'", &model.Event{Severity: 6}, &model.Event{Severity: 5}},
		"!=":                   {"outcome: '!= success'", &model.Event{Outcome: "failure"}, &model.Event{Outcome: "SUCCESS"}},
		"not":                  {"outcome: 'not success'", &model.Event{Outcome: "failure"}, &model.Event{Outcome: "success"}},
		"eq без регистра":      {"action: Login", &model.Event{Action: "LOGIN"}, &model.Event{Action: "logout"}},
		"contains в строке":    {"object: 'contains Temp'", &model.Event{Object: `c:\temp\x`}, &model.Event{Object: "c:\\windows"}},
		"модификатор contains": {"object|contains: TEMP", &model.Event{Object: `c:\Temp\x`}, &model.Event{Object: "x"}},
		"startswith":           {"node|startswith: WKS", &model.Event{Node: "wks-01"}, &model.Event{Node: "srv-01"}},
		"endswith":             {"node: 'endswith -01'", &model.Event{Node: "wks-01"}, &model.Event{Node: "wks-02"}},
		"regex":                {"object: 'regex ^a+$'", &model.Event{Object: "aaa"}, &model.Event{Object: "aab"}},
		"модификатор re":       {"object|re: '^a+$'", &model.Event{Object: "aa"}, &model.Event{Object: "b"}},
		"gt":                   {"severity|gt: 5", &model.Event{Severity: 6}, &model.Event{Severity: 5}},
		"lt":                   {"severity|lt: 5", &model.Event{Severity: 4}, &model.Event{Severity: 5}},
		"gte":                  {"severity|gte: 5", &model.Event{Severity: 5}, &model.Event{Severity: 4}},
		"lte":                  {"severity|lte: 5", &model.Event{Severity: 5}, &model.Event{Severity: 6}},
		"число против текста":  {"object: '> 5'", &model.Event{Object: "6"}, &model.Event{Object: "many"}},
		"список значений":      {"action: [a, b]", &model.Event{Action: "B"}, &model.Event{Action: "c"}},
		"число как значение":   {"severity: 7", &model.Event{Severity: 7}, &model.Event{Severity: 8}},
	} {
		r := load(t, "title: x\nid: y\nlevel: high\ndetection:\n  selection:\n    "+tc.sel+"\n")
		if !r.Match(tc.hit) {
			t.Errorf("%s: должно совпасть", name)
		}
		if r.Match(tc.miss) {
			t.Errorf("%s: не должно совпасть", name)
		}
	}
}

func TestCompileErrors(t *testing.T) {
	mustFail(t, "пустой список", "title: x\nid: y\ndetection:\n  selection: {node: []}\n", "пустое значение")
	mustFail(t, "null", "title: x\nid: y\ndetection:\n  selection: {node: null}\n", "пустое значение")
	mustFail(t, "битый regex", "title: x\nid: y\ndetection:\n  selection: {node: 'regex ['}\n", "node")
	mustFail(t, "не число после >", "title: x\nid: y\ndetection:\n  selection: {severity: '> many'}\n", "число ожидалось")
	mustFail(t, "неизвестный модификатор", "title: x\nid: y\ndetection:\n  selection: {node|fuzzy: a}\n", "неизвестный модификатор")
	mustFail(t, "чужое поле в filter", base+"  filter: {nosuch: a}\n  condition: selection and not filter\n", "неизвестное поле")
	mustFail(t, "чужое поле в close_on", base+"close_on: {nosuch: a}\n", "close_on")
	mustFail(t, "пустой selection", "title: x\nid: y\ndetection:\n  condition: selection\n", "пустой detection.selection")
	mustFail(t, "без title", "id: y\ndetection:\n  selection: {node: a}\n", "нужны id и title")
	mustFail(t, "не yaml", "title: [\n", "")
	if _, err := LoadFile(filepath.Join(t.TempDir(), "nosuch.yml")); err == nil {
		t.Error("отсутствующий файл")
	}
}

func TestAsList(t *testing.T) {
	if asList(nil) != nil {
		t.Fatal("nil")
	}
	if got := asList([]any{1, "b", true}); strings.Join(got, ",") != "1,b,true" {
		t.Fatalf("%v", got)
	}
	if got := asList(3.5); len(got) != 1 || got[0] != "3.5" {
		t.Fatalf("%v", got)
	}
}

func TestLoadThresholdValidation(t *testing.T) {
	th := func(spec string) string {
		return base + "  threshold: " + spec + "\n  condition: selection and threshold\n"
	}
	mustFail(t, "distinct без field", th("{distinct: 3, window: 1m}"), "distinct")
	mustFail(t, "kind distinct без distinct", th("{kind: distinct, field: src.ip, window: 1m}"), "distinct")
	mustFail(t, "count 0", th("{window: 1m}"), "нужен count")
	mustFail(t, "periodic count 3", th("{kind: periodic, count: 3, window: 1h}"), "periodic")
	mustFail(t, "неизвестный kind", th("{kind: median, count: 3, window: 1h}"), "неизвестен")
	mustFail(t, "кривое окно", th("{count: 3, window: soon}"), "threshold.window")
	mustFail(t, "absence без окна", th("{kind: absence}"), "threshold.window")

	p := load(t, th("{kind: periodic, count: 4, window: 1h}"))
	if p.Detection.Threshold.Jitter != 0.05 {
		t.Fatalf("jitter по умолчанию 0.05, got %v", p.Detection.Threshold.Jitter)
	}
	p = load(t, th("{kind: periodic, count: 4, window: 1h, jitter: 0.2}"))
	if p.Detection.Threshold.Jitter != 0.2 {
		t.Fatalf("jitter задан явно: %v", p.Detection.Threshold.Jitter)
	}
	d := load(t, th("{field: src.ip, distinct: 5, window: 5m}"))
	if d.Detection.Threshold.KindResolved() != "distinct" || d.Window() != 5*time.Minute {
		t.Fatal("distinct")
	}
	// condition по умолчанию — selection.
	if load(t, "title: x\nid: y\ndetection:\n  selection: {node: a}\n").Detection.Condition != "selection" {
		t.Fatal("condition по умолчанию")
	}
}

func TestLoadAutoCloseAndRespondValidation(t *testing.T) {
	mustFail(t, "auto_close кривой", base+"auto_close: tomorrow\n", "auto_close")
	mustFail(t, "auto_close_action кривой", base+"auto_close: 1h\nauto_close_action: drop\n", "auto_close_action")
	for _, ok := range []string{"close", "escalate", ""} {
		load(t, base+"auto_close: 1h\nauto_close_action: '"+ok+"'\n")
	}
	mustFail(t, "respond не block_ip", base+"respond: {action: isolate_host}\n", "respond.action")
	mustFail(t, "respond target не адрес", base+"respond: {action: block_ip, target: object}\n", "respond.target")
	mustFail(t, "respond target чужой", base+"respond: {action: block_ip, target: nosuch.ip}\n", "respond.target")
	mustFail(t, "respond min_level", base+"respond: {action: block_ip, min_level: urgent}\n", "respond.min_level")
	mustFail(t, "respond ttl", base+"respond: {action: block_ip, ttl: forever}\n", "respond.ttl")
	mustFail(t, "respond max_targets < 0", base+"respond: {action: block_ip, max_targets: -1}\n", "respond.max_targets")
	for _, target := range []string{"src.ip", "source.ip", "dst.ip", "target.ip", "actor.name", "actor", "attrs.peer", ""} {
		r := load(t, base+"respond: {action: block_ip, target: '"+target+"', min_level: High, ttl: 2h, max_targets: 5}\n")
		if r.Respond.MaxTargets != 5 {
			t.Fatalf("%s: respond не прочитан", target)
		}
	}
}

func TestFilesSkipsTestsDirsAndSorts(t *testing.T) {
	dir := t.TempDir()
	for _, p := range []string{"b.yml", "a.yaml", "c.txt", "tests/t.yml", "ops/tests/x.yml", "ops/z.yml", "zz/tests/deep/y.yml"} {
		full := filepath.Join(dir, filepath.FromSlash(p))
		_ = os.MkdirAll(filepath.Dir(full), 0o755)
		_ = os.WriteFile(full, []byte("x"), 0o600)
	}
	got, err := Files(dir)
	if err != nil {
		t.Fatal(err)
	}
	var rel []string
	for _, p := range got {
		r, _ := filepath.Rel(dir, p)
		rel = append(rel, filepath.ToSlash(r))
	}
	// Каталог tests/ пропускается на любом уровне (ops/tests тоже), .txt — не правило, порядок — лексический.
	if strings.Join(rel, ",") != "a.yaml,b.yml,ops/z.yml" {
		t.Fatalf("файлы: %v", rel)
	}
	if _, err := Files(filepath.Join(dir, "nosuch")); err == nil {
		t.Fatal("несуществующий каталог — ошибка")
	}
	// Корень с именем tests — правила читаются: пропуск только для подкаталогов.
	root := filepath.Join(t.TempDir(), "tests")
	_ = os.MkdirAll(root, 0o755)
	_ = os.WriteFile(filepath.Join(root, "r.yml"), []byte("x"), 0o600)
	if got, _ := Files(root); len(got) != 1 {
		t.Fatalf("корень tests: %v", got)
	}
}

func TestMatchCloseAndCloseMatchKeyEdges(t *testing.T) {
	r := load(t, base)
	if r.MatchClose(&model.Event{Node: "a"}) {
		t.Fatal("без close_on не закрывает")
	}
	if _, ok := r.CloseMatchKey(&model.Event{Object: "x"}); ok {
		t.Fatal("без close_match ключа нет")
	}
	c := load(t, base+"close_on: {action: revoke, outcome: success}\n")
	if !c.MatchClose(&model.Event{Action: "REVOKE", Outcome: "success"}) || c.MatchClose(&model.Event{Action: "revoke", Outcome: "failure"}) {
		t.Fatal("close_on требует всех полей")
	}
}
