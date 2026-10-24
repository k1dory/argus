package model

import (
	"math"
	"strings"
	"testing"
	"time"
	"unicode/utf8"
)

func TestClampTimeWindow(t *testing.T) {
	fixed := time.Date(2026, 9, 14, 12, 0, 0, 0, time.UTC)
	Now = func() time.Time { return fixed }
	defer func() { Now = time.Now }()

	cases := []struct {
		name string
		in   time.Time
		ok   bool
	}{
		{"now", fixed, true},
		{"yesterday", fixed.Add(-24 * time.Hour), true},
		{"+23h", fixed.Add(23 * time.Hour), true},
		{"+25h", fixed.Add(25 * time.Hour), false},
		{"11y ago", fixed.Add(-11 * 365 * 24 * time.Hour), false},
		{"epoch", time.Unix(0, 0), false},
		{"unixmilli MaxInt64", time.UnixMilli(math.MaxInt64), false},
		{"unix MaxInt64", time.Unix(math.MaxInt64, 0), false},
		{"zero", time.Time{}, true},
	}
	for _, c := range cases {
		got, ok := ClampTime(c.in)
		if ok != c.ok {
			t.Errorf("%s: ok=%v, want %v", c.name, ok, c.ok)
		}
		if !ok && !got.Equal(fixed) {
			t.Errorf("%s: clamped to %v, want now", c.name, got)
		}
	}
	if s := FormatTS(time.UnixMilli(math.MaxInt64)); s != "2026-09-14 12:00:00.000" {
		t.Errorf("FormatTS overflow → %q", s)
	}
}

func TestSetTSKeepsRaw(t *testing.T) {
	fixed := time.Date(2026, 9, 14, 12, 0, 0, 0, time.UTC)
	Now = func() time.Time { return fixed }
	defer func() { Now = time.Now }()

	var e Event
	e.SetTS(time.Date(2099, 1, 1, 0, 0, 0, 0, time.UTC), "2099-01-01T00:00:00Z")
	if e.TS != "2026-09-14 12:00:00.000" || e.Attrs["ts_raw"] != "2099-01-01T00:00:00Z" {
		t.Errorf("future: ts=%q attrs=%v", e.TS, e.Attrs)
	}
	e = Event{}
	e.SetTS(fixed.Add(-time.Hour), "")
	if e.TS != "2026-09-14 11:00:00.000" || e.Attrs["ts_raw"] != "" {
		t.Errorf("in-window: ts=%q attrs=%v", e.TS, e.Attrs)
	}
}

func TestEnsureRepairsTS(t *testing.T) {
	fixed := time.Date(2026, 9, 14, 12, 0, 0, 0, time.UTC)
	Now = func() time.Time { return fixed }
	defer func() { Now = time.Now }()

	for in, wantRaw := range map[string]string{
		"garbage":                       "garbage",
		"2999-12-31 23:59:59.000":       "2999-12-31 23:59:59.000",
		"1970-01-01T00:00:00Z":          "1970-01-01T00:00:00Z",
		"292278994-08-17 07:12:55.807":  "292278994-08-17 07:12:55.807",
		"2026-09-14T11:30:00+03:00":     "", // валидное — приводится к UTC
		"2026-09-14 11:30:00":           "",
		strings.Repeat("9", 200) + "-x": strings.Repeat("9", 64),
	} {
		e := Event{TS: in}
		e.Ensure()
		if _, ok := ParseTS(e.TS); !ok {
			t.Errorf("%q → ts %q не парсится", in, e.TS)
		}
		if e.Attrs["ts_raw"] != wantRaw {
			t.Errorf("%q → ts_raw %q, want %q", in, e.Attrs["ts_raw"], wantRaw)
		}
		if wantRaw != "" && e.TS != "2026-09-14 12:00:00.000" {
			t.Errorf("%q → ts %q, want now", in, e.TS)
		}
	}
	e := Event{TS: "2026-09-14T11:30:00+03:00"}
	e.Ensure()
	if e.TS != "2026-09-14 08:30:00.000" {
		t.Errorf("tz normalize: %q", e.TS)
	}
}

func TestSanitize(t *testing.T) {
	e := Event{
		ActorName: "adm\x1b[31min\x1b[0m",
		Object:    "/api\r\nX-Injected: 1\x00\x07",
		Node:      "host\x1b]0;evil\x07",
		Action:    "a\tbc",
		Raw:       "raw\x1b[31m untouched\x00",
		Attrs:     map[string]string{"k\x01": "v\x1bP dcs \x1b\\ok", "long": strings.Repeat("я", 5000)},
	}
	e.Ensure()
	if e.ActorName != "admin" {
		t.Errorf("ActorName %q", e.ActorName)
	}
	if e.Object != "/api  X-Injected: 1" {
		t.Errorf("Object %q", e.Object)
	}
	if e.Node != "host" {
		t.Errorf("Node %q", e.Node)
	}
	if e.Action != "a\tbc" {
		t.Errorf("Action %q", e.Action)
	}
	if e.Raw != "raw\x1b[31m untouched\x00" {
		t.Errorf("Raw изменён: %q", e.Raw)
	}
	if e.Attrs["k"] != "vok" {
		t.Errorf("attrs: %q", e.Attrs)
	}
	if _, ok := e.Attrs["k\x01"]; ok {
		t.Error("грязный ключ остался")
	}
	long := e.Attrs["long"]
	if len(long) > MaxFieldLen || len(long) < MaxFieldLen-3 || !strings.HasSuffix(long, "я") {
		t.Errorf("обрезка по руне: len=%d", len(long))
	}
	if e.Attrs["truncated"] != "1" {
		t.Error("нет пометки truncated")
	}
	clean := Event{Object: "plain ascii"}
	clean.Ensure()
	if _, ok := clean.Attrs["truncated"]; ok {
		t.Error("truncated без обрезки")
	}
}

func TestTruncateInvalidUTF8(t *testing.T) {
	in := strings.Repeat("a", 100) + "\xff" + strings.Repeat("b", 20000)
	got, cut := Clean(in)
	if !cut {
		t.Fatal("строка длиннее MaxFieldLen должна быть обрезана")
	}
	if len(got) < MaxFieldLen-3 || len(got) > MaxFieldLen {
		t.Fatalf("len=%d, want ≈ %d: битый байт срезал строку до себя", len(got), MaxFieldLen)
	}
	if !strings.HasPrefix(got, strings.Repeat("a", 100)+"�") || !utf8.ValidString(got) {
		t.Errorf("битый байт должен стать U+FFFD: %q…", got[:110])
	}
	// многобайтовые руны: срез по границе, назад не больше 3 байт
	ru := strings.Repeat("я", 5000)
	got = truncate(ru, MaxFieldLen)
	if !utf8.ValidString(got) || len(got) < MaxFieldLen-3 || !strings.HasSuffix(got, "я") {
		t.Errorf("обрезка по руне: len=%d", len(got))
	}
	if got := truncate("abc", 10); got != "abc" {
		t.Errorf("короткая строка не меняется: %q", got)
	}
	// подряд идущие битые байты схлопываются в один U+FFFD и строка помещается — без обрезки
	if got := truncate("a\xff\xff\xff\xffb", 5); got != "a�b" {
		t.Errorf("замена без обрезки: %q", got)
	}
}

func TestRawCapped(t *testing.T) {
	e := Event{Raw: strings.Repeat("x", MaxRawLen+10)}
	e.Ensure()
	if len(e.Raw) != MaxRawLen || e.Attrs["truncated"] != "1" {
		t.Errorf("raw: len=%d truncated=%q", len(e.Raw), e.Attrs["truncated"])
	}
	// первые байты, не последние
	head := strings.Repeat("h", 100) + strings.Repeat("t", MaxRawLen)
	e = Event{Raw: head}
	e.Ensure()
	if !strings.HasPrefix(e.Raw, strings.Repeat("h", 100)) {
		t.Error("должны остаться первые байты Raw")
	}
	ok := Event{Raw: strings.Repeat("x", MaxRawLen)}
	ok.Ensure()
	if _, cut := ok.Attrs["truncated"]; cut || len(ok.Raw) != MaxRawLen {
		t.Error("ровно MaxRawLen — без обрезки")
	}
}

func TestApproxSize(t *testing.T) {
	e := Event{Raw: strings.Repeat("x", 1000), Object: "obj", Attrs: map[string]string{"k": "v"}}
	if n := e.ApproxSize(); n < 1000+3+2 || n > 1000+3+2+512 {
		t.Errorf("ApproxSize=%d", n)
	}
}
