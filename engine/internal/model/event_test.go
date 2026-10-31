package model

import (
	"testing"
	"time"
)

func TestFormatTS(t *testing.T) {
	// Формат — ровно колонка ts таблицы argus.events (DateTime64(3), UTC).
	msk := time.FixedZone("MSK", 3*3600)
	got := FormatTS(time.Date(2026, 9, 14, 13, 4, 5, 678_000_000, msk))
	if got != "2026-09-14 10:04:05.678" {
		t.Fatalf("время приводится к UTC с миллисекундами: %q", got)
	}
	// Нулевое время — «сейчас», а не 0001-01-01: строка обязана вставиться.
	before := time.Now().UTC().Add(-time.Second)
	e := Event{TS: FormatTS(time.Time{})}
	if ts := e.Time(); ts.Before(before) || ts.After(time.Now().UTC().Add(time.Second)) {
		t.Fatalf("нулевое время → текущее, получили %s", ts)
	}
}

func TestEnsureDefaults(t *testing.T) {
	var e Event
	e.Ensure()
	if e.TS == "" || e.Time().IsZero() {
		t.Fatalf("ts обязателен и разбирается обратно: %q", e.TS)
	}
	if e.Attrs == nil {
		t.Fatal("attrs — пустая map, а не nil (Map в ClickHouse)")
	}
	if e.Outcome != "unknown" || e.ActorKind != "unknown" {
		t.Fatalf("outcome/actor_kind по умолчанию unknown: %q %q", e.Outcome, e.ActorKind)
	}
	// TODO ревью: порядок в Ensure — сначала Source = SourceClass, потом
	// SourceClass = "syslog"; событие без обоих полей получает класс syslog, а
	// source остаётся пустым. Так же устроен collector/internal/model. Тест
	// фиксирует текущее поведение; если менять — в обоих модулях.
	if e.SourceClass != "syslog" || e.Source != "" {
		t.Fatalf("без класса — syslog, source при этом пуст: %q %q", e.Source, e.SourceClass)
	}
}

func TestEnsureKeepsFilled(t *testing.T) {
	e := Event{TS: "2026-01-02 03:04:05.000", Source: "ngfw.checkpoint", SourceClass: "ngfw", Outcome: "deny", ActorKind: "user", Attrs: map[string]string{"k": "v"}}
	e.Ensure()
	if e.TS != "2026-01-02 03:04:05.000" || e.Source != "ngfw.checkpoint" || e.SourceClass != "ngfw" || e.Outcome != "deny" || e.ActorKind != "user" || e.Attrs["k"] != "v" {
		t.Fatalf("заполненные поля не перетираются: %+v", e)
	}
	// Источник без имени, но с классом: имя = класс.
	e2 := Event{SourceClass: "edr"}
	e2.Ensure()
	if e2.Source != "edr" || e2.SourceClass != "edr" {
		t.Fatalf("source наследует заданный класс: %q %q", e2.Source, e2.SourceClass)
	}
}

func TestTimeLayouts(t *testing.T) {
	want := time.Date(2026, 9, 14, 10, 4, 5, 0, time.UTC)
	cases := map[string]time.Time{
		"2026-09-14 10:04:05.000":       want,
		"2026-09-14 10:04:05.678":       want.Add(678 * time.Millisecond),
		"2026-09-14 10:04:05":           want, // DateTime без миллисекунд (collector_health, фикстуры)
		"2026-09-14T10:04:05Z":          want, // RFC3339
		"2026-09-14T13:04:05+03:00":     want, // RFC3339 со смещением — приводится к UTC
		"2026-09-14T10:04:05.000123Z":   want.Add(123 * time.Microsecond),
		"":                              {},
		"вчера":                         {},
		"2026-09-14":                    {},
		"14.09.2026 10:04:05":           {},
		"2026-09-14 10:04:05.000 +0300": {},
	}
	for in, exp := range cases {
		got := (&Event{TS: in}).Time()
		if !got.Equal(exp) {
			t.Errorf("%q → %s, ожидалось %s", in, got, exp)
		}
		if !got.IsZero() && got.Location() != time.UTC {
			t.Errorf("%q → зона %s, ожидался UTC", in, got.Location())
		}
	}
}

func TestFormatAndParseRoundTrip(t *testing.T) {
	orig := time.Date(2026, 2, 28, 23, 59, 59, 999_000_000, time.UTC)
	e := Event{TS: FormatTS(orig)}
	if got := e.Time(); !got.Equal(orig) {
		t.Fatalf("FormatTS → Time теряет точность: %s ≠ %s", got, orig)
	}
}
