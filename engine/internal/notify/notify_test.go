package notify

import (
	"strings"
	"testing"
	"time"
)

func TestLimiterTokenBucket(t *testing.T) {
	now := time.Date(2026, 9, 14, 10, 0, 0, 0, time.UTC)
	l := NewLimiter(20)
	l.nowFn = func() time.Time { return now }
	for i := 0; i < 20; i++ {
		if !l.Allow() {
			t.Fatalf("burst 20: отказ на %d", i)
		}
	}
	if l.Allow() {
		t.Fatal("21-е сообщение в ту же секунду — отказ")
	}
	now = now.Add(3 * time.Second) // 20/мин = 1 токен за 3 с
	if !l.Allow() || l.Allow() {
		t.Fatal("через 3 секунды ровно один токен")
	}
	now = now.Add(time.Hour)
	for i := 0; i < 20; i++ {
		if !l.Allow() {
			t.Fatal("bucket не должен переполняться выше burst, но burst восстанавливается")
		}
	}
	if l.Allow() {
		t.Fatal("выше burst")
	}
}

// Ограничитель не зависит от настоящих часов: подменённое «сейчас» в прошлом
// или будущем относительно момента создания ведёт себя одинаково, а ход часов
// назад не пополняет и не опустошает bucket.
func TestLimiterClockIndependent(t *testing.T) {
	for _, start := range []time.Time{time.Date(2000, 1, 1, 0, 0, 0, 0, time.UTC), time.Now().Add(-48 * time.Hour), time.Now().Add(365 * 24 * time.Hour)} {
		now := start
		l := NewLimiter(2)
		l.nowFn = func() time.Time { return now }
		if !l.Allow() || !l.Allow() || l.Allow() {
			t.Fatalf("burst 2 от %s", start)
		}
		now = now.Add(-time.Hour) // часы назад
		if l.Allow() {
			t.Fatal("ход часов назад не должен давать токен")
		}
		now = now.Add(time.Hour + 30*time.Second) // 2/мин = 1 токен за 30 с относительно последнего вызова
		if !l.Allow() || l.Allow() {
			t.Fatal("после 30 с — ровно один токен")
		}
	}
}

func TestAggregatorStorm(t *testing.T) {
	now := time.Date(2026, 9, 14, 10, 0, 0, 0, time.UTC)
	a := NewAggregator(time.Minute, 5)
	a.nowFn = func() time.Time { return now }
	direct := 0
	for i := 0; i < 12; i++ {
		if a.Add("r1", "WAF burst", "203.0.113."+string(rune('1'+i))) {
			direct++
		}
		now = now.Add(2 * time.Second)
	}
	if direct != 5 {
		t.Fatalf("первые 5 отдельно, got %d", direct)
	}
	if a.Add("r2", "другое правило", "x") != true {
		t.Fatal("другое правило считается отдельно")
	}
	if out := a.Flush(); len(out) != 0 {
		t.Fatalf("окно ещё открыто: %v", out)
	}
	now = now.Add(time.Minute)
	out := a.Flush()
	if len(out) != 1 || !strings.Contains(out[0], "12 инцидентов по правилу «WAF burst» (r1)") || !strings.Contains(out[0], "и ещё 2") {
		t.Fatalf("сводка: %v", out)
	}
	// r2: 1 инцидент, ушёл отдельно — сводки нет; после сброса окно r1 открывается заново
	if a.Add("r1", "WAF burst", "203.0.113.50") != true {
		t.Fatal("новое окно — снова отдельно")
	}
}
