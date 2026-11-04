package model

import (
	"runtime"
	"strings"
	"testing"
)

// Достижение неподвижной точки не должно оплачивать полную копию строки
// за каждый удалённый C1. Такие байты принимает LEEF/CEF по UDP/TCP;
// ограничение длины отдельного атрибута не ограничивает суммарную стоимость
// всех проходов. Проверяем расход памяти на одном маленьком значении,
// без таймингов, сетевого трафика и нагрузки на работающий коллектор.
func TestPR110Round3SanitizeNestedC1AllocationBound(t *testing.T) {
	const depth = 2048
	dirty := "a" + strings.Repeat("\xc2", depth) + "\x00" + strings.Repeat("\x80", depth) + "b"
	if len(dirty) >= MaxFieldLen {
		t.Fatal("fixture must fit the field limit without truncation")
	}
	e := Event{Raw: dirty, Attrs: map[string]string{"payload": dirty}}

	runtime.GC()
	var before, after runtime.MemStats
	runtime.ReadMemStats(&before)
	e.Sanitize()
	runtime.ReadMemStats(&after)

	if e.Attrs["payload"] != "ab" || e.Raw != dirty {
		t.Fatal("sanitization must reach the fixed point and preserve raw evidence")
	}
	// Запас в 256 размеров входа допускает вспомогательные структуры и
	// несколько проходов. Квадратичный вариант тратит более 1000 размеров.
	allocated := after.TotalAlloc - before.TotalAlloc
	limit := uint64(256 * len(dirty))
	if allocated > limit {
		t.Fatalf("Sanitize allocated %d bytes for a %d-byte attribute; budget %d: nested controls amplify ingestion work",
			allocated, len(dirty), limit)
	}
}
