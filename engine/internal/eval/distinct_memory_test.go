package eval

import (
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strconv"
	"testing"
	"time"

	"github.com/devitex-soft/argus/engine/internal/model"
	"github.com/devitex-soft/argus/engine/internal/rules"
)

// Сканер на argus1 (02.11, a41c-net-070/071): одна группа src.ip с ~40 тыс.
// событий дольше окна правила. Оценка такого буфера не должна стоить O(n²)
// памяти: прежде каждое событие после сдвига окна заводило новую сработку с
// копией всего окна, а distinct каждый раз строил map по окну.
func scannerEvents(n int, span time.Duration) []*model.Event {
	t0 := time.Date(2026, 11, 2, 19, 0, 0, 0, time.UTC)
	out := make([]*model.Event, n)
	for i := range out {
		ts := t0.Add(time.Duration(int64(span) * int64(i) / int64(n)))
		out[i] = &model.Event{
			TS: model.FormatTS(ts), Source: "netflow", SourceClass: "netflow", Action: "flow",
			SrcIP: "94.26.88.90", DstIP: "203.0.113." + strconv.Itoa(i%250), DstPort: uint16(1 + i%60000),
			Attrs: map[string]string{"scope": "inbound", "syn_only": "1"},
		}
	}
	return out
}

func scannerRule(t testing.TB, field string, distinct int) *rules.Rule {
	t.Helper()
	path := filepath.Join(t.TempDir(), "scan.yml")
	if err := os.WriteFile(path, []byte(fmt.Sprintf(`
title: scan
id: t-scan
level: medium
detection:
  selection: {source.class: netflow, attrs.scope: inbound, attrs.syn_only: "1"}
  threshold: {kind: distinct, field: %s, distinct: %d, window: 10m, group_by: src.ip}
  condition: selection and threshold
`, field, distinct)), 0o644); err != nil {
		t.Fatal(err)
	}
	r, err := rules.LoadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	return r
}

func TestDistinctScannerGroupBoundedMemory(t *testing.T) {
	events := scannerEvents(40000, 30*time.Minute)
	rs := []*rules.Rule{scannerRule(t, "dst.port", 50), scannerRule(t, "dst.ip", 20)}
	rs[1].ID = "t-sweep"
	runtime.GC()
	var before, after runtime.MemStats
	runtime.ReadMemStats(&before)
	dets, _ := Evaluate(Input{Rules: rs, Events: events})
	runtime.ReadMemStats(&after)
	allocated := after.TotalAlloc - before.TotalAlloc
	t.Logf("сработок %d, выделено %d МиБ", len(dets), allocated>>20)
	if len(dets) != 2 {
		t.Fatalf("сработок %d: одна непрерывная серия сканера на правило", len(dets))
	}
	for _, d := range dets {
		if len(d.Events) != len(events) {
			t.Fatalf("%s: в сработке %d событий из %d", d.Rule.ID, len(d.Events), len(events))
		}
	}
	// Буфер 40k указателей ≈ 0,3 МиБ на копию; линейная оценка двух правил с
	// группами и сортировкой укладывается в десятки МиБ, квадратичная — в гигабайты.
	if allocated > 64<<20 {
		t.Fatalf("оценка выделила %d МиБ на 40 тыс. событий — рост не линейный", allocated>>20)
	}
}

func BenchmarkDistinctScannerGroup(b *testing.B) {
	events := scannerEvents(40000, 30*time.Minute)
	rs := []*rules.Rule{scannerRule(b, "dst.port", 50)}
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		Evaluate(Input{Rules: rs, Events: events})
	}
}

// Порог по аллокациям оценки (бенчмарк: ~67 тыс. на 40 тыс. событий) и та же
// линейность для правил без порога и с count: непрерывный поток одной группы
// не размножает сработки на каждом сдвиге окна.
func TestScannerGroupAllocsAndOtherKinds(t *testing.T) {
	events := scannerEvents(40000, 30*time.Minute)
	scan := []*rules.Rule{scannerRule(t, "dst.port", 50)}
	if allocs := testing.AllocsPerRun(3, func() { Evaluate(Input{Rules: scan, Events: events}) }); allocs > 200000 {
		t.Fatalf("аллокаций на оценку %.0f — больше 200 тыс.", allocs)
	}
	write := func(body string) *rules.Rule {
		path := filepath.Join(t.TempDir(), "r.yml")
		if err := os.WriteFile(path, []byte(body), 0o644); err != nil {
			t.Fatal(err)
		}
		r, err := rules.LoadFile(path)
		if err != nil {
			t.Fatal(err)
		}
		return r
	}
	plain := write("title: flow\nid: t-flow\nlevel: low\ndetection:\n  selection: {source.class: netflow}\n  condition: selection\n  group_by: src.ip\ndedupe: 10m\n")
	count := write("title: burst\nid: t-burst\nlevel: low\ndetection:\n  selection: {source.class: netflow}\n  threshold: {kind: count, count: 100, window: 10m, group_by: src.ip}\n  condition: selection and threshold\n")
	runtime.GC()
	var before, after runtime.MemStats
	runtime.ReadMemStats(&before)
	dets, _ := Evaluate(Input{Rules: []*rules.Rule{plain, count}, Events: events})
	runtime.ReadMemStats(&after)
	n := map[string]int{}
	for _, d := range dets {
		n[d.Rule.ID]++
	}
	// без порога склейка — от начала сработки: 30 минут потока при окне 10m — 3 сработки
	if n["t-flow"] != 3 || n["t-burst"] != 1 {
		t.Fatalf("сработок: %v", n)
	}
	if mib := (after.TotalAlloc - before.TotalAlloc) >> 20; mib > 64 {
		t.Fatalf("выделено %d МиБ", mib)
	}
}
