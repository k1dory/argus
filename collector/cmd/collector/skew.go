package main

import (
	"log/slog"
	"math"
	"os"
	"sort"
	"strconv"
	"sync"
	"sync/atomic"
	"time"

	"github.com/devitex-soft/argus/collector/internal/model"
)

// Часы источника в будущем. RFC 3164 без пояса (QNAP, коммутаторы) при ошибке пояса
// пишет время на часы вперёд: событие на это время выпадает из окон правил (движок
// смотрит назад от «сейчас»). Если ts дальше COLLECTOR_CLOCK_SKEW_MAX (10m; 0 —
// выключено) от момента приёма, ts = время приёма, исходное — в attrs.ts_original.
// Значение ts_original из тела события не принимается никогда (его ставит только
// коллектор, как transport). Счётчик — argus_collector_clock_skew_total; раз в
// минуту по каждому отправителю с расхождением — событие argus.collector /
// collector.clock_skew (attrs.peer, attrs.source, attrs.count, value — наибольшее
// расхождение в секундах). Дальше суток в будущем ts и раньше заменял Ensure
// (attrs.ts_raw) — там ts уже «сейчас», и сюда такое событие не попадает.

const defaultClockSkewMax = 10 * time.Minute

func clockSkewMax() time.Duration {
	v := os.Getenv("COLLECTOR_CLOCK_SKEW_MAX")
	if v == "" {
		return defaultClockSkewMax
	}
	d, err := time.ParseDuration(v)
	if err != nil || d < 0 {
		slog.Warn("COLLECTOR_CLOCK_SKEW_MAX: ожидалась длительность (10m, 0 — выключено), взято по умолчанию", "value", v)
		return defaultClockSkewMax
	}
	return d
}

// skewPeersMax — потолок отправителей в сводке за минуту: сверх — в «прочие».
const skewPeersMax = 256

type skewPeer struct {
	source  string
	count   uint64
	maxSkew time.Duration
}

type skewWatch struct {
	max   time.Duration
	total atomic.Uint64
	mu    sync.Mutex
	peers map[string]*skewPeer
}

func newSkewWatch(max time.Duration) *skewWatch {
	return &skewWatch{max: max, peers: map[string]*skewPeer{}}
}

// apply — проверить ts события относительно момента приёма now.
func (w *skewWatch) apply(e *model.Event, now time.Time) {
	if e.Attrs != nil {
		delete(e.Attrs, "ts_original")
	}
	if w == nil || w.max <= 0 {
		return
	}
	t, ok := model.ParseTS(e.TS)
	if !ok {
		return
	}
	skew := t.Sub(now)
	if skew <= w.max {
		return
	}
	if e.Attrs == nil {
		e.Attrs = map[string]string{}
	}
	e.Attrs["ts_original"] = e.TS
	e.TS = model.FormatTS(now)
	w.total.Add(1)
	peer := e.Attrs["peer"]
	if peer == "" {
		peer = e.Attrs["transport"] + ":" + e.Source
	}
	w.mu.Lock()
	defer w.mu.Unlock()
	p := w.peers[peer]
	if p == nil {
		if len(w.peers) >= skewPeersMax {
			peer = "other"
			if p = w.peers[peer]; p == nil {
				p = &skewPeer{source: "*"}
				w.peers[peer] = p
			}
		} else {
			p = &skewPeer{source: e.Source}
			w.peers[peer] = p
		}
	}
	p.count++
	p.maxSkew = max(p.maxSkew, skew)
}

// flush — события сводки за прошедший интервал (по отправителю) и сброс.
func (w *skewWatch) flush(now time.Time) []model.Event {
	if w == nil {
		return nil
	}
	w.mu.Lock()
	peers := w.peers
	w.peers = map[string]*skewPeer{}
	w.mu.Unlock()
	names := make([]string, 0, len(peers))
	for name := range peers {
		names = append(names, name)
	}
	sort.Strings(names)
	out := make([]model.Event, 0, len(names))
	for _, name := range names {
		p := peers[name]
		e := model.Event{
			TS: model.FormatTS(now), Source: "argus.collector", SourceClass: "telemetry", Vendor: "ARGUS", Product: "collector",
			Action: "collector.clock_skew", Outcome: "failure", ActorName: "argus-collector", ActorKind: "system", Node: "argus-collector",
			Value: math.Round(p.maxSkew.Seconds()), Unit: "seconds", Severity: 4,
			Attrs: map[string]string{
				"peer": name, "source": p.source, "count": strconv.FormatUint(p.count, 10),
				"threshold_sec": strconv.Itoa(int(w.max.Seconds())), "transport": "internal",
			},
		}
		e.Sanitize()
		out = append(out, e)
		slog.Warn("часы источника впереди: ts заменён временем приёма", "peer", name, "source", p.source, "events", p.count, "max_skew", p.maxSkew.Round(time.Second))
	}
	return out
}
