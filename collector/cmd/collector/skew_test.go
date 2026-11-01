package main

import (
	"fmt"
	"testing"
	"time"

	"github.com/devitex-soft/argus/collector/internal/model"
)

func TestSkewWatchReplacesFutureTimestamp(t *testing.T) {
	now := time.Date(2026, 11, 1, 12, 0, 0, 0, time.UTC)
	w := newSkewWatch(10 * time.Minute)
	ev := func(ts, peer string, attrs ...string) *model.Event {
		e := &model.Event{TS: ts, Source: "nas.qnap", Attrs: map[string]string{"transport": "tcp"}}
		if peer != "" {
			e.Attrs["peer"] = peer
		}
		for i := 0; i+1 < len(attrs); i += 2 {
			e.Attrs[attrs[i]] = attrs[i+1]
		}
		return e
	}
	future := ev("2026-11-01 15:00:00.000", "192.168.0.59:40000")
	w.apply(future, now)
	if future.TS != "2026-11-01 12:00:00.000" || future.Attrs["ts_original"] != "2026-11-01 15:00:00.000" {
		t.Fatalf("+3 ч: ts=%s ts_original=%q", future.TS, future.Attrs["ts_original"])
	}
	edge := ev("2026-11-01 12:10:00.000", "192.168.0.59:40000")
	w.apply(edge, now)
	if edge.TS != "2026-11-01 12:10:00.000" || edge.Attrs["ts_original"] != "" {
		t.Fatal("ровно на пороге — не трогается")
	}
	past := ev("2026-11-01 09:00:00.000", "", "ts_original", "spoofed")
	w.apply(past, now)
	if past.TS != "2026-11-01 09:00:00.000" {
		t.Fatal("прошлое не трогается")
	}
	if _, ok := past.Attrs["ts_original"]; ok {
		t.Fatal("ts_original из тела события не принимается")
	}
	w.apply(ev("2026-11-01 13:00:00.000", "192.168.0.59:40000"), now)
	w.apply(ev("2026-11-01 14:00:00.000", "", "source_hint", "x"), now)
	if w.total.Load() != 3 {
		t.Fatalf("счётчик: %d", w.total.Load())
	}
	events := w.flush(now)
	if len(events) != 2 {
		t.Fatalf("сводка по отправителям: %d", len(events))
	}
	byPeer := map[string]model.Event{}
	for _, e := range events {
		byPeer[e.Attrs["peer"]] = e
		if e.Source != "argus.collector" || e.Action != "collector.clock_skew" || e.Attrs["transport"] != "internal" || e.Attrs["threshold_sec"] != "600" || e.Object != e.Attrs["peer"]+" ("+e.Attrs["source"]+")" || e.Node != "argus-collector" {
			t.Fatalf("событие телеметрии: %+v", e)
		}
	}
	if q := byPeer["192.168.0.59:40000"]; q.Attrs["count"] != "2" || q.Value != 3*3600 || q.Attrs["source"] != "nas.qnap" {
		t.Fatalf("сводка QNAP: %+v", q)
	}
	if h := byPeer["tcp:nas.qnap"]; h.Attrs["count"] != "1" {
		t.Fatalf("без peer — по транспорту и источнику: %+v", byPeer)
	}
	if len(w.flush(now)) != 0 {
		t.Fatal("после сводки счётчики по отправителям сброшены")
	}
}

func TestSkewWatchDisabledAndPeerCap(t *testing.T) {
	now := time.Date(2026, 11, 1, 12, 0, 0, 0, time.UTC)
	off := newSkewWatch(0)
	e := &model.Event{TS: "2026-11-01 18:00:00.000", Attrs: map[string]string{"ts_original": "spoofed"}}
	off.apply(e, now)
	if e.TS != "2026-11-01 18:00:00.000" || e.Attrs["ts_original"] != "" {
		t.Fatalf("выключено: ts не меняется, но присланный ts_original всё равно убран: %+v", e)
	}
	w := newSkewWatch(time.Minute)
	for i := 0; i < skewPeersMax+10; i++ {
		w.apply(&model.Event{TS: "2026-11-01 13:00:00.000", Source: "s", Attrs: map[string]string{"peer": fmt.Sprintf("10.0.%d.%d:514", i/250, i%250)}}, now)
	}
	events := w.flush(now)
	if len(events) != skewPeersMax+1 {
		t.Fatalf("потолок отправителей: %d", len(events))
	}
	other := 0
	for _, e := range events {
		if e.Attrs["peer"] == "other" {
			other++
			if e.Attrs["count"] != "10" {
				t.Fatalf("прочие: %+v", e.Attrs)
			}
		}
	}
	if other != 1 {
		t.Fatal("сверх потолка — одна строка «other»")
	}
}

func TestClockSkewMaxEnv(t *testing.T) {
	for v, want := range map[string]time.Duration{"": defaultClockSkewMax, "5m": 5 * time.Minute, "0": 0, "soon": defaultClockSkewMax, "-1m": defaultClockSkewMax} {
		t.Setenv("COLLECTOR_CLOCK_SKEW_MAX", v)
		if got := clockSkewMax(); got != want {
			t.Errorf("%q: %s", v, got)
		}
	}
}
