package main

import (
	"testing"
	"time"

	"github.com/devitex-soft/argus/engine/internal/model"
)

func TestTrimBufferByAgeAndCap(t *testing.T) {
	now := time.Now()
	var buf []*model.Event
	for i := 0; i < 10; i++ {
		buf = append(buf, &model.Event{Action: "x", ReceivedAt: now.Add(time.Duration(i-10) * time.Minute)})
	}
	buf = append(buf, &model.Event{Action: "no-ts"})
	kept, evicted := trimBuffer(buf, now.Add(-5*time.Minute), 0)
	if evicted != 0 || len(kept) != 6 {
		t.Fatalf("по возрасту: kept=%d evicted=%d, ожидалось 6/0", len(kept), evicted)
	}
	kept, evicted = trimBuffer(kept, time.Time{}, 4)
	if evicted != 2 || len(kept) != 4 {
		t.Fatalf("по потолку: kept=%d evicted=%d, ожидалось 4/2", len(kept), evicted)
	}
	if kept[0].ReceivedAt.Before(now.Add(-3*time.Minute)) || kept[len(kept)-1].Action != "no-ts" {
		t.Fatalf("выброшены не самые старые: первый %v, последний %q", kept[0].ReceivedAt, kept[len(kept)-1].Action)
	}
	if kept, evicted = trimBuffer(nil, now, 1); len(kept) != 0 || evicted != 0 {
		t.Fatalf("пустой буфер: kept=%d evicted=%d", len(kept), evicted)
	}
}
