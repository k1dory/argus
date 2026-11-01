package main

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/devitex-soft/argus/engine/internal/model"
)

func pr49FollowupRules(t *testing.T, names ...string) map[string]string {
	t.Helper()
	files := make(map[string]string, len(names))
	for _, name := range names {
		raw, err := os.ReadFile(filepath.Join("..", "..", "..", "rules", name))
		if err != nil {
			t.Fatal(err)
		}
		files[name] = string(raw)
	}
	return files
}

func pr49FollowupSaveResponses(f *fakeCH) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.selects["FROM response_log"] = strings.Join(f.inserts["response_log"], "\n") + "\n"
}

// A real shipped rule reaches its threshold at 50 ports, but evaluation
// returns the entire batch. Exceeding the incident's display/memory budget
// must not silently remove the only source address from autoRespond.
func TestPR49FollowupLargeScanStillBlocksSource(t *testing.T) {
	f := newFakeCH(t)
	srv, blocks := pr49NGFW(t)
	e := testEngine(t, f, rulesDirWith(t, pr49FollowupRules(t, "net-inbound-portscan.yml")), ipsConfig(srv), "fixture", "fixture")
	now := time.Date(2026, 11, 1, 10, 5, 0, 0, time.UTC)
	const ip = "203.0.113.7"
	var events []*model.Event
	for i := 0; i < 2001; i++ {
		ev := flow(model.FormatTS(now.Add(-3*time.Second+time.Duration(i)*time.Millisecond)), ip, uint16(1000+i))
		ev.Attrs["syn_only"] = "1"
		events = append(events, ev)
	}
	created, _ := e.applyEvents(events, now)
	if len(created) != 1 || created[0].EventCount != 2001 || len(created[0].Members) != 1 {
		t.Fatalf("fixture must detect one 2001-event port scan: %+v", created)
	}
	e.autoRespond(context.Background(), snapshotIncidents(created), now)
	if got := blocks.Load(); got != 1 {
		t.Fatalf("qualifying scanner must be blocked once, got %d; retained events=%d, decision=%q",
			got, len(created[0].Events), e.respStatus(created[0].IncidentID+"|"+ip))
	}
}
