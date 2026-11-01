package main

import (
	"context"
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/devitex-soft/argus/engine/internal/incidents"
	"github.com/devitex-soft/argus/engine/internal/store"
)

// Exclude and revoke can both commit within one DateTime second. ClickHouse
// ORDER BY ts does not order ties by insertion time. Replaying either valid
// ordering of the same journal must preserve the acknowledged revocation.
func TestReviewPR75ExcludeRevokeSameSecondSurvivesReorderedJournal(t *testing.T) {
	for _, reverse := range []bool{false, true} {
		name := "insertion_order"
		if reverse {
			name = "reversed_equal_timestamps"
		}
		t.Run(name, func(t *testing.T) {
			f := newFakeCH(t)
			x := newKeyExecutor(t)
			x.available.Store(true)
			now := time.Now().UTC().Truncate(time.Second)
			at := now.Add(-time.Minute)
			grant := excludeRow("203.0.113.7", "qa", "approved scanner window", at, at.Add(excludeMaxTTL))
			revoke := excludeRow("203.0.113.7", "qa", "scanner window revoked", at, at)
			journal := []store.ResponseRow{grant, revoke}
			if reverse {
				journal[0], journal[1] = journal[1], journal[0]
			}
			var lines []string
			for _, row := range journal {
				b, err := json.Marshal(row)
				if err != nil {
					t.Fatal(err)
				}
				lines = append(lines, string(b))
			}
			f.mu.Lock()
			f.selects["FROM response_log WHERE ip != ''"] = strings.Join(lines, "\n") + "\n"
			f.mu.Unlock()
			e := keyEngine(t, f, x, 4)
			e.autoRespond(context.Background(), []*incidents.Incident{capInc("INC-75", "203.0.113.7")}, now)
			if x.blocks.Load() != 1 {
				t.Fatalf("a revoked exclusion disabled a new incident after restart: blocks=%d, key=%q, exclusions=%v",
					x.blocks.Load(), keyState(e, "INC-75", "203.0.113.7"), e.exclusions(now))
			}
		})
	}
}
