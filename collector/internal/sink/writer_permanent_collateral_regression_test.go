package sink

import (
	"context"
	"encoding/json"
	"fmt"
	"testing"

	"github.com/devitex-soft/argus/collector/internal/model"
)

type pr43PoisonInserter struct {
	code     int
	accepted map[string]int
	rejected []Reject
}

func (s *pr43PoisonInserter) InsertEvents(_ context.Context, rows []any) error {
	for _, row := range rows {
		if row.(model.Event).Attrs["fixture_poison"] == "1" {
			return &Error{Table: "events", Status: 400, Code: s.code, Msg: "fixture row rejected"}
		}
	}
	for _, row := range rows {
		s.accepted[row.(model.Event).Object]++
	}
	return nil
}

func (s *pr43PoisonInserter) InsertRejects(_ context.Context, rows []Reject) error {
	s.rejected = append(s.rejected, rows...)
	return nil
}

// The permanent-error ceiling predates PR #43 and is explicitly retained by it.
// This regression states the data-preservation invariant that ceiling violates:
// one poison event in each half must not discard all the unrelated valid events.
// Test both the minimum mixed batch and the configured default batch size (500).
func TestPR43PermanentErrorsPreserveHealthyNeighbours(t *testing.T) {
	for _, code := range []int{27, 6, 53, 117} {
		for _, size := range []int{4, 500} {
			t.Run(fmt.Sprintf("code=%d/rows=%d", code, size), func(t *testing.T) {
				stats := &Stats{}
				ins := &pr43PoisonInserter{code: code, accepted: make(map[string]int)}
				writer := NewWriter(ins, NewQueue(1000, stats), stats)
				rows := make([]any, size)
				for i := range rows {
					e := model.Event{Source: "pr43-poison", Object: fmt.Sprintf("event-%d", i)}
					e.Ensure()
					if i == 0 || i == size/2 {
						e.Attrs["fixture_poison"] = "1"
					}
					rows[i] = e
				}
				writer.Write(context.Background(), rows)
				validInserted, validRejected := 0, 0
				for _, row := range rows {
					e := row.(model.Event)
					if e.Attrs["fixture_poison"] != "1" && ins.accepted[e.Object] == 1 {
						validInserted++
					}
				}
				for _, reject := range ins.rejected {
					var e model.Event
					if err := json.Unmarshal([]byte(reject.Raw), &e); err != nil {
						t.Fatal(err)
					}
					if e.Attrs["fixture_poison"] != "1" {
						validRejected++
					}
				}
				if validInserted != size-2 || validRejected != 0 {
					t.Errorf("two poison events displaced healthy events: inserted=%d/%d healthy_rejects=%d", validInserted, size-2, validRejected)
				}
				if stats.Inserted.Load() != uint64(size-2) || stats.DeadLetter.Load() != 2 || len(ins.rejected) != 2 {
					t.Errorf("only the two poison rows may be rejected: inserted=%d dead=%d rejects=%d", stats.Inserted.Load(), stats.DeadLetter.Load(), len(ins.rejected))
				}
			})
		}
	}
}
