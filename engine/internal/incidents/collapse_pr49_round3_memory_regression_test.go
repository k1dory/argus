package incidents

import (
	"runtime"
	"testing"
	"time"
	"weak"

	"github.com/devitex-soft/argus/engine/internal/eval"
	"github.com/devitex-soft/argus/engine/internal/model"
)

// Keep the original detection and its slice out of the caller's stack frame.
// Weak references observe whether discarded Event objects remain reachable
// through the registry, without themselves retaining those objects.
//
//go:noinline
func pr49Round3RetentionFixture(t *testing.T) (*Registry, []weak.Pointer[model.Event]) {
	t.Helper()
	r := pr49CollapsedRule("scan")
	now := time.Date(2026, 11, 1, 10, 0, 0, 0, time.UTC)
	d := pr49Detection(r, "203.0.113.7", now, maxCollapsedEvents+257)
	refs := make([]weak.Pointer[model.Event], len(d.Events))
	for i, ev := range d.Events {
		refs[i] = weak.Make(ev)
	}
	reg := NewRegistry(0, nil)
	created, _, _ := reg.Apply([]eval.Detection{d}, d.Last)
	if len(created) != 1 || len(created[0].Events) > maxCollapsedEvents {
		t.Fatal("fixture must reach the advertised event-retention budget")
	}
	return reg, refs
}

// Return only a count, so temporary strong pointers from Value cannot survive
// across the next GC through a caller-side loop variable.
//
//go:noinline
func pr49Round3LiveEvents(refs []weak.Pointer[model.Event]) int {
	n := 0
	for _, ref := range refs {
		if ref.Value() != nil {
			n++
		}
	}
	return n
}

// Trimming len(part.events) is insufficient if the slice still points inside
// the original pointer array. GC scans that array, including the discarded
// prefix, and retains the corresponding events after the input buffer is gone.
// Event contains pointers and is much larger than the tiny-allocation class.
func TestPR49Round3DiscardedEventsAreCollectible(t *testing.T) {
	reg, refs := pr49Round3RetentionFixture(t)
	live := 0
	for i := 0; i < 5; i++ {
		runtime.GC()
		live = pr49Round3LiveEvents(refs)
		if live <= maxCollapsedEvents {
			break
		}
	}
	runtime.KeepAlive(reg)
	if live > maxCollapsedEvents {
		t.Fatalf("registry still retains %d Event objects after GC despite a %d-event cap; trimming a slice kept its discarded prefix alive",
			live, maxCollapsedEvents)
	}
}
