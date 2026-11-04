package rules

import (
	"fmt"
	"strings"
	"testing"
)

// A user catalogue can contain many small files with one non-shipped ID.
// DedupeIDs keeps every rejection until loading/reloading finishes. Diagnostics
// must not copy the entire collision group into every rejected file's error:
// thousands of otherwise tiny rules then consume gigabytes before detection
// can start. Measure returned bytes on small fixtures, without provoking OOM
// or relying on elapsed time, GC, or the machine's available memory.
func TestPR111DeltaDuplicateDiagnosticsGrowLinearly(t *testing.T) {
	for _, active := range []bool{false, true} {
		name := "startup"
		if active {
			name = "reload"
		}
		t.Run(name, func(t *testing.T) {
			measure := func(n int) int {
				t.Helper()
				rs := make([]*Rule, n)
				for i := range rs {
					rs[i] = &Rule{
						ID: "pr111-user-duplicate", User: true,
						File: fmt.Sprintf("user/%04d-%s.yml", i, strings.Repeat("x", 96)),
					}
				}
				var previous map[string]string
				if active {
					previous = map[string]string{rs[0].ID: rs[n-1].File}
				}
				kept, rejected := DedupeIDs(rs, previous)
				winner := rs[0]
				if active {
					winner = rs[n-1]
				}
				if len(kept) != 1 || kept[0] != winner || len(rejected) != n-1 {
					t.Fatalf("deduplication: kept=%d rejected=%d, want one winner and %d rejections", len(kept), len(rejected), n-1)
				}
				bytes := 0
				for _, re := range rejected {
					if re.Reason != "duplicate_id" || re.Err == nil {
						t.Fatalf("unexpected rejection: %+v", re)
					}
					bytes += len(re.Err.Error())
				}
				return bytes
			}
			small, large := measure(32), measure(64)
			// Doubling same-length paths permits 3x for fixed per-file overhead,
			// but not the approximately 4x amplification of a quadratic output.
			if large > 3*small {
				t.Fatalf("doubling duplicate files grows retained diagnostic text from %d to %d bytes; user rules must not amplify memory quadratically", small, large)
			}
		})
	}
}
