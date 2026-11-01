package main

import (
	"fmt"
	"testing"
	"time"

	"github.com/devitex-soft/argus/collector/internal/listen"
	"github.com/devitex-soft/argus/collector/internal/normalize"
)

// Expiring entries after one minute does not bound memory within that minute.
// Use a small in-process batch, no sockets or exhaustion attempt. 4096 is an
// explicit test-only safety budget for this diagnostic cache; production has
// no size cap at all. A smaller production cap is also acceptable.
func TestPR44ReReviewUndeclaredWarningsHaveCapacityBeforeTTL(t *testing.T) {
	count := pr44IsolateWarnings(t)
	savedStores := undeclaredStores.Load()
	undeclaredStores.Store(0)
	t.Cleanup(func() { undeclaredStores.Store(savedStores) })

	const maxRememberedPeers = 4096
	const senders = maxRememberedPeers + 64
	started := time.Now()
	n := &normalize.Normalizer{}
	for i := 0; i < senders; i++ {
		// All addresses are in the benchmarking-only 198.18.0.0/15 range.
		peer := listen.Peer{Addr: fmt.Sprintf("198.18.%d.%d", i/256, i%256), Transport: "udp"}
		e, ok := parseSyslogLine(n, nil, pr44CEF, peer)
		if !ok || e.SourceClass != "syslog" {
			t.Fatalf("sender %d: undeclared record was not retained as syslog", i)
		}
	}
	if undeclaredFormatTotal.Load() != senders {
		t.Fatalf("capacity limiting must preserve the metric: got %d, want %d", undeclaredFormatTotal.Load(), senders)
	}
	entries := 0
	undeclaredWarned.Range(func(_, _ any) bool {
		entries++
		return true
	})
	// Do not mistake expiry on an exceptionally slow machine for a capacity
	// limit. No sleep or artificial timestamp aging is used in this test.
	if time.Since(started) >= time.Minute {
		t.Skip("fixture crossed the TTL; cannot validate capacity within one minute")
	}
	if entries > maxRememberedPeers {
		t.Fatalf("warning cache retained %d fresh source IPs (budget %d, warnings %d); TTL sweeps do not cap a burst within one minute", entries, maxRememberedPeers, count.Load())
	}
}
