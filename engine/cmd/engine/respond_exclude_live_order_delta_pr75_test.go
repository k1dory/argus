package main

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/devitex-soft/argus/engine/internal/incidents"
	"github.com/devitex-soft/argus/engine/internal/store"
)

// A renewal INSERT commits, but its acknowledgement arrives after an acknowledged
// revoke. The live state must obey the same timestamp/revoke ordering as replay.
// Run the revoke from the journal fixture before replying to the renewal, so the
// interleaving needs neither sleeps nor a scheduler-dependent race.
func TestDeltaPR75DelayedExcludeAckCannotOverwriteRevoke(t *testing.T) {
	f := newFakeCH(t)
	x := newKeyExecutor(t)
	x.available.Store(true)
	e := keyEngine(t, f, x, 4)
	ctx := context.Background()
	now := time.Now().UTC().Truncate(time.Second)
	if !e.restoreKeys(ctx, now) {
		t.Fatal("fixture: initial restore failed")
	}
	initial := exclusion{at: now.Add(-time.Hour), until: now.Add(time.Hour)}
	e.setExclusion("203.0.113.7", initial)
	if err := e.ch.InsertResponses(ctx, []store.ResponseRow{
		excludeRow("203.0.113.7", "qa", "initial window", initial.at, initial.until),
	}); err != nil {
		t.Fatal(err)
	}
	type reply struct {
		code int
		body string
	}
	revoked := make(chan reply, 1)
	var intercepted atomic.Bool
	journal := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, err := io.ReadAll(r.Body)
		if err != nil {
			http.Error(w, "fixture: read request", http.StatusBadRequest)
			return
		}
		r.Body = io.NopCloser(strings.NewReader(string(body)))
		f.srv.Config.Handler.ServeHTTP(w, r)
		if strings.HasPrefix(r.URL.Query().Get("query"), "INSERT INTO response_log ") &&
			strings.Contains(string(body), `"reason":"renewed scanner window"`) && intercepted.CompareAndSwap(false, true) {
			code, out := do(t, e.handler(), http.MethodPost, "/respond/exclude/revoke", "s",
				`{"ip":"203.0.113.7","user":"qa","reason":"scanner no longer trusted"}`)
			revoked <- reply{code, out}
		}
	}))
	t.Cleanup(journal.Close)
	e.ch = store.New(journal.URL, "argus", "default", "")
	code, out := do(t, e.handler(), http.MethodPost, "/respond/exclude", "s",
		`{"ip":"203.0.113.7","ttl":"720h","user":"qa","reason":"renewed scanner window"}`)
	if code != http.StatusOK {
		t.Fatalf("fixture: renewal failed: HTTP %d %s", code, out)
	}
	select {
	case res := <-revoked:
		if res.code != http.StatusOK {
			t.Fatalf("fixture: revoke failed: HTTP %d %s", res.code, res.body)
		}
	default:
		t.Fatal("fixture: revoke was not acknowledged before the renewal")
	}
	e.autoRespond(ctx, []*incidents.Incident{capInc("INC-751", "203.0.113.7")}, time.Now())
	if x.blocks.Load() != 1 {
		t.Errorf("delayed renewal resurrected a revoked exclusion: blocks=%d, key=%q, excluded=%v",
			x.blocks.Load(), keyState(e, "INC-751", "203.0.113.7"), e.exclusions(time.Now()))
	}
	// The identical durable decisions already produce the opposite result on
	// restart: the revoke wins even when its timestamp equals the renewal's.
	saveJournal(f)
	restarted := keyEngine(t, f, x, 4)
	before := x.blocks.Load()
	restarted.autoRespond(ctx, []*incidents.Incident{capInc("INC-752", "203.0.113.7")}, time.Now())
	if x.blocks.Load() != before+1 {
		t.Fatal("replay must also preserve the acknowledged revoke")
	}
}

// A local grant made during startup and a durable revoke in the same DateTime
// second must resolve to revoke, just like two rows inside one SELECT result.
func TestDeltaPR75SnapshotRevokeWinsEqualTimestampLocalGrant(t *testing.T) {
	f := newFakeCH(t)
	x := newKeyExecutor(t)
	x.available.Store(true)
	e := keyEngine(t, f, x, 4)
	now := time.Now().UTC().Truncate(time.Second)
	at := now.Add(-time.Second)
	e.setExclusion("203.0.113.7", exclusion{at: at, until: at.Add(excludeMaxTTL)})
	row, err := json.Marshal(excludeRow("203.0.113.7", "qa", "revoked", at, at))
	if err != nil {
		t.Fatal(err)
	}
	f.mu.Lock()
	f.selects["FROM response_log WHERE ip != ''"] = string(row) + "\n"
	f.mu.Unlock()
	e.autoRespond(context.Background(), []*incidents.Incident{capInc("INC-753", "203.0.113.7")}, now)
	if x.blocks.Load() != 1 {
		t.Fatalf("local grant defeated the equal-timestamp revoke: blocks=%d, exclusions=%v", x.blocks.Load(), e.exclusions(now))
	}
}
