package main

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/devitex-soft/argus/engine/internal/eval"
	"github.com/devitex-soft/argus/engine/internal/incidents"
	"github.com/devitex-soft/argus/engine/internal/model"
	"github.com/devitex-soft/argus/engine/internal/store"
)

// The real flush/InsertEvents path runs against an in-process RoundTripper:
// no listening socket, database, or external connection. Tests using it are
// sequential because store.New uses http.DefaultTransport.
type pr111DeltaRulesEventSink struct {
	events       []*model.Event
	duringInsert func()
	failNext     bool
}

func (s *pr111DeltaRulesEventSink) RoundTrip(req *http.Request) (*http.Response, error) {
	if req.URL.Hostname() != "pr111-rules.invalid" || req.URL.Query().Get("query") != "INSERT INTO events FORMAT JSONEachRow" {
		return nil, fmt.Errorf("unexpected request in rules-event fixture: %s", req.URL.Path)
	}
	defer req.Body.Close()
	var batch []*model.Event
	dec := json.NewDecoder(req.Body)
	for {
		var ev model.Event
		if err := dec.Decode(&ev); err == io.EOF {
			break
		} else if err != nil {
			return nil, err
		}
		batch = append(batch, &ev)
	}
	// Deterministically run a reload after flush detached its pending batch,
	// but before INSERT returns. This models the HTTP reload interleaving
	// without scheduler timing or a goroutine left behind on test failure.
	if hook := s.duringInsert; hook != nil {
		s.duringInsert = nil
		hook()
	}
	status := http.StatusOK
	if s.failNext {
		s.failNext = false
		status = http.StatusServiceUnavailable
	} else {
		s.events = append(s.events, batch...)
	}
	return &http.Response{StatusCode: status, Header: make(http.Header), Body: io.NopCloser(strings.NewReader("")), Request: req}, nil
}

func pr111DeltaInstallRulesEventSink(t *testing.T) *pr111DeltaRulesEventSink {
	t.Helper()
	sink := &pr111DeltaRulesEventSink{}
	previous := http.DefaultTransport
	http.DefaultTransport = sink
	t.Cleanup(func() { http.DefaultTransport = previous })
	return sink
}

func pr111DeltaRulesEngine(t *testing.T, shippedFiles, userFiles map[string]string) *engine {
	t.Helper()
	ops, err := os.ReadFile(filepath.Join(repoRulesDir, "ops", "rules-rejected.yml"))
	if err != nil {
		t.Fatal(err)
	}
	files := make(map[string]string, len(shippedFiles)+1)
	for path, raw := range shippedFiles {
		files[path] = raw
	}
	files["ops.yml"] = string(ops)
	dirs := ruleSet{shipped: rulesDirWith(t, files), user: rulesDirWith(t, userFiles)}
	rs, rejected := loadForRun(dirs)
	e := &engine{
		dirs: dirs, rulesSig: dirs.signature(), reg: incidents.NewRegistry(0, nil),
		ch: store.New("http://pr111-rules.invalid", "argus", "fixture", ""),
	}
	e.rules.Store(&rs)
	e.m.rulesRejected.Store(int64(len(rejected)))
	e.noteRejected(rejected, rs, time.Now())
	return e
}

func pr111DeltaApplyRulesEvents(e *engine, events []*model.Event) {
	now := time.Now()
	detections, closers := eval.Evaluate(eval.Input{Rules: e.current(), Events: events, Now: now})
	e.reg.Apply(detections, now)
	for _, c := range closers {
		e.reg.Close(c.Rule.ID, c.Key, "fixture: recovered", c.Event.Time(), now)
	}
}

func TestPR111DeltaRecoveryBeforeRejectionIsIngested(t *testing.T) {
	for _, origin := range []string{"shipped", "user"} {
		t.Run(origin, func(t *testing.T) {
			for _, timing := range []string{"before_flush", "during_insert", "during_failed_insert", "after_insert", "after_ingest_control"} {
				t.Run(timing, func(t *testing.T) {
					sink := pr111DeltaInstallRulesEventSink(t)
					shippedGood := simpleRule("pr111-recovery-shipped", "shipped.action")
					userGood := simpleRule("pr111-recovery-user", "user.action")
					e := pr111DeltaRulesEngine(t,
						map[string]string{"protected.yml": shippedGood},
						map[string]string{"custom.yml": userGood})
					path, good := filepath.Join(e.dirs.shipped, "protected.yml"), shippedGood
					bad, object := shippedGood+"  group_by_next: attrs.peer\n", "shipped/protected.yml"
					if origin == "user" {
						path, good = filepath.Join(e.dirs.user, "custom.yml"), userGood
						bad, object = simpleRule("pr111-recovery-shipped", "override.action"), "user/custom.yml"
					}
					if err := os.WriteFile(path, []byte(bad), 0o600); err != nil {
						t.Fatal(err)
					}
					if rejected := e.maybeReload(true); len(rejected) != 1 || rejectKey(rejected[0]) != object {
						t.Fatalf("expected one rejection for %s: %+v", object, rejected)
					}
					// Model the rejection from a previous poll, avoiding an unrelated
					// equal-millisecond rejection/recovery timestamp in this test.
					for _, ev := range e.rulesPending {
						ev.TS = model.FormatTS(time.Now().Add(-time.Minute))
					}
					repair := func() {
						if err := os.WriteFile(path, []byte(good), 0o600); err != nil {
							t.Fatal(err)
						}
						if rejected := e.maybeReload(true); len(rejected) != 0 || e.m.rulesRejected.Load() != 0 {
							t.Fatalf("repair must load successfully: rejected=%+v gauge=%d", rejected, e.m.rulesRejected.Load())
						}
					}
					ctx := context.Background()
					switch timing {
					case "before_flush":
						repair()
					case "during_insert", "during_failed_insert":
						sink.duringInsert = repair
						sink.failNext = timing == "during_failed_insert"
					}
					e.flushRulesEvents(ctx)
					if timing == "during_failed_insert" {
						if len(e.rulesPending) == 0 {
							t.Fatal("failed INSERT must leave the original rejection queued for retry")
						}
						e.flushRulesEvents(ctx)
					}
					if timing == "after_ingest_control" {
						pr111DeltaApplyRulesEvents(e, sink.events)
						if e.reg.OpenByRule("a41c-ops-068") == nil {
							t.Fatal("control must create the rejection incident before repair")
						}
					}
					if timing == "after_insert" || timing == "after_ingest_control" {
						repair()
					}
					// The loop polls and applies the inserted events on a later tick.
					// Subsequent unchanged signatures must not strand a stale alarm.
					for tick := 0; tick < 3; tick++ {
						e.maybeReload(false)
						e.flushRulesEvents(ctx)
						pr111DeltaApplyRulesEvents(e, sink.events)
					}
					if len(sink.events) == 0 {
						t.Fatal("fixture did not deliver the queued rejection")
					}
					if open := e.reg.OpenByRule("a41c-ops-068"); open != nil {
						t.Fatalf("%s is repaired and rejection gauge is zero, but incident %s for %s stays open after %s; recovery was lost before the registry observed the rejection", origin, open.IncidentID, open.GroupKey, timing)
					}
				})
			}
		})
	}
}
