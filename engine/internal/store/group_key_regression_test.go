package store

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/devitex-soft/argus/engine/internal/incidents"
)

// incidents_current intentionally has no group_key in migration 0034.
// These two persisted incidents therefore look identical until their keys
// are read from incidents. A failed read must not turn them into legacy rows:
// NewRegistry would otherwise keep only one of the two under the same key.
func TestGroupKeyRestoreFailureMustNotSeedLegacyRegistry(t *testing.T) {
	for _, tc := range []struct {
		name   string
		status int
		body   string
	}{
		{"http_error", http.StatusInternalServerError, "Code: 241. DB::Exception: Memory limit exceeded"},
		{"streamed_error", http.StatusOK, "Code: 159. DB::Exception: Timeout exceeded"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				body, err := io.ReadAll(r.Body)
				if err != nil {
					t.Errorf("read ClickHouse request: %v", err)
					http.Error(w, "request read failed", http.StatusBadRequest)
					return
				}
				query := string(body)
				if strings.Contains(query, "group_key") {
					w.WriteHeader(tc.status)
					fmt.Fprintln(w, tc.body)
					return
				}
				if strings.Contains(query, "FROM incidents_current") {
					fmt.Fprintln(w, `{"incident_id":"INC-7","rule_id":"nas-storage-failure","actor_name":"System","node":"QNAP-2","status":"new","event_count":1,"first_ts":"2026-10-30 12:00:00.000","last_ts":"2026-10-30 12:00:00.000"}`)
					fmt.Fprintln(w, `{"incident_id":"INC-8","rule_id":"nas-storage-failure","actor_name":"System","node":"QNAP-2","status":"new","event_count":1,"first_ts":"2026-10-30 12:01:00.000","last_ts":"2026-10-30 12:01:00.000"}`)
					return
				}
				t.Errorf("unexpected ClickHouse query: %s", query)
				http.Error(w, "unexpected query", http.StatusBadRequest)
			}))
			defer srv.Close()
			open, _, err := New(srv.URL, "argus", "", "").OpenIncidents(context.Background())
			if err == nil {
				t.Fatalf("failed group_key read must fail restoration so startup can retry; returned %d legacy-looking incidents with no error: %+v", len(open), open)
			}
		})
	}
}

// Exercise the actual migration and production InsertIncidents/OpenIncidents
// SQL as well as Registry restoration; copying a struct with GroupKey set
// does not verify that the key survives the database boundary.
func TestLiveGroupKeyRoundTripPreservesIndependentIncidents(t *testing.T) {
	c := liveStore(t)
	applyMigrations(t, c)
	ctx := context.Background()
	sfx := suffix(t)
	firstN := 900000000 + int(time.Now().UnixNano()%90000000)
	rule := "group_key.live." + sfx
	node := "QNAP-" + sfx
	now := time.Now().UTC().Truncate(time.Second)
	first := inc(fmt.Sprintf("INC-%d", firstN), rule, incidents.StatusNew, "high", "System", node, now.Add(-time.Hour))
	second := inc(fmt.Sprintf("INC-%d", firstN+1), rule, incidents.StatusNew, "high", "System", node, now.Add(-30*time.Minute))
	legacy := inc(fmt.Sprintf("INC-%d", firstN+2), rule, incidents.StatusNew, "high", "System", "legacy-"+sfx, now.Add(-2*time.Hour))
	first.GroupKey, second.GroupKey = node+"|disk3", node+"|disk4"
	if err := c.InsertIncidents(ctx, []*incidents.Incident{first, second, legacy}); err != nil {
		t.Fatal(err)
	}
	open, maxN, err := c.OpenIncidents(ctx)
	if err != nil {
		t.Fatal(err)
	}
	want := map[string]string{first.IncidentID: first.GroupKey, second.IncidentID: second.GroupKey, legacy.IncidentID: ""}
	var restored []incidents.Incident
	for _, row := range open {
		key, ours := want[row.IncidentID]
		if !ours {
			continue
		}
		if row.GroupKey != key {
			t.Errorf("restored %s group_key=%q, want %q", row.IncidentID, row.GroupKey, key)
		}
		restored = append(restored, row)
	}
	if len(restored) != len(want) {
		t.Fatalf("restored %d of %d fixture incidents", len(restored), len(want))
	}
	reg := incidents.NewRegistry(maxN, restored)
	for _, original := range []*incidents.Incident{first, second} {
		closed := reg.Close(rule, original.GroupKey, "disk recovered", now.Add(time.Minute), now.Add(time.Minute))
		if closed == nil || closed.IncidentID != original.IncidentID {
			t.Errorf("restarted registry must resolve group %q to %s, got %+v", original.GroupKey, original.IncidentID, closed)
		}
	}
}
