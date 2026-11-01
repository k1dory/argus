package main

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/devitex-soft/argus/engine/internal/eval"
	"github.com/devitex-soft/argus/engine/internal/incidents"
	"github.com/devitex-soft/argus/engine/internal/model"
	"github.com/devitex-soft/argus/engine/internal/rules"
	"github.com/devitex-soft/argus/engine/internal/store"
)

type pr25ReviewTransport func(*http.Request) (*http.Response, error)

func (f pr25ReviewTransport) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }

// Use the real writeIncidents and ClickHouse client, without an OS listener.
func TestPR25RejectedEscalationWriteAcknowledgement(t *testing.T) {
	for _, status := range []string{incidents.StatusEscalated, incidents.StatusInProgress, incidents.StatusWaitingOwner, incidents.StatusObserving} {
		t.Run(status, func(t *testing.T) {
			start := time.Date(2026, 10, 30, 12, 0, 0, 0, time.UTC)
			rule := &rules.Rule{ID: "pr25-review", Title: "review fixture", Level: "high"}
			rule.Detection.GroupBy = "actor.name, src.ip"
			event := &model.Event{TS: model.FormatTS(start), Source: "test", ActorName: "admin", Node: "NAS-A", SrcIP: "192.0.2.10"}
			dets := []eval.Detection{{Rule: rule, Key: "admin|192.0.2.10", Events: []*model.Event{event}, First: start, Last: start}}
			legacy := incidents.Incident{IncidentID: "INC-7", RuleID: rule.ID, Status: incidents.StatusNew, ActorName: event.ActorName, Node: event.Node,
				EventCount: 1, FirstTS: event.TS, LastTS: event.TS, CreatedAt: event.TS[:19], UpdatedAt: event.TS[:19]}
			reg := incidents.NewRegistry(7, []incidents.Incident{legacy})
			op := store.OperatorState{IncidentID: legacy.IncidentID, Status: status, Owner: "analyst", Note: "Operator decision", UpdatedAt: model.FormatTS(start.Add(30 * time.Second))[:19]}
			stored := legacy
			fail := true
			inserts := 0
			previousTransport := http.DefaultTransport
			http.DefaultTransport = pr25ReviewTransport(func(req *http.Request) (*http.Response, error) {
				if req.URL.Host != "pr25-clickhouse.invalid" {
					t.Errorf("unexpected host: %s", req.URL.Host)
					return nil, fmt.Errorf("unexpected host: %s", req.URL.Host)
				}
				body, err := io.ReadAll(req.Body)
				if err != nil {
					return nil, err
				}
				req.Body.Close()
				code, response := http.StatusOK, ""
				query := req.URL.Query().Get("query")
				switch {
				case strings.HasPrefix(query, "INSERT INTO incidents FORMAT"):
					inserts++
					if fail {
						code, response = http.StatusInternalServerError, "fixture write failure"
					} else {
						if err := json.Unmarshal(body, &stored); err != nil {
							return nil, err
						}
					}
				case strings.Contains(string(body), "FROM incidents_current"):
					raw, err := json.Marshal(op)
					if err != nil {
						return nil, err
					}
					response = string(raw)
				default:
					t.Errorf("unexpected SQL: query=%q body=%q", query, body)
					return nil, fmt.Errorf("unexpected SQL: query=%q body=%q", query, body)
				}
				return &http.Response{StatusCode: code, Status: fmt.Sprintf("%d", code), Header: make(http.Header), Body: io.NopCloser(strings.NewReader(response)), Request: req}, nil
			})
			t.Cleanup(func() { http.DefaultTransport = previousTransport })
			e := &engine{reg: reg, ch: store.New("http://pr25-clickhouse.invalid", "argus", "test", "")}
			now := start.Add(2 * time.Minute)
			created, updated, _ := reg.Apply(dets, now)
			if len(created) != 0 || len(updated) != 1 {
				t.Fatalf("adoption: created=%d updated=%d", len(created), len(updated))
			}
			adopted := updated[0]
			closed, escalated := reg.Sweep(func(string) incidents.AutoClose { return incidents.AutoClose{After: time.Minute, Escalate: true} }, now)
			if len(closed) != 0 || len(escalated) != 1 {
				t.Fatal("fixture must escalate exactly once")
			}
			e.writeIncidents(context.Background(), append(updated, escalated...), map[string]bool{legacy.IncidentID: true}, now)
			for attempt := 3; attempt <= 4; attempt++ {
				now = start.Add(time.Duration(attempt) * time.Minute)
				created, updated, _ = reg.Apply(nil, now)
				if len(created) != 0 || len(updated) != 1 || updated[0] != adopted {
					t.Fatalf("retry %d missing", attempt)
				}
				fail = attempt == 3
				e.writeIncidents(context.Background(), updated, nil, now)
			}
			if inserts < 2 || stored.GroupKey != dets[0].Key || stored.Status != status || stored.Owner != op.Owner || stored.Note != op.Note {
				t.Fatalf("write path did not preserve adopted key and operator decision: inserts=%d stored=%+v", inserts, stored)
			}
			stamp := adopted.UpdatedAt
			for _, offset := range []time.Duration{5 * time.Minute, 26 * time.Hour} {
				created, updated, _ = reg.Apply(nil, start.Add(offset))
				if len(created)+len(updated) != 0 || adopted.UpdatedAt != stamp {
					t.Fatal("successful INSERT did not settle retry")
				}
			}
		})
	}
}
