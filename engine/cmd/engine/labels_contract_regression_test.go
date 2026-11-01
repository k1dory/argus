package main

import (
	"context"
	"encoding/json"
	"net/http"
	"reflect"
	"testing"
	"time"

	"github.com/devitex-soft/argus/engine/internal/incidents"
	"github.com/devitex-soft/argus/engine/internal/store"
)

func labelContractEngine(t *testing.T, status string, tags []string) (*engine, *fakeCH) {
	t.Helper()
	f := newFakeCH(t)
	inc, err := json.Marshal(incidents.Incident{IncidentID: "INC-4", Status: status, Owner: "anna", Tags: tags})
	if err != nil {
		t.Fatal(err)
	}
	f.selects["FROM incidents_current WHERE incident_id ="] = string(inc) + "\n"
	f.selects["max(revision)"] = `{"revision":"2"}` + "\n"
	return &engine{ctx: context.Background(), token: "label-contract-token",
		ch: store.New(f.srv.URL, "argus", "default", ""), reg: incidents.NewRegistry(0, nil)}, f
}

func assertLabelWire(t *testing.T, raw string, overrides map[string]any) map[string]any {
	t.Helper()
	var got map[string]any
	if err := json.Unmarshal([]byte(raw), &got); err != nil {
		t.Fatalf("state event is not JSON: %v", err)
	}
	want := map[string]any{
		"disposition": "", "escalate": nil, "severity_correct": nil,
		"ops_cause": "", "ops_action": "", "blind": false, "labeled_by_human": false,
	}
	for k, v := range overrides {
		want[k] = v
	}
	for k, v := range want {
		if actual, present := got[k]; !present || !reflect.DeepEqual(actual, v) {
			t.Errorf("state field %s: present=%v got=%#v want=%#v", k, present, actual, v)
		}
	}
	return got
}

func TestClosureLabelHTTPAndStoredEvent(t *testing.T) {
	for _, tc := range []struct {
		name, kind, status, label string
		tags                      []string
		code                      int
		want                      map[string]any
	}{
		{name: "human security closure keeps explicit false", kind: "status", status: "closed",
			label: `{"disposition":"malicious","escalate":false,"severity_correct":false}`, code: http.StatusOK,
			want: map[string]any{"disposition": "malicious", "escalate": false, "severity_correct": false, "blind": true, "labeled_by_human": true}},
		{name: "human ops closure keeps nullable security fields", kind: "status", status: "closed", tags: []string{"ops.storage"},
			label: `{"ops_cause":"real_failure","ops_action":"fixed"}`, code: http.StatusOK,
			want: map[string]any{"ops_cause": "real_failure", "ops_action": "fixed", "blind": true, "labeled_by_human": true}},
		{name: "legacy take needs no label", kind: "take", code: http.StatusOK},
		{name: "closing without label rejected", kind: "status", status: "closed", code: http.StatusConflict},
		{name: "null is not an explicit false answer", kind: "status", status: "closed",
			label: `{"disposition":"malicious","escalate":null,"severity_correct":false}`, code: http.StatusConflict},
		{name: "label on nonfinal transition rejected", kind: "status", status: "observing",
			label: `{"disposition":"malicious","escalate":false,"severity_correct":false}`, code: http.StatusConflict},
		{name: "caller cannot override blind sample", kind: "status", status: "closed",
			label: `{"disposition":"malicious","escalate":false,"severity_correct":false,"blind":false}`, code: http.StatusBadRequest},
		{name: "caller cannot override human provenance", kind: "status", status: "closed",
			label: `{"disposition":"malicious","escalate":false,"severity_correct":false,"labeled_by_human":false}`, code: http.StatusBadRequest},
	} {
		t.Run(tc.name, func(t *testing.T) {
			initial := incidents.StatusInProgress
			if tc.kind == "take" {
				initial = incidents.StatusNew
			}
			e, f := labelContractEngine(t, initial, tc.tags)
			request := map[string]any{"actor": "anna", "role": "analyst", "kind": tc.kind,
				"status": tc.status, "reason": "QA checked the source events"}
			if tc.label != "" {
				request["label"] = json.RawMessage(tc.label)
			}
			body, err := json.Marshal(request)
			if err != nil {
				t.Fatal(err)
			}
			code, response := do(t, e.handler(), "POST", "/incidents/INC-4/workflow", "label-contract-token", string(body))
			if code != tc.code {
				t.Fatalf("HTTP %d, want %d: %s", code, tc.code, response)
			}
			rows := f.rows("incident_state_events")
			if tc.code != http.StatusOK {
				if len(rows) != 0 {
					t.Fatalf("rejected transition wrote %d state events", len(rows))
				}
				return
			}
			if len(rows) != 1 {
				t.Fatalf("successful transition wrote %d state events, want one", len(rows))
			}
			returned := assertLabelWire(t, response, tc.want)
			stored := assertLabelWire(t, rows[0], tc.want)
			if !reflect.DeepEqual(returned, stored) {
				t.Fatal("HTTP response and stored state event differ")
			}
			if stored["incident_id"] != "INC-4" || stored["actor"] != "anna" || stored["revision"] != float64(3) {
				t.Fatalf("label lost its incident/author/revision: %#v", stored)
			}
		})
	}
}

func TestAutomaticClosureNeverProducesHumanLabel(t *testing.T) {
	e, f := labelContractEngine(t, incidents.StatusInProgress, []string{"ops.storage"})
	inc := &incidents.Incident{IncidentID: "INC-4", RuleID: "ops-test", Status: incidents.StatusClosed, Owner: "anna"}
	e.writeIncidents(context.Background(), []*incidents.Incident{inc}, map[string]bool{"INC-4": true}, time.Now().UTC())
	rows := f.rows("incident_state_events")
	if len(rows) != 1 {
		t.Fatalf("auto-close wrote %d state events, want one", len(rows))
	}
	stored := assertLabelWire(t, rows[0], nil)
	if stored["kind"] != "auto_close" || stored["actor"] != "argus-engine" || stored["status"] != "closed" {
		t.Fatalf("wrong automatic provenance: %#v", stored)
	}
}
