package main

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net/http"
	"reflect"
	"testing"

	"github.com/devitex-soft/argus/engine/internal/dataset"
	"github.com/devitex-soft/argus/engine/internal/systemone"
)

// Error/PII records have no verified revision covering their answers. In
// particular, rejecting an absent response.model must not then write the
// configured request alias into that same dataset field.
// Run from engine: go test ./cmd/engine -run '^TestPR85ExportRevisionMetadata$' -count=1
func TestPR85ExportRevisionMetadata(t *testing.T) {
	for _, tc := range []struct {
		name      string
		source    string
		pii       uint8
		replies   []pr85DecisionReply
		wantError string
		wantModel string
	}{
		{
			name: "reported_revision_with_unicode_whitespace_control", source: "laya",
			replies:   []pr85DecisionReply{{modelJSON: `" \tlaya-v1\r\n"`}, {modelJSON: `"\u00a0laya-v1\u2003"`}},
			wantModel: "laya-v1",
		},
		{
			name: "missing_revision", source: "laya", replies: []pr85DecisionReply{{}},
			wantError: "systemone laya: model revision not reported",
		},
		{
			name: "empty_revision", source: "laya", replies: []pr85DecisionReply{{modelJSON: `""`}},
			wantError: "systemone laya: model revision not reported",
		},
		{
			name: "null_revision", source: "laya", replies: []pr85DecisionReply{{modelJSON: `null`}},
			wantError: "systemone laya: model revision not reported",
		},
		{
			name: "whitespace_revision", source: "laya", replies: []pr85DecisionReply{{modelJSON: `"\t\u00a0\u2003\r\n"`}},
			wantError: "systemone laya: model revision not reported",
		},
		{
			name: "http_error", source: "laya", replies: []pr85DecisionReply{{status: http.StatusBadGateway}},
			wantError: "systemone laya: HTTP 502",
		},
		{
			name: "second_revision_missing", source: "laya",
			replies:   []pr85DecisionReply{{modelJSON: `"laya-v1"`}, {}},
			wantError: "systemone laya: model revision changed between requests",
		},
		{
			name: "second_revision_changed", source: "laya",
			replies:   []pr85DecisionReply{{modelJSON: `"laya-v1"`}, {modelJSON: `"laya-v2"`}},
			wantError: "systemone laya: model revision changed between requests",
		},
		{
			name: "pii_skipped_without_calling_jev", source: "jev", pii: 1,
			wantError: "pii: не отправлялся в облако",
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			client, calls := pr85DecisionSequence(t, tc.replies)
			client.Name, client.Model = tc.source, tc.source+"-latest"
			var laya, jev *systemone.Client
			if tc.source == "jev" {
				jev = client
			} else {
				laya = client
			}
			row := labeled("INC-85001", tc.pii, true)
			wantHuman := dataset.Build(row, "prod")
			if wantHuman == nil {
				t.Fatal("fixture must have a current human label")
			}
			var output bytes.Buffer
			stats, err := exportDataset(context.Background(), fakeLabeled{row}, &output,
				datasetOpts{Source: "prod", Models: []string{tc.source}}, laya, jev)
			if err != nil || stats.Written != 1 {
				t.Fatalf("human record must survive: error=%v stats=%+v", err, stats)
			}
			records := readRecords(t, &output)
			if len(records) != 1 || !reflect.DeepEqual(records[0].Labels, wantHuman.Labels) {
				t.Fatalf("human labels changed: records=%+v", records)
			}
			if *calls != len(tc.replies) {
				t.Errorf("model calls=%d, want %d", *calls, len(tc.replies))
			}
			ma, ok := records[0].Models[tc.source]
			if !ok {
				t.Fatal("attempted/skipped model must be recorded")
			}
			if ma.Error != tc.wantError {
				t.Errorf("model error=%q, want %q", ma.Error, tc.wantError)
			}
			if ma.Model != tc.wantModel {
				t.Errorf("exported revision=%q, want %q: configured alias %q is not a reported revision",
					ma.Model, tc.wantModel, client.Model)
			}
			wantErrors, wantSkipped := 0, 0
			if tc.pii != 0 {
				wantSkipped = 1
			} else if tc.wantError != "" {
				wantErrors = 1
			}
			if stats.ModelErrors != wantErrors || stats.PIISkippedJev != wantSkipped {
				t.Errorf("stats=%+v, want model_errors=%d pii_skipped_jev=%d", stats, wantErrors, wantSkipped)
			}
			samples := dataset.Samples(records, tc.source, ma.Model, "attack_technique", nil)
			if tc.wantError != "" {
				if len(ma.Answers) != 0 || len(ma.Questions) != 0 || len(samples) != 0 {
					t.Errorf("failed/skipped model must not supply answers or eval samples: model=%+v samples=%d", ma, len(samples))
				}
			} else if len(ma.Answers) != 5 || len(samples) != 1 {
				t.Errorf("reported revision must retain both stages: model=%+v samples=%d", ma, len(samples))
			}
		})
	}
}

// Rewrite only response metadata on the existing valid-answer fixture. All
// traffic stays in memory; no model server, socket, or credential is used.
type pr85DecisionReply struct {
	modelJSON   string // Raw JSON value; empty means the property is omitted.
	routingJSON string // Optional laya-serve routing metadata, not a revision.
	status      int    // Zero means HTTP 200.
}

func pr85DecisionSequence(t *testing.T, replies []pr85DecisionReply) (*systemone.Client, *int) {
	t.Helper()
	client := pr64Round5GroupModel(t, "credential-access", "T1110")
	base := client.HTTP.Transport
	calls := 0
	client.HTTP.Transport = pr64DatasetTransport(func(req *http.Request) (*http.Response, error) {
		if calls >= len(replies) {
			t.Fatalf("unexpected model request %d; have %d replies", calls+1, len(replies))
		}
		reply := replies[calls]
		calls++
		resp, err := base.RoundTrip(req)
		if err != nil {
			return nil, err
		}
		var body map[string]json.RawMessage
		err = json.NewDecoder(resp.Body).Decode(&body)
		resp.Body.Close()
		if err != nil {
			t.Fatal(err)
		}
		if reply.modelJSON == "" {
			delete(body, "model")
		} else {
			body["model"] = json.RawMessage(reply.modelJSON)
		}
		if reply.routingJSON != "" {
			body["routing"] = json.RawMessage(reply.routingJSON)
		}
		raw, err := json.Marshal(body)
		if err != nil {
			t.Fatal(err)
		}
		resp.Body = io.NopCloser(bytes.NewReader(raw))
		if reply.status != 0 {
			resp.StatusCode = reply.status
		}
		return resp, nil
	})
	return client, &calls
}
