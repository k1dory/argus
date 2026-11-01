package main

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net/http"
	"testing"

	"github.com/devitex-soft/argus/engine/internal/dataset"
)

// Equality of two missing model IDs does not establish a common revision.
// A backend behind a mutable alias can omit model on both requests; exporting
// its answers under that alias makes an unverifiable pair eligible for eval.
// Exercise export and eval using only an in-memory transport, without sockets.
//
// Run from engine:
//
//	go test ./cmd/engine -run '^TestPR81ExportRequiresReportedModelRevision$' -count=1
func TestPR81ExportRequiresReportedModelRevision(t *testing.T) {
	for _, tc := range []struct {
		name        string
		firstModel  string // JSON value; empty means the property is absent.
		secondModel string
		wantError   bool
	}{
		{"stable_revision_control", `"laya-v1"`, `"laya-v1"`, false},
		{"changed_revision_control", `"laya-v1"`, `"laya-v2"`, true},
		{"both_omitted", "", "", true},
		{"both_empty", `""`, `""`, true},
		{"both_null", `null`, `null`, true},
		{"both_whitespace", `"   "`, `"   "`, true},
		{"first_omitted_control", "", `"laya-v1"`, true},
		{"second_omitted_control", `"laya-v1"`, "", true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			client := pr64Round5GroupModel(t, "credential-access", "T1110")
			client.Model = "laya-latest"
			base := client.HTTP.Transport
			calls := 0
			client.HTTP.Transport = pr64DatasetTransport(func(req *http.Request) (*http.Response, error) {
				if calls >= 2 {
					t.Fatal("unexpected third model request")
				}
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
				model := []string{tc.firstModel, tc.secondModel}[calls]
				calls++
				if model == "" {
					delete(body, "model")
				} else {
					body["model"] = json.RawMessage(model)
				}
				raw, err := json.Marshal(body)
				if err != nil {
					t.Fatal(err)
				}
				resp.Body = io.NopCloser(bytes.NewReader(raw))
				return resp, nil
			})

			var output bytes.Buffer
			stats, err := exportDataset(context.Background(), fakeLabeled{labeled("INC-81001", 0, true)}, &output,
				datasetOpts{Source: "prod", Models: []string{"laya"}}, client, nil)
			if err != nil || stats.Written != 1 {
				t.Fatalf("export must keep the human-labeled record: error=%v stats=%+v", err, stats)
			}
			records := readRecords(t, &output)
			if len(records) != 1 || calls < 1 || calls > 2 {
				t.Fatalf("records=%d requests=%d, want one record and one or two requests", len(records), calls)
			}
			if got := records[0].Labels["attack_technique"]; got != "T1110" {
				t.Fatalf("human technique label was lost: %q", got)
			}
			ma, ok := records[0].Models["laya"]
			if !ok {
				t.Fatal("the attempted model call must be recorded")
			}
			samples := dataset.Samples(records, "laya", ma.Model, "attack_technique", nil)
			if tc.wantError {
				if stats.ModelErrors != 1 || ma.Error == "" || len(ma.Answers) != 0 {
					t.Errorf("unverified revision pair exported successfully: model=%q answers=%d error=%q model_errors=%d",
						ma.Model, len(ma.Answers), ma.Error, stats.ModelErrors)
				}
				if len(samples) != 0 {
					t.Errorf("unverified revision pair contributes %d evaluation samples under %q", len(samples), ma.Model)
				}
			} else if calls != 2 || stats.ModelErrors != 0 || ma.Error != "" || ma.Model != "laya-v1" || len(ma.Answers) != 5 || len(samples) != 1 {
				t.Errorf("stable reported revision must retain both stages: requests=%d stats=%+v model=%+v samples=%d",
					calls, stats, ma, len(samples))
			}
		})
	}
}
