package main

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net/http"
	"testing"

	"github.com/devitex-soft/argus/engine/internal/systemone"
)

func TestPR72ExportDoesNotMixModelVersionsBetweenDecisionStages(t *testing.T) {
	for _, tc := range []struct {
		name, secondVersion string
		wantError           bool
	}{
		{"stable_version_control", "laya-v1", false},
		{"deployment_between_requests", "laya-v2", true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			client := pr64Round5GroupModel(t, "credential-access", "T1110")
			client.Model = "laya-latest"
			base := client.HTTP.Transport
			calls := 0
			client.HTTP.Transport = pr64DatasetTransport(func(req *http.Request) (*http.Response, error) {
				// Reuse the valid in-memory answers and vary only the reported
				// model revision, as a rolling deployment behind an alias can do.
				resp, err := base.RoundTrip(req)
				if err != nil {
					return nil, err
				}
				var body systemone.Response
				err = json.NewDecoder(resp.Body).Decode(&body)
				resp.Body.Close()
				if err != nil {
					t.Fatal(err)
				}
				calls++
				body.Model = "laya-v1"
				if calls == 2 {
					body.Model = tc.secondVersion
				}
				raw, err := json.Marshal(body)
				if err != nil {
					t.Fatal(err)
				}
				resp.Body = io.NopCloser(bytes.NewReader(raw))
				return resp, nil
			})
			var output bytes.Buffer
			stats, err := exportDataset(context.Background(), fakeLabeled{labeled("INC-72003", 0, true)}, &output,
				datasetOpts{Source: "prod", Models: []string{"laya"}}, client, nil)
			if err != nil || stats.Written != 1 || calls != 2 {
				t.Fatalf("export: %v; stats=%+v; requests=%d", err, stats, calls)
			}
			records := readRecords(t, &output)
			if len(records) != 1 {
				t.Fatalf("expected one record, got %d", len(records))
			}
			ma := records[0].Models["laya"]
			if tc.wantError {
				// ModelAnswers has one revision for all answers; reject a mixed
				// pair rather than silently evaluating v2's technique as v1's.
				if stats.ModelErrors != 1 || ma.Error == "" || len(ma.Answers) != 0 {
					t.Errorf("two revisions were exported as a successful %q answer: errors=%d, answers=%d, error=%q",
						ma.Model, stats.ModelErrors, len(ma.Answers), ma.Error)
				}
			} else if stats.ModelErrors != 0 || ma.Error != "" || ma.Model != "laya-v1" || len(ma.Answers) != 5 {
				t.Errorf("a stable revision must still export all five answers: stats=%+v, model=%+v", stats, ma)
			}
		})
	}
}
