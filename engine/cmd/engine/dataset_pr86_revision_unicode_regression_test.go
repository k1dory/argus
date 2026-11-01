package main

import (
	"bytes"
	"context"
	"encoding/json"
	"reflect"
	"testing"

	"github.com/devitex-soft/argus/engine/internal/dataset"
)

// A backend name with invisible characters, spacing, or lookalike letters still
// supplies no checkpoint revision. Exercise export -> JSONL -> eval, rather than
// reportedRevision alone: askModel trims surrounding whitespace at its caller.
// All responses use the existing in-memory transport; no socket is opened.
// Run from engine:
// go test ./cmd/engine -run '^TestPR86ExportRevisionIdentity$' -count=1
func TestPR86ExportRevisionIdentity(t *testing.T) {
	const whitespace = " \t\r\n\u0085\u00a0\u1680\u2000\u2003\u200a\u2028\u2029\u202f\u205f\u3000"
	for _, tc := range []struct {
		name      string
		model     string
		wantModel string // Empty means the response must be rejected.
	}{
		{name: "empty_control"},
		{name: "whitespace_only_control", model: whitespace},
		{name: "backend_control", model: "laya-rl-agent"},
		{name: "uppercase_backend_control", model: "LAYA-RL-AGENT"},
		{name: "padded_mixed_case_backend_control", model: whitespace + "LaYa-Rl-AgEnT" + whitespace},
		{name: "backend_zero_width_suffix", model: "laya-rl-agent\u200b"},
		{name: "backend_embedded_zero_width_space", model: "laya-\u200brl-agent"},
		{name: "backend_bom_prefix", model: "\ufefflaya-rl-agent"},
		{name: "backend_internal_ascii_space", model: "laya-rl- agent"},
		{name: "backend_internal_nbsp", model: "laya-rl-\u00a0agent"},
		{name: "backend_cyrillic_a", model: "l\u0430ya-rl-agent"},
		{name: "backend_fullwidth_letters", model: "\uff4c\uff41\uff59\uff41-\uff52\uff4c-\uff41\uff47\uff45\uff4e\uff54"},
		// The visually empty cases also guard the older empty-revision check.
		{name: "invisible_only", model: "\u200b"},
		{name: "whitespace_around_invisible", model: whitespace + "\ufeff" + whitespace},
		{name: "revision_control", model: "argus-v1@revision-86001", wantModel: "argus-v1@revision-86001"},
		{
			name: "backend_with_revision_control", model: "laya-rl-agent@checkpoint-86001",
			wantModel: "laya-rl-agent@checkpoint-86001",
		},
		{
			name: "padded_revision_control", model: whitespace + "argus-v1@revision-86001" + whitespace,
			wantModel: "argus-v1@revision-86001",
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			for _, withRouting := range []bool{false, true} {
				name := "without_routing"
				if withRouting {
					name = "routing_repo_is_not_a_revision"
				}
				t.Run(name, func(t *testing.T) {
					modelJSON, err := json.Marshal(tc.model)
					if err != nil {
						t.Fatal(err)
					}
					reply := pr85DecisionReply{modelJSON: string(modelJSON)}
					if withRouting {
						reply.routingJSON = `{"model":"argus","repo":"fixture-org/argus-v1","reason":"fixture route"}`
					}
					// Supply both stages so a faulty validator reaches eval. A
					// correct rejection must stop before the second model call.
					client, calls := pr85DecisionSequence(t, []pr85DecisionReply{reply, reply})
					client.Model = "argus-latest"
					row := labeled("INC-86001", 0, true)
					wantHuman := dataset.Build(row, "prod")
					if wantHuman == nil {
						t.Fatal("fixture must produce a current human label")
					}
					var output bytes.Buffer
					stats, err := exportDataset(context.Background(), fakeLabeled{row}, &output,
						datasetOpts{Source: "prod", Models: []string{"laya"}}, client, nil)
					if err != nil || stats.Written != 1 {
						t.Fatalf("human record must survive: error=%v stats=%+v", err, stats)
					}
					records := readRecords(t, &output)
					if len(records) != 1 || !reflect.DeepEqual(records[0].Labels, wantHuman.Labels) {
						t.Fatalf("human labels changed: records=%+v", records)
					}
					ma, ok := records[0].Models["laya"]
					if !ok {
						t.Fatal("attempted model must be recorded")
					}
					// Do not let the HMAC split hide an erroneously accepted answer.
					records[0].Split, records[0].Blind = "holdout", true
					reports := dataset.EvaluateRecords(records, dataset.EvalOpts{
						CalibSplit: "train", EvalSplit: "holdout", BlindOnly: true,
						TargetAuto: 0.98, TargetHint: 0.85, MinN: 1,
					})
					if tc.wantModel != "" {
						if *calls != 2 || stats.ModelErrors != 0 || ma.Error != "" || ma.Model != tc.wantModel || len(ma.Answers) != 5 || len(reports) != 5 {
							t.Errorf("reported revision must remain usable: calls=%d stats=%+v model=%q error=%q answers=%d reports=%d",
								*calls, stats, ma.Model, ma.Error, len(ma.Answers), len(reports))
						}
						return
					}
					if *calls != 1 || stats.ModelErrors != 1 || ma.Error != "systemone laya: model revision not reported" {
						t.Errorf("unversioned identity %q must be rejected after the first call: calls=%d stats=%+v error=%q",
							tc.model, *calls, stats, ma.Error)
					}
					if ma.Model != "" || len(ma.Answers) != 0 || len(ma.Questions) != 0 {
						t.Errorf("rejected identity must not retain revision or answers: model=%q answers=%d questions=%d",
							ma.Model, len(ma.Answers), len(ma.Questions))
					}
					if len(reports) != 0 {
						t.Errorf("unversioned identity %q entered eval: reports=%d", ma.Model, len(reports))
					}
				})
			}
		})
	}
}
