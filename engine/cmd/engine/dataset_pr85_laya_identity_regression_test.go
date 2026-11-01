package main

import (
	"bytes"
	"context"
	"testing"

	"github.com/devitex-soft/argus/engine/internal/dataset"
)

// Upstream laya-serve returns the constant "laya-rl-agent", even for different
// checkpoints. Router.predict adds routing metadata; serve passes that response
// through (or removes routing in LAYA_JEV_STRICT mode). This is a backend name,
// not evidence that two decisions came from the same checkpoint/revision.
// Sources inspected on 2026-11-01:
// https://raw.githubusercontent.com/NandhaKishorM/laya/main/laya/agent.py (Agent.predict_batch)
// https://raw.githubusercontent.com/NandhaKishorM/laya/main/laya/router.py (Router.predict)
// https://raw.githubusercontent.com/NandhaKishorM/laya/main/laya/serve.py (_project_jev_strict)
// Run from engine: go test ./cmd/engine -run '^TestPR85LayaBackendNameIsNotARevision$' -count=1
func TestPR85LayaBackendNameIsNotARevision(t *testing.T) {
	const (
		backendName = `"laya-rl-agent"`
		// The same registered serving alias can point to different checkpoints
		// on two replicas during a deployment. Neither payload reports a revision.
		oldRoute = `{"model":"argus","repo":"fixture-org/argus-v1","reason":"explicit model='argus'"}`
		newRoute = `{"model":"argus","repo":"fixture-org/argus-v2","reason":"explicit model='argus'"}`
	)
	for _, tc := range []struct {
		name      string
		replies   []pr85DecisionReply
		wantError bool
	}{
		{
			name: "full_payload_without_revision", wantError: true,
			replies: []pr85DecisionReply{
				{modelJSON: backendName, routingJSON: oldRoute},
				{modelJSON: backendName, routingJSON: oldRoute},
			},
		},
		{
			name: "checkpoint_changed_between_requests", wantError: true,
			replies: []pr85DecisionReply{
				{modelJSON: backendName, routingJSON: oldRoute},
				{modelJSON: backendName, routingJSON: newRoute},
			},
		},
		{
			name: "strict_jev_payload_without_routing", wantError: true,
			replies: []pr85DecisionReply{{modelJSON: backendName}, {modelJSON: backendName}},
		},
		{
			name:    "reported_checkpoint_revision_control",
			replies: []pr85DecisionReply{{modelJSON: `"argus-v1@revision-85001"`}, {modelJSON: `"argus-v1@revision-85001"`}},
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			client, calls := pr85DecisionSequence(t, tc.replies)
			client.Model = "argus"
			var output bytes.Buffer
			stats, err := exportDataset(context.Background(), fakeLabeled{labeled("INC-85002", 0, true)}, &output,
				datasetOpts{Source: "prod", Models: []string{"laya"}}, client, nil)
			if err != nil || stats.Written != 1 {
				t.Fatalf("human record must survive: error=%v stats=%+v", err, stats)
			}
			records := readRecords(t, &output)
			if len(records) != 1 || records[0].Labels["attack_technique"] != "T1110" {
				t.Fatalf("human technique label was lost: %+v", records)
			}
			ma, ok := records[0].Models["laya"]
			if !ok || *calls < 1 || *calls > 2 {
				t.Fatalf("attempted model missing or unexpected request count: model=%+v calls=%d", ma, *calls)
			}
			// Place the exported record in the eval partition so this assertion
			// cannot accidentally pass just because its HMAC split was train.
			records[0].Split, records[0].Blind = "holdout", true
			reports := dataset.EvaluateRecords(records, dataset.EvalOpts{
				CalibSplit: "train", EvalSplit: "holdout", BlindOnly: true,
				TargetAuto: 0.98, TargetHint: 0.85, MinN: 1,
			})
			if tc.wantError {
				if stats.ModelErrors != 1 || ma.Error == "" || len(ma.Answers) != 0 {
					t.Errorf("unversioned laya-serve backend name accepted as a revision: model=%+v stats=%+v", ma, stats)
				}
				if len(reports) != 0 {
					t.Errorf("unversioned laya-serve answers produced %d evaluation reports under %q", len(reports), ma.Model)
				}
			} else if *calls != 2 || stats.ModelErrors != 0 || ma.Error != "" || ma.Model != "argus-v1@revision-85001" || len(ma.Answers) != 5 || len(reports) != 5 {
				t.Errorf("reported revision must remain usable: calls=%d stats=%+v model=%+v reports=%d", *calls, stats, ma, len(reports))
			}
		})
	}
}
