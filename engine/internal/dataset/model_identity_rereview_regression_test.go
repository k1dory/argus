package dataset

import (
	"testing"

	"github.com/devitex-soft/argus/engine/internal/systemone"
)

func TestPR64RereviewEmptyModelVersionIsNotAWildcardInReports(t *testing.T) {
	// An empty version is accepted by the JSONL reader and is one of the
	// (source, model) pairs discovered by EvaluateRecords. It must not absorb
	// the explicitly versioned records in the same input.
	var records []Record
	for _, version := range []string{"", "laya-v2"} {
		for _, split := range []string{"train", "holdout"} {
			choice, p := "malicious", 0.9
			if version != "" {
				choice, p = "false_positive", 0.1
			}
			records = append(records, Record{
				Schema: Schema, Split: split, Blind: true, Questions: Questions(Security),
				Labels: map[string]string{"disposition": "malicious"},
				Models: map[string]ModelAnswers{"laya": {
					Model: version,
					Answers: map[string]systemone.Answer{"disposition": {
						Type: systemone.Choice, Choice: choice,
						Probabilities: map[string]float64{"malicious": p, "false_positive": 1 - p, "benign_authorized": 0},
					}},
				}},
			})
		}
	}
	reports := EvaluateRecords(records, EvalOpts{
		CalibSplit: "train", EvalSplit: "holdout", BlindOnly: true,
		TargetAuto: 0.98, TargetHint: 0.85, MinN: 1,
	})
	if len(reports) != 2 {
		t.Fatalf("expected one report per version, got %+v", reports)
	}
	for _, report := range reports {
		wantAcc := 0.0
		if report.Model == "" {
			wantAcc = 1
		}
		if report.CalibN != 1 || report.Raw.N != 1 || report.Raw.Acc != wantAcc {
			t.Errorf("source=%q model=%q mixes model identities: calib_n=%d eval_n=%d acc=%g, want 1/1/%g",
				report.Source, report.Model, report.CalibN, report.Raw.N, report.Raw.Acc, wantAcc)
		}
	}
}
