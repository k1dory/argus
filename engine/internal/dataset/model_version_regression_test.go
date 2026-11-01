package dataset

import (
	"testing"

	"github.com/devitex-soft/argus/engine/internal/systemone"
)

func TestPR64EvaluateKeepsModelVersionsSeparate(t *testing.T) {
	// Concatenating exports from before and after a Laya deployment is valid
	// JSONL with the same schema and questions, but contains two different models.
	var recs []Record
	for _, version := range []string{"laya-v1", "laya-v2"} {
		for _, split := range []string{"train", "holdout"} {
			p := 0.9
			choice := "malicious"
			if version == "laya-v2" {
				p, choice = 0.1, "false_positive"
			}
			recs = append(recs, Record{
				Schema: Schema, IncidentID: version + "-" + split, GroupID: version + "-" + split,
				Split: split, Blind: true, Questions: Questions(Security),
				Labels: map[string]string{"disposition": "malicious"},
				Models: map[string]ModelAnswers{"laya": {
					Model: version, Answers: map[string]systemone.Answer{"disposition": {
						Type: systemone.Choice, Choice: choice,
						Probabilities: map[string]float64{"malicious": p, "false_positive": 1 - p, "benign_authorized": 0},
					}},
				}},
			})
		}
	}
	reports := EvaluateRecords(recs, EvalOpts{
		CalibSplit: "train", EvalSplit: "holdout", BlindOnly: true, TargetAuto: 0.98, TargetHint: 0.85, MinN: 1,
	})
	if len(reports) != 2 {
		t.Fatalf("two model versions need independent calibration and reports; got %+v", reports)
	}
	seen := map[string]bool{}
	accuracies := map[float64]bool{}
	for _, report := range reports {
		if seen[report.Model] {
			t.Errorf("report model %q does not distinguish versions", report.Model)
		}
		seen[report.Model] = true
		if report.CalibN != 1 || report.Raw.N != 1 {
			t.Errorf("calibration/evaluation mixed versions: %+v", report)
		}
		accuracies[report.Raw.Acc] = true
	}
	if !accuracies[0] || !accuracies[1] {
		t.Fatalf("one version is always right, the other always wrong; got %+v", reports)
	}
}
