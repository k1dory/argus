package main

import (
	"bytes"
	"encoding/json"
	"io"
	"os"
	"path/filepath"
	"syscall"
	"testing"

	"github.com/devitex-soft/argus/engine/internal/dataset"
	"github.com/devitex-soft/argus/engine/internal/systemone"
)

type pr64EvalFailWriter struct{ calls int }

func (w *pr64EvalFailWriter) Write([]byte) (int, error) {
	w.calls++
	return 0, syscall.ENOSPC
}

func TestPR64DatasetEvalReportsOutputFailure(t *testing.T) {
	path := filepath.Join(t.TempDir(), "dataset.jsonl")
	f, err := os.Create(path)
	if err != nil {
		t.Fatal(err)
	}
	enc := json.NewEncoder(f)
	for _, split := range []string{"train", "holdout"} {
		if err := enc.Encode(dataset.Record{
			Schema: dataset.Schema, IncidentID: "fixture-" + split, GroupID: "fixture-" + split,
			Split: split, Blind: true, Questions: dataset.Questions(dataset.Security),
			Labels: map[string]string{"disposition": "malicious"},
			Models: map[string]dataset.ModelAnswers{"laya": {Model: "fixture-model", Answers: map[string]systemone.Answer{
				"disposition": {Type: systemone.Choice, Choice: "malicious",
					Probabilities: map[string]float64{"malicious": 0.9, "false_positive": 0.1, "benign_authorized": 0}},
			}}},
		}); err != nil {
			_ = f.Close()
			t.Fatal(err)
		}
	}
	if err := f.Close(); err != nil {
		t.Fatal(err)
	}
	for _, format := range []string{"json", "table"} {
		t.Run(format, func(t *testing.T) {
			args := []string{"--in", path}
			if format == "json" {
				args = append(args, "--json")
			}
			// Valid input must produce output before testing a failing sink.
			var good bytes.Buffer
			if code := datasetEvalCmd(args, &good); code != 0 || good.Len() == 0 {
				t.Fatalf("valid fixture failed: exit=%d output=%q", code, good.String())
			}
			var failed pr64EvalFailWriter
			code := datasetEvalCmd(args, io.Writer(&failed))
			if failed.calls == 0 {
				t.Fatal("fixture did not reach the output writer")
			}
			if code == 0 {
				t.Error("ENOSPC while writing the evaluation report must return a nonzero exit code")
			}
		})
	}
}
