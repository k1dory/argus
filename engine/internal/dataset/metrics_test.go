package dataset

import (
	"math"
	"math/rand/v2"
	"testing"

	"github.com/devitex-soft/argus/engine/internal/systemone"
)

func near(t *testing.T, name string, got, want, eps float64) {
	t.Helper()
	if math.Abs(got-want) > eps {
		t.Fatalf("%s = %.4f, ждали %.4f ± %.4f", name, got, want, eps)
	}
}

func TestEvaluatePerfectAndHandValues(t *testing.T) {
	perfect := []Sample{
		{P: map[string]float64{"a": 1, "b": 0}, Label: "a"},
		{P: map[string]float64{"a": 0, "b": 1}, Label: "b"},
	}
	m := Evaluate(perfect, 1)
	near(t, "acc", m.Acc, 1, 1e-9)
	near(t, "brier", m.Brier, 0, 1e-9)
	near(t, "ece", m.ECE, 0, 1e-9)

	// Два наблюдения с уверенностью 0.8: одно верно, одно нет.
	// acc 0.5; soft (0.8+0.2)/2 = 0.5; Brier ((0.2²+0.2²) + (0.8²+0.8²))/2 = 0.68;
	// ECE: одна корзина, |0.5 − 0.8| = 0.3.
	hand := []Sample{
		{P: map[string]float64{"a": 0.8, "b": 0.2}, Label: "a"},
		{P: map[string]float64{"a": 0.8, "b": 0.2}, Label: "b"},
	}
	m = Evaluate(hand, 1)
	near(t, "acc", m.Acc, 0.5, 1e-9)
	near(t, "soft", m.SoftAcc, 0.5, 1e-9)
	near(t, "brier", m.Brier, 0.68, 1e-9)
	near(t, "ece", m.ECE, 0.3, 1e-9)
}

func TestDistNoul(t *testing.T) {
	p := 0.8
	d := Dist(systemone.Question{Type: systemone.Noul}, systemone.Answer{Type: systemone.Noul, Noul: &p})
	near(t, "true", d["true"], 0.8, 1e-12)
	near(t, "false", d["false"], 0.2, 1e-12)
}

// overconfident — модель всегда уверена на 0.97, а права в 70 % случаев.
func overconfident(n int, seed uint64) []Sample {
	r := rand.New(rand.NewPCG(seed, 1))
	out := make([]Sample, n)
	for i := range out {
		label, other := "malicious", "false_positive"
		if r.IntN(2) == 0 {
			label, other = other, label
		}
		pred := label
		if r.Float64() >= 0.7 {
			pred = other
		}
		out[i] = Sample{P: map[string]float64{pred: 0.97, map[bool]string{true: other, false: label}[pred == label]: 0.03}, Label: label}
	}
	return out
}

func TestTemperatureFixesOverconfidence(t *testing.T) {
	calib, test := overconfident(2000, 1), overconfident(2000, 2)
	raw := Evaluate(test, 1)
	tt := FitTemperature(calib)
	cal := Evaluate(test, tt)
	if tt <= 1.5 {
		t.Fatalf("самоуверенной модели нужна T > 1, подобрана %.2f", tt)
	}
	near(t, "acc не меняется", cal.Acc, raw.Acc, 1e-9)
	if raw.ECE < 0.2 || cal.ECE > 0.05 {
		t.Fatalf("ECE до %.3f, после %.3f", raw.ECE, cal.ECE)
	}
	if cal.NLL >= raw.NLL || cal.Brier >= raw.Brier {
		t.Fatalf("NLL/Brier после калибровки не лучше: %+v → %+v", raw, cal)
	}
	near(t, "уверенность после калибровки ≈ точности", Temper(test[0].P, tt)[mustArgmax(test[0].P)], 0.7, 0.03)
}

func mustArgmax(p map[string]float64) string { k, _ := argmax(p); return k }

// graded — уверенность совпадает с точностью: выше порога модель права чаще.
func graded(n int, seed uint64) []Sample {
	r := rand.New(rand.NewPCG(seed, 2))
	out := make([]Sample, n)
	for i := range out {
		conf := 0.5 + 0.5*r.Float64()
		label := "a"
		pred := "a"
		if r.Float64() >= conf {
			pred = "b"
		}
		out[i] = Sample{P: map[string]float64{pred: conf, map[bool]string{true: "b", false: "a"}[pred == "a"]: 1 - conf}, Label: label}
	}
	return out
}

func TestFitThreshold(t *testing.T) {
	calib, test := graded(4000, 1), graded(4000, 2)
	th := FitThreshold(calib, 1, 0.95, 20)
	if th.Conf > 1 || th.Acc < 0.95 || th.Coverage <= 0 || th.Coverage > 0.5 {
		t.Fatalf("порог 95 %%: %+v", th)
	}
	cov, acc, n := ApplyThreshold(test, 1, th.Conf)
	if acc < 0.93 || n == 0 {
		t.Fatalf("на замере точность %.3f, n %d", acc, n)
	}
	near(t, "покрытие держится", cov, th.Coverage, 0.05)
	low := FitThreshold(calib, 1, 0.80, 20)
	if low.Conf >= th.Conf || low.Coverage <= th.Coverage {
		t.Fatalf("порог подсказки ниже и шире порога автозакрытия: %+v vs %+v", low, th)
	}
	if never := FitThreshold(overconfident(500, 3), 1, 0.95, 20); never.Conf != 2 {
		t.Fatalf("недостижимая точность — уровень выключен: %+v", never)
	}
}

func TestEvaluateRecordsSplitsAndBlind(t *testing.T) {
	ans := func(choice string, p float64) map[string]ModelAnswers {
		probs := map[string]float64{"malicious": 1 - p, "benign_authorized": 0, "false_positive": 0}
		probs[choice] += p
		if choice != "malicious" {
			probs["malicious"] = 1 - p
		}
		return map[string]ModelAnswers{"laya": {Model: "m", Answers: map[string]systemone.Answer{
			"disposition": {Type: systemone.Choice, Choice: choice, Probabilities: probs},
		}}}
	}
	qs := Questions(Security)
	rec := func(split string, blind bool, label, pred string) Record {
		return Record{Split: split, Blind: blind, Questions: qs, Labels: map[string]string{"disposition": label}, Models: ans(pred, 0.9)}
	}
	recs := []Record{
		rec("train", false, "malicious", "malicious"),
		rec("holdout", true, "malicious", "malicious"),
		rec("holdout", true, "false_positive", "false_positive"),
		rec("holdout", false, "false_positive", "malicious"), // не слепая — не в замере
	}
	reps := EvaluateRecords(recs, EvalOpts{CalibSplit: "train", EvalSplit: "holdout", BlindOnly: true, TargetAuto: 0.99, TargetHint: 0.9, MinN: 1})
	if len(reps) != 1 || reps[0].Model != "laya" || reps[0].Question != "disposition" {
		t.Fatalf("отчёты: %+v", reps)
	}
	if reps[0].Raw.N != 2 || reps[0].Raw.Acc != 1 || reps[0].CalibN != 1 {
		t.Fatalf("замер только по слепой отложенной части: %+v", reps[0])
	}
	reps = EvaluateRecords(recs, EvalOpts{CalibSplit: "train", EvalSplit: "holdout", TargetAuto: 0.99, TargetHint: 0.9, MinN: 1})
	if reps[0].Raw.N != 3 {
		t.Fatalf("без BlindOnly — вся отложенная часть: %+v", reps[0].Raw)
	}
}
