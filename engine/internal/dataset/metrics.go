package dataset

import (
	"math"
	"sort"
	"strconv"

	"github.com/devitex-soft/argus/engine/internal/systemone"
)

// Замеры моделей решений по записям датасета (ROADMAP этап 4): точность,
// мягкая точность, Brier, ECE; калибровка температуры и пороги воздержания
// (аналог fit_abstention_thresholds из laya). Истина — метка человека.
//
// Правила (DECISIONS §3, §6, §10): замер качества — только по слепой части
// отложенной выборки; температура и пороги подбираются на другой части
// (по умолчанию train) и применяются к замеру, а не подгоняются под него.

// Dist — распределение ответа модели по вариантам вопроса. Noul — два
// варианта "true"/"false" (как метки escalate, severity_correct).
func Dist(q systemone.Question, a systemone.Answer) map[string]float64 {
	switch a.Type {
	case systemone.Noul:
		if a.Noul == nil {
			return nil
		}
		return map[string]float64{"true": *a.Noul, "false": 1 - *a.Noul}
	case systemone.Choice, systemone.Score:
		if len(a.Probabilities) == 0 {
			return nil
		}
		out := make(map[string]float64, len(a.Probabilities))
		for k, v := range a.Probabilities {
			out[k] = v
		}
		return out
	}
	return nil
}

// Sample — одно наблюдение: распределение модели и правильный вариант.
type Sample struct {
	P     map[string]float64
	Label string
}

// Samples — наблюдения источника (laya, jev) по вопросу из записей, подходящих
// под keep. version — ModelAnswers.Model: разные версии одной модели (до и
// после переобучения) не смешиваются; пустая версия — тоже версия, не «любая».
// Записи без метки, без ответа или с ошибкой модели пропускаются.
func Samples(recs []Record, model, version, question string, keep func(*Record) bool) []Sample {
	var out []Sample
	for i := range recs {
		r := &recs[i]
		if keep != nil && !keep(r) {
			continue
		}
		label, ok := r.Labels[question]
		if !ok {
			continue
		}
		ma, ok := r.Models[model]
		if !ok || ma.Error != "" || ma.Model != version {
			continue
		}
		a, ok := ma.Answers[question]
		if !ok {
			continue
		}
		if p := Dist(r.Questions[question], a); p != nil {
			out = append(out, Sample{P: p, Label: label})
		}
	}
	return out
}

// argmax — вариант с наибольшей вероятностью; при равенстве — меньший по
// имени (детерминированно).
func argmax(p map[string]float64) (string, float64) {
	keys := make([]string, 0, len(p))
	for k := range p {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	best, bp := "", -1.0
	for _, k := range keys {
		if p[k] > bp {
			best, bp = k, p[k]
		}
	}
	return best, bp
}

// Temper — распределение с температурой T: p_k^(1/T), нормированное (то же,
// что деление логитов на T). T > 1 смягчает самоуверенную модель.
func Temper(p map[string]float64, t float64) map[string]float64 {
	if t == 1 {
		return p
	}
	out := make(map[string]float64, len(p))
	sum := 0.0
	for k, v := range p {
		w := math.Pow(math.Max(v, 1e-12), 1/t)
		out[k] = w
		sum += w
	}
	for k := range out {
		out[k] /= sum
	}
	return out
}

// Metrics — качество и калибровка на наборе наблюдений.
type Metrics struct {
	N       int     `json:"n"`
	Acc     float64 `json:"acc"`
	SoftAcc float64 `json:"soft_acc"` // средняя вероятность правильного варианта
	Brier   float64 `json:"brier"`    // многоклассовый: Σ_k (p_k − 1[k=y])²
	ECE     float64 `json:"ece"`      // по уверенности = max p, ECEBins равных корзин
	NLL     float64 `json:"nll"`
}

// ECEBins — число корзин ECE.
const ECEBins = 10

// Evaluate считает метрики с температурой t (1 — без калибровки).
func Evaluate(ss []Sample, t float64) Metrics {
	m := Metrics{N: len(ss)}
	if len(ss) == 0 {
		return m
	}
	var binN [ECEBins]int
	var binAcc, binConf [ECEBins]float64
	for _, s := range ss {
		p := Temper(s.P, t)
		pred, conf := argmax(p)
		hit := 0.0
		if pred == s.Label {
			hit = 1
		}
		m.Acc += hit
		m.SoftAcc += p[s.Label]
		m.NLL -= math.Log(math.Max(p[s.Label], 1e-12))
		for k, v := range p {
			y := 0.0
			if k == s.Label {
				y = 1
			}
			m.Brier += (v - y) * (v - y)
		}
		if _, ok := p[s.Label]; !ok {
			m.Brier++ // правильного варианта нет в распределении: (0 − 1)²
		}
		b := int(conf * ECEBins)
		if b >= ECEBins {
			b = ECEBins - 1
		}
		binN[b]++
		binAcc[b] += hit
		binConf[b] += conf
	}
	n := float64(len(ss))
	for b := 0; b < ECEBins; b++ {
		if binN[b] > 0 {
			m.ECE += math.Abs(binAcc[b]-binConf[b]) / n
		}
	}
	m.Acc /= n
	m.SoftAcc /= n
	m.Brier /= n
	m.NLL /= n
	return m
}

// FitTemperature — температура с наименьшим NLL на наборе (сетка 0.25…5 с
// шагом 0.05). Пустой набор — 1.
func FitTemperature(ss []Sample) float64 {
	if len(ss) == 0 {
		return 1
	}
	best, bestNLL := 1.0, math.Inf(1)
	for i := 5; i <= 100; i++ {
		t := float64(i) * 0.05
		if nll := Evaluate(ss, t).NLL; nll < bestNLL-1e-12 {
			best, bestNLL = t, nll
		}
	}
	return best
}

// Threshold — порог уверенности уровня воздержания.
type Threshold struct {
	Target   float64 `json:"target"`   // целевая точность среди ответов не ниже порога
	Conf     float64 `json:"conf"`     // порог; 2 — недостижимо (уровень не включать)
	Coverage float64 `json:"coverage"` // доля наблюдений с уверенностью ≥ порога
	Acc      float64 `json:"acc"`      // точность среди них
	N        int     `json:"n"`
}

// FitThreshold — наименьший порог уверенности (после температуры t), при
// котором точность среди наблюдений с уверенностью ≥ порога не ниже target и
// таких наблюдений не меньше minN. Не нашлось — Conf = 2 (уровень выключен).
func FitThreshold(ss []Sample, t, target float64, minN int) Threshold {
	type pt struct {
		conf float64
		hit  bool
	}
	pts := make([]pt, 0, len(ss))
	for _, s := range ss {
		p := Temper(s.P, t)
		pred, conf := argmax(p)
		pts = append(pts, pt{conf, pred == s.Label})
	}
	sort.Slice(pts, func(i, j int) bool { return pts[i].conf > pts[j].conf })
	th := Threshold{Target: target, Conf: 2}
	hits := 0
	for i, x := range pts {
		if x.hit {
			hits++
		}
		n := i + 1
		// Порог ставится только между разными значениями уверенности.
		if i+1 < len(pts) && pts[i+1].conf == x.conf {
			continue
		}
		if n >= minN && float64(hits)/float64(n) >= target {
			th = Threshold{Target: target, Conf: x.conf, Coverage: float64(n) / float64(len(pts)), Acc: float64(hits) / float64(n), N: n}
		}
	}
	return th
}

// ApplyThreshold — покрытие и точность порога на другом наборе.
func ApplyThreshold(ss []Sample, t, conf float64) (coverage, acc float64, n int) {
	hits := 0
	for _, s := range ss {
		p := Temper(s.P, t)
		pred, c := argmax(p)
		if c >= conf {
			n++
			if pred == s.Label {
				hits++
			}
		}
	}
	if len(ss) > 0 {
		coverage = float64(n) / float64(len(ss))
	}
	if n > 0 {
		acc = float64(hits) / float64(n)
	}
	return coverage, acc, n
}

// Report — замер одной модели по одному вопросу.
type Report struct {
	Source      string  `json:"source"` // laya | jev — кто спрошен
	Model       string  `json:"model"`  // версия модели из ответа (ModelAnswers.Model)
	Question    string  `json:"question"`
	Temperature float64 `json:"temperature"` // подобрана на калибровочной части
	CalibN      int     `json:"calib_n"`
	Raw         Metrics `json:"raw"`        // замер без калибровки
	Calibrated  Metrics `json:"calibrated"` // замер с температурой
	Auto        Level   `json:"auto"`       // порог автозакрытия
	Hint        Level   `json:"hint"`       // порог подсказки дежурному
}

// Level — порог, подобранный на калибровочной части, и его поведение на замере.
type Level struct {
	Fit      Threshold `json:"fit"`
	Coverage float64   `json:"coverage"`
	Acc      float64   `json:"acc"`
	N        int       `json:"n"`
}

// EvalOpts — как делить записи и какие цели у порогов.
type EvalOpts struct {
	CalibSplit string  // откуда подбирать температуру и пороги (train)
	EvalSplit  string  // где мерить (holdout)
	BlindOnly  bool    // замер только по слепой части
	TargetAuto float64 // точность для автозакрытия
	TargetHint float64 // точность для подсказки
	MinN       int     // минимум наблюдений над порогом
}

// Evaluate по всем моделям и вопросам, встреченным в записях.
func EvaluateRecords(recs []Record, o EvalOpts) []Report {
	type sv struct{ source, version string }
	models := map[sv]bool{}
	questions := map[string]bool{}
	for _, r := range recs {
		for m, ma := range r.Models {
			if ma.Error == "" {
				models[sv{m, ma.Model}] = true
			}
		}
		for q := range r.Labels {
			questions[q] = true
		}
	}
	calib := func(r *Record) bool { return r.Split == o.CalibSplit }
	eval := func(r *Record) bool { return r.Split == o.EvalSplit && (!o.BlindOnly || r.Blind) }
	var out []Report
	keys := make([]sv, 0, len(models))
	for k := range models {
		keys = append(keys, k)
	}
	sort.Slice(keys, func(i, j int) bool {
		if keys[i].source != keys[j].source {
			return keys[i].source < keys[j].source
		}
		return keys[i].version < keys[j].version
	})
	for _, m := range keys {
		for _, q := range sortedKeys(questions) {
			cs, es := Samples(recs, m.source, m.version, q, calib), Samples(recs, m.source, m.version, q, eval)
			if len(cs) == 0 && len(es) == 0 {
				continue
			}
			t := FitTemperature(cs)
			rep := Report{Source: m.source, Model: m.version, Question: q, Temperature: t, CalibN: len(cs), Raw: Evaluate(es, 1), Calibrated: Evaluate(es, t)}
			for _, lv := range []struct {
				dst    *Level
				target float64
			}{{&rep.Auto, o.TargetAuto}, {&rep.Hint, o.TargetHint}} {
				fit := FitThreshold(cs, t, lv.target, o.MinN)
				cov, acc, n := ApplyThreshold(es, t, fit.Conf)
				*lv.dst = Level{Fit: fit, Coverage: cov, Acc: acc, N: n}
			}
			out = append(out, rep)
		}
	}
	return out
}

func sortedKeys(m map[string]bool) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

// FormatPct — проценты для таблицы.
func FormatPct(v float64) string { return strconv.FormatFloat(v*100, 'f', 1, 64) }
