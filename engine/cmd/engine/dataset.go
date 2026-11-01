package main

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"log/slog"
	"maps"
	"os"
	"slices"
	"strings"
	"time"

	"github.com/devitex-soft/argus/engine/internal/analyst"
	"github.com/devitex-soft/argus/engine/internal/dataset"
	"github.com/devitex-soft/argus/engine/internal/registry"
	"github.com/devitex-soft/argus/engine/internal/store"
	"github.com/devitex-soft/argus/engine/internal/systemone"
)

/* ===== dataset export ===== */

// labeledSource — откуда брать размеченные инциденты (ClickHouse или тест).
type labeledSource interface {
	LabeledIncidents(ctx context.Context, since string, limit int) ([]store.LabeledIncident, error)
}

type datasetOpts struct {
	Since      string
	Limit      int
	MaxPerRule int
	Source     string
	Models     []string // laya, jev — модели, которым задаются вопросы
}

type datasetStats struct {
	Labeled, Written, Capped, PIISkippedJev, ModelErrors int
	SkippedLegacy                                        int // метки формы до 0036 (dataset.Legacy)
	OmittedTechnique                                     int // техника вне кандидатов инцидента
}

// exportDataset пишет JSONL: одна строка на инцидент с меткой человека. Модели
// спрашиваются только если включены и в окружении, и в opts.Models. Jev —
// облако: инциденты с ПДн ему не отправляются никогда (в записи — пометка),
// состояние и так обезличено (analyst.DecisionState).
func exportDataset(ctx context.Context, src labeledSource, w io.Writer, o datasetOpts, laya, jev *systemone.Client) (datasetStats, error) {
	var st datasetStats
	rows, err := src.LabeledIncidents(ctx, o.Since, o.Limit)
	if err != nil {
		return st, err
	}
	st.Labeled = len(rows)
	var recs []*dataset.Record
	for _, l := range rows {
		if l.Label.LabeledByHuman && dataset.Legacy(l) {
			st.SkippedLegacy++
			continue
		}
		if r := dataset.Build(l, o.Source); r != nil {
			if len(r.OmittedLabels) > 0 {
				st.OmittedTechnique++
			}
			recs = append(recs, r)
		}
	}
	before := len(recs)
	recs = dataset.Cap(recs, o.MaxPerRule)
	st.Capped = before - len(recs)

	want := map[string]bool{}
	for _, m := range o.Models {
		want[strings.TrimSpace(m)] = true
	}
	bw := bufio.NewWriter(w)
	enc := json.NewEncoder(bw)
	enc.SetEscapeHTML(false)
	for _, r := range recs {
		ask := func(c *systemone.Client) {
			if c == nil || !want[c.Name] {
				return
			}
			if r.Models == nil {
				r.Models = map[string]dataset.ModelAnswers{}
			}
			if c.Name == "jev" && r.PII {
				st.PIISkippedJev++
				r.Models[c.Name] = dataset.ModelAnswers{Model: c.Model, Error: "pii: не отправлялся в облако"}
				return
			}
			cctx, cancel := context.WithTimeout(ctx, 90*time.Second)
			defer cancel()
			ma, err := askModel(cctx, c, r)
			if err != nil {
				st.ModelErrors++
				r.Models[c.Name] = dataset.ModelAnswers{Model: c.Model, Error: err.Error()}
				return
			}
			r.Models[c.Name] = ma
		}
		ask(laya)
		ask(jev)
		if err := enc.Encode(r); err != nil {
			return st, err
		}
		st.Written++
	}
	return st, bw.Flush()
}

// askModel задаёт модели вопросы записи. Техника ATT&CK — вторым шагом
// (DECISIONS §8): кандидаты строятся по тактике, которую ответила модель, а не
// человек — иначе ответ человека попал бы в вопрос.
func askModel(ctx context.Context, c *systemone.Client, r *dataset.Record) (dataset.ModelAnswers, error) {
	first := r.Questions
	_, twoStep := first["attack_technique"]
	if twoStep {
		first = maps.Clone(first)
		delete(first, "attack_technique")
	}
	resp, err := c.Decide(ctx, r.State, first)
	if err != nil {
		return dataset.ModelAnswers{}, err
	}
	ma := dataset.ModelAnswers{Model: orDefault(resp.Model, c.Model), Answers: resp.Answers}
	if !twoStep {
		return ma, nil
	}
	tq := dataset.TechniqueQuestion(r.Tags, choiceOf(resp.Answers["attack_tactic"]))
	resp2, err := c.Decide(ctx, r.State, map[string]systemone.Question{"attack_technique": tq})
	if err != nil {
		return dataset.ModelAnswers{}, fmt.Errorf("attack_technique: %w", err)
	}
	// У записи одна версия модели на все ответы: если за псевдонимом модели
	// между запросами выкатили другую ревизию, пару не смешиваем.
	if resp2.Model != resp.Model {
		return dataset.ModelAnswers{}, errors.New("systemone " + c.Name + ": model revision changed between requests")
	}
	ma.Answers = maps.Clone(ma.Answers)
	ma.Answers["attack_technique"] = resp2.Answers["attack_technique"]
	ma.Questions = map[string]systemone.Question{"attack_technique": tq}
	return ma, nil
}

// choiceOf — выбранный вариант: choice, а без него — наибольшая вероятность.
func choiceOf(a systemone.Answer) string {
	if a.Choice != "" {
		return a.Choice
	}
	best, bp := "", -1.0
	for _, k := range slices.Sorted(maps.Keys(a.Probabilities)) {
		if a.Probabilities[k] > bp {
			best, bp = k, a.Probabilities[k]
		}
	}
	return best
}

const datasetUsage = `engine dataset export [--since 2026-11-01] [--limit 50000] [--max-per-rule 100] [--source prod] [--models laya,jev] [--out file.jsonl]
engine dataset eval --in file.jsonl [--calib train] [--eval holdout] [--all] [--target-auto 0.98] [--target-hint 0.85] [--min-n 10] [--json]`

func datasetCmd(args []string) int {
	if len(args) > 0 && args[0] == "eval" {
		return datasetEvalCmd(args[1:], os.Stdout)
	}
	if len(args) == 0 || args[0] != "export" {
		fmt.Fprintln(os.Stderr, datasetUsage)
		return 2
	}
	fs := flag.NewFlagSet("dataset export", flag.ExitOnError)
	since := fs.String("since", "1970-01-01", "метки не раньше (ISO 8601, UTC)")
	limit := fs.Int("limit", 50000, "не больше меток")
	maxPerRule := fs.Int("max-per-rule", dataset.MaxPerRule, "потолок записей на правило (0 — без потолка)")
	source := fs.String("source", "prod", "источник: prod | emulation | honeypot | chaos")
	models := fs.String("models", "", "кого спросить: laya,jev (нужны и флаг, и окружение ARGUS_LAYA_ENDPOINT / ARGUS_JEV_ENABLED=1)")
	outPath := fs.String("out", "-", "файл JSONL, - — stdout")
	_ = fs.Parse(args[1:])

	// Секрет выгрузки: псевдонимы, group_id и разбиение train/holdout — HMAC с
	// ним. Один секрет на все выгрузки (vault_argus_dataset_secret), иначе
	// группы перемешаются между train и holdout разных выгрузок. В JSONL не пишется.
	secret := os.Getenv("ARGUS_DATASET_SECRET")
	if len(secret) < 32 {
		fmt.Fprintln(os.Stderr, "нужен ARGUS_DATASET_SECRET (не короче 32 символов): один и тот же для всех выгрузок")
		return 2
	}
	analyst.SetDatasetSecret([]byte(secret))
	// Реестр поставляемого набора — из копии в образе (ARGUS_SHIPPED_DIR,
	// по умолчанию /usr/share/argus/shipped). Без него каждое правило было бы
	// «[rule]», а каждое действие — «[action]»: выгрузка бесполезна, поэтому отказ.
	if err := registry.LoadEnv(); err != nil {
		fmt.Fprintln(os.Stderr, "реестр поставляемого набора:", err)
		return 2
	}
	laya, jev := systemone.FromEnv(os.Getenv)
	var list []string
	if *models != "" {
		list = strings.Split(*models, ",")
		for _, m := range list {
			m = strings.TrimSpace(m)
			if (m == "laya" && laya == nil) || (m == "jev" && jev == nil) {
				fmt.Fprintf(os.Stderr, "модель %s не включена в окружении\n", m)
				return 2
			} else if m != "laya" && m != "jev" {
				fmt.Fprintf(os.Stderr, "неизвестная модель %q\n", m)
				return 2
			}
		}
	}
	w := io.Writer(os.Stdout)
	if *outPath != "-" {
		f, err := os.OpenFile(*outPath, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0o600)
		if err != nil {
			slog.Error("dataset", "err", err)
			return 1
		}
		defer f.Close()
		w = f
	}
	ch := store.New(env("CLICKHOUSE_URL", "http://localhost:8123"), env("CLICKHOUSE_DB", "argus"),
		env("CLICKHOUSE_USER", "default"), os.Getenv("CLICKHOUSE_PASSWORD"))
	st, err := exportDataset(context.Background(), ch, w, datasetOpts{
		Since: *since, Limit: *limit, MaxPerRule: *maxPerRule, Source: *source, Models: list,
	}, laya, jev)
	if err != nil {
		slog.Error("dataset", "err", err)
		return 1
	}
	slog.Info("dataset export", "labeled", st.Labeled, "written", st.Written, "capped", st.Capped,
		"pii_skipped_jev", st.PIISkippedJev, "model_errors", st.ModelErrors,
		"skipped_legacy_label", st.SkippedLegacy, "omitted_technique", st.OmittedTechnique)
	return 0
}

/* ===== dataset eval ===== */

func readDataset(path string) ([]dataset.Record, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	var out []dataset.Record
	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 1<<20), 64<<20)
	for n := 1; sc.Scan(); n++ {
		line := strings.TrimSpace(sc.Text())
		if line == "" {
			continue
		}
		var r dataset.Record
		if err := json.Unmarshal([]byte(line), &r); err != nil {
			return nil, fmt.Errorf("%s:%d: %w", path, n, err)
		}
		if r.Schema != dataset.Schema {
			return nil, fmt.Errorf("%s:%d: схема %q, ждали %q — записи разных версий не смешиваются", path, n, r.Schema, dataset.Schema)
		}
		out = append(out, r)
	}
	return out, sc.Err()
}

// datasetEvalCmd — замеры моделей по JSONL: метрики до и после калибровки
// температуры, пороги автозакрытия и подсказки. По умолчанию замер — по
// слепой отложенной части, калибровка — по train (DECISIONS §3, §6).
func datasetEvalCmd(args []string, w io.Writer) int {
	fs := flag.NewFlagSet("dataset eval", flag.ContinueOnError)
	in := fs.String("in", "", "JSONL из dataset export")
	calib := fs.String("calib", "train", "часть для калибровки температуры и порогов")
	evalSplit := fs.String("eval", "holdout", "часть для замера")
	all := fs.Bool("all", false, "мерить по всей части, а не только по слепой")
	targetAuto := fs.Float64("target-auto", 0.98, "точность для автозакрытия")
	targetHint := fs.Float64("target-hint", 0.85, "точность для подсказки дежурному")
	minN := fs.Int("min-n", 10, "минимум наблюдений над порогом")
	asJSON := fs.Bool("json", false, "вывод JSON")
	if err := fs.Parse(args); err != nil || *in == "" {
		fmt.Fprintln(os.Stderr, datasetUsage)
		return 2
	}
	recs, err := readDataset(*in)
	if err != nil {
		slog.Error("dataset eval", "err", err)
		return 1
	}
	reps := dataset.EvaluateRecords(recs, dataset.EvalOpts{
		CalibSplit: *calib, EvalSplit: *evalSplit, BlindOnly: !*all,
		TargetAuto: *targetAuto, TargetHint: *targetHint, MinN: *minN,
	})
	if *asJSON {
		enc := json.NewEncoder(w)
		enc.SetIndent("", "  ")
		if err := enc.Encode(reps); err != nil {
			slog.Error("dataset eval: запись отчёта", "err", err)
			return 1
		}
		return 0
	}
	pct := dataset.FormatPct
	level := func(l dataset.Level) string {
		if l.Fit.Conf > 1 {
			return "—"
		}
		return fmt.Sprintf("≥%.2f: %s%% / %s%%", l.Fit.Conf, pct(l.Coverage), pct(l.Acc))
	}
	bw := bufio.NewWriter(w)
	fmt.Fprintf(bw, "%-6s %-20s %-17s %5s %6s %6s %6s %6s %5s %6s %6s  %-24s %-24s\n",
		"source", "model", "question", "n", "acc", "soft", "brier", "ece", "T", "ece_T", "soft_T", "auto: cov / acc", "hint: cov / acc")
	for _, r := range reps {
		fmt.Fprintf(bw, "%-6s %-20s %-17s %5d %6s %6s %6.3f %6.3f %5.2f %6.3f %6s  %-24s %-24s\n",
			r.Source, r.Model, r.Question, r.Raw.N, pct(r.Raw.Acc), pct(r.Raw.SoftAcc), r.Raw.Brier, r.Raw.ECE,
			r.Temperature, r.Calibrated.ECE, pct(r.Calibrated.SoftAcc), level(r.Auto), level(r.Hint))
	}
	// bufio запоминает первую ошибку записи и возвращает её из Flush.
	if err := bw.Flush(); err != nil {
		slog.Error("dataset eval: запись отчёта", "err", err)
		return 1
	}
	return 0
}
