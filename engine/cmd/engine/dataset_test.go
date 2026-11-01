package main

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"github.com/devitex-soft/argus/engine/internal/registry"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/devitex-soft/argus/engine/internal/dataset"
	"github.com/devitex-soft/argus/engine/internal/incidents"
	"github.com/devitex-soft/argus/engine/internal/store"
	"github.com/devitex-soft/argus/engine/internal/systemone"
)

type fakeLabeled []store.LabeledIncident

func (f fakeLabeled) LabeledIncidents(context.Context, string, int) ([]store.LabeledIncident, error) {
	return f, nil
}

func boolp(v bool) *bool { return &v }

func u8p(v uint8) *uint8 { return &v }

func labeled(id string, pii uint8, human bool) store.LabeledIncident {
	return store.LabeledIncident{
		Incident: incidents.Incident{IncidentID: id, RuleID: "a41c-auth-031", RuleTitle: "SSH brute force", Level: "high",
			Tags: []string{"attack.credential_access"}, Status: incidents.StatusClosed, ActorName: "203.0.113." + id[len(id)-1:],
			Node: "web-1", PII: pii, Chain: []string{"auth.ssh failure"}},
		Label: store.ClosureLabel{Disposition: "malicious", Escalate: boolp(true), SeverityLevel: u8p(4), AttackTactic: "credential-access",
			AttackTechnique: "T1110", AttackVersion: "20.0", LabeledByHuman: human},
	}
}

// decisionServer — System One на httptest: отвечает на любой набор вопросов
// равномерным распределением и считает запросы и состояния, которые получил.
func decisionServer(t *testing.T, calls *atomic.Int32, states *[]string) *httptest.Server {
	t.Helper()
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls.Add(1)
		var req struct {
			State     string                        `json:"state"`
			Questions map[string]systemone.Question `json:"questions"`
		}
		body, _ := io.ReadAll(r.Body)
		if err := json.Unmarshal(body, &req); err != nil {
			t.Error(err)
		}
		*states = append(*states, req.State)
		answers := map[string]any{}
		for id, q := range req.Questions {
			switch q.Type {
			case systemone.Noul:
				answers[id] = map[string]any{"type": "noul", "noul": 0.5}
			case systemone.Score:
				n := len(q.Criteria.([]any))
				probs := map[string]float64{}
				for i := 0; i < n; i++ {
					probs[strconv.Itoa(i)] = 1 / float64(n)
				}
				answers[id] = map[string]any{"type": "score", "score": 0, "confidence": 0.1, "probabilities": probs}
			case systemone.Choice:
				crit, _ := q.Criteria.(map[string]any)
				probs := map[string]float64{}
				var first string
				for k := range crit {
					probs[k] = 1 / float64(len(crit))
					first = k
				}
				answers[id] = map[string]any{"type": "choice", "choice": first, "confidence": 0.1, "probabilities": probs}
			}
		}
		_ = json.NewEncoder(w).Encode(map[string]any{"model": "m-1", "answers": answers})
	}))
}

func readRecords(t *testing.T, b *bytes.Buffer) []dataset.Record {
	t.Helper()
	var out []dataset.Record
	sc := bufio.NewScanner(b)
	sc.Buffer(make([]byte, 1<<20), 1<<24)
	for sc.Scan() {
		var r dataset.Record
		if err := json.Unmarshal(sc.Bytes(), &r); err != nil {
			t.Fatal(err)
		}
		out = append(out, r)
	}
	return out
}

func TestExportDatasetNoModelsByDefault(t *testing.T) {
	var calls atomic.Int32
	var states []string
	srv := decisionServer(t, &calls, &states)
	defer srv.Close()
	laya := &systemone.Client{Name: "laya", Endpoint: srv.URL}
	var out bytes.Buffer
	st, err := exportDataset(context.Background(), fakeLabeled{labeled("INC-1", 0, true), labeled("INC-2", 0, false)},
		&out, datasetOpts{MaxPerRule: 100, Source: "prod"}, laya, nil)
	if err != nil {
		t.Fatal(err)
	}
	recs := readRecords(t, &out)
	if st.Labeled != 2 || st.Written != 1 || len(recs) != 1 || recs[0].IncidentID != "INC-1" {
		t.Fatalf("только метки человека: %+v %d", st, len(recs))
	}
	if calls.Load() != 0 || recs[0].Models != nil {
		t.Fatal("без --models модели не спрашиваются, даже если включены в окружении")
	}
}

func TestExportDatasetAsksModelsJevNeverGetsPII(t *testing.T) {
	var layaCalls, jevCalls atomic.Int32
	var layaStates, jevStates []string
	ls, js := decisionServer(t, &layaCalls, &layaStates), decisionServer(t, &jevCalls, &jevStates)
	defer ls.Close()
	defer js.Close()
	laya := &systemone.Client{Name: "laya", Endpoint: ls.URL, Model: "laya-multilingual"}
	jev := &systemone.Client{Name: "jev", Endpoint: js.URL, APIKey: "k", Model: "typesafe/jev-1.13"}
	var out bytes.Buffer
	st, err := exportDataset(context.Background(), fakeLabeled{labeled("INC-1", 0, true), labeled("INC-2", 1, true)},
		&out, datasetOpts{MaxPerRule: 100, Source: "prod", Models: []string{"laya", "jev"}}, laya, jev)
	if err != nil {
		t.Fatal(err)
	}
	recs := readRecords(t, &out)
	// Два запроса на запись: вопросы без техники, затем техника по тактике модели.
	if len(recs) != 2 || layaCalls.Load() != 4 || jevCalls.Load() != 2 || st.PIISkippedJev != 1 || st.ModelErrors != 0 {
		t.Fatalf("laya=%d jev=%d stats=%+v", layaCalls.Load(), jevCalls.Load(), st)
	}
	for _, r := range recs {
		la := r.Models["laya"]
		if la.Model != "m-1" || len(la.Answers) != 5 {
			t.Fatalf("%s: ответ Laya: %+v", r.IncidentID, la)
		}
		tactic := la.Answers["attack_tactic"].Choice
		want := dataset.TechniqueQuestion(r.Tags, tactic)
		got := la.Questions["attack_technique"]
		gj, _ := json.Marshal(got.Criteria)
		wj, _ := json.Marshal(want.Criteria)
		if tactic == "" || len(got.Options()) != len(want.Options()) || string(gj) != string(wj) {
			t.Fatalf("%s: кандидаты техники не по тактике модели %q: %v", r.IncidentID, tactic, got.Options())
		}
		jevAns := r.Models["jev"]
		if r.PII && (jevAns.Error == "" || jevAns.Answers != nil) {
			t.Fatalf("%s с ПДн: Jev не спрашивается, в записи — причина: %+v", r.IncidentID, jevAns)
		}
		if !r.PII && len(jevAns.Answers) != 5 {
			t.Fatalf("%s без ПДн: ответ Jev: %+v", r.IncidentID, jevAns)
		}
	}
	for _, s := range append(layaStates, jevStates...) {
		if strings.Contains(s, "web-1") || strings.Contains(s, "INC-") {
			t.Fatalf("модели получили необезличенное состояние:\n%s", s)
		}
	}
}

func TestExportDatasetModelErrorKeepsRecord(t *testing.T) {
	fail := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "down", http.StatusBadGateway)
	}))
	defer fail.Close()
	var out bytes.Buffer
	st, err := exportDataset(context.Background(), fakeLabeled{labeled("INC-1", 0, true)}, &out,
		datasetOpts{Models: []string{"laya"}}, &systemone.Client{Name: "laya", Endpoint: fail.URL}, nil)
	if err != nil {
		t.Fatal(err)
	}
	recs := readRecords(t, &out)
	if st.ModelErrors != 1 || len(recs) != 1 || !strings.Contains(recs[0].Models["laya"].Error, "HTTP 502") {
		t.Fatalf("ошибка модели не роняет выгрузку: %+v %+v", st, recs)
	}
}

// Сквозной прогон: export с моделью на httptest → eval по тому же JSONL.
func TestDatasetEvalCmdOnExport(t *testing.T) {
	var calls atomic.Int32
	var states []string
	srv := decisionServer(t, &calls, &states)
	defer srv.Close()
	var rows fakeLabeled
	for i := 0; i < 400; i++ {
		l := labeled(fmt.Sprintf("INC-%d", i), 0, true)
		l.Incident.ActorName = fmt.Sprintf("198.%d.%d.1", i/200, i%200) // разные /24 — разные группы
		l.Label.Blind = i%2 == 0
		rows = append(rows, l)
	}
	path := filepath.Join(t.TempDir(), "ds.jsonl")
	f, err := os.Create(path)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := exportDataset(context.Background(), rows, f, datasetOpts{MaxPerRule: 0, Models: []string{"laya"}},
		&systemone.Client{Name: "laya", Endpoint: srv.URL}, nil); err != nil {
		t.Fatal(err)
	}
	f.Close()
	var out bytes.Buffer
	if code := datasetEvalCmd([]string{"--in", path}, &out); code != 0 {
		t.Fatalf("код %d", code)
	}
	for _, want := range []string{"laya", "disposition", "escalate", "severity_level", "attack_tactic", "attack_technique"} {
		if !strings.Contains(out.String(), want) {
			t.Fatalf("нет %q в выводе:\n%s", want, out.String())
		}
	}
	out.Reset()
	if code := datasetEvalCmd([]string{"--in", path, "--json"}, &out); code != 0 {
		t.Fatal("json")
	}
	var reps []dataset.Report
	if err := json.Unmarshal(out.Bytes(), &reps); err != nil || len(reps) != 5 {
		t.Fatalf("json: %v %d", err, len(reps))
	}
	for _, r := range reps {
		if r.Raw.N == 0 || r.CalibN == 0 || r.Raw.N >= r.CalibN {
			t.Fatalf("%s: замер на слепой отложенной части меньше калибровочной: %+v", r.Question, r)
		}
	}
}

func TestReadDatasetRejectsOtherSchema(t *testing.T) {
	path := filepath.Join(t.TempDir(), "old.jsonl")
	_ = os.WriteFile(path, []byte(`{"schema":"argus-dataset/v0"}`+"\n"), 0o600)
	if _, err := readDataset(path); err == nil || !strings.Contains(err.Error(), "схема") {
		t.Fatalf("чужая схема: %v", err)
	}
}

// Без секрета выгрузки export отказывает до обращения к ClickHouse и моделям:
// иначе псевдонимы и разбиение не совпали бы между выгрузками.
func TestDatasetExportRequiresSecret(t *testing.T) {
	t.Setenv("ARGUS_DATASET_SECRET", "short")
	t.Setenv("CLICKHOUSE_URL", "http://127.0.0.1:1")
	if code := datasetCmd([]string{"export", "--out", filepath.Join(t.TempDir(), "x.jsonl")}); code != 2 {
		t.Fatalf("код %d", code)
	}
}

// Без копии поставляемого набора export отказывает: иначе все правила и
// действия стали бы «[rule]» / «[action]».
func TestDatasetExportRequiresShippedRegistry(t *testing.T) {
	t.Setenv("ARGUS_DATASET_SECRET", strings.Repeat("s", 32))
	t.Setenv("ARGUS_SHIPPED_DIR", t.TempDir())
	t.Setenv("CLICKHOUSE_URL", "http://127.0.0.1:1")
	if code := datasetCmd([]string{"export", "--out", filepath.Join(t.TempDir(), "x.jsonl")}); code != 2 {
		t.Fatalf("код %d", code)
	}
}

// Старт движка: реестр есть — info с размерами, нет — warn без отказа.
func TestLogShippedRegistry(t *testing.T) {
	var buf bytes.Buffer
	prev := slog.Default()
	slog.SetDefault(slog.New(slog.NewTextHandler(&buf, nil)))
	t.Cleanup(func() { slog.SetDefault(prev); _ = registry.LoadRepo() })
	t.Setenv("ARGUS_SHIPPED_DIR", t.TempDir())
	logShippedRegistry()
	if !strings.Contains(buf.String(), "level=WARN") || !strings.Contains(buf.String(), "dataset export откажет") {
		t.Fatalf("без набора — предупреждение: %s", buf.String())
	}
}
