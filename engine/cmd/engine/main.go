// engine — ядро корреляции ARGUS: правила из репозитория (перечитываются на
// лету), инциденты со статусами, исключения из консоли, авто-закрытие,
// обогащение, LLM-аналитик, уведомления, метрики. Подкоманды:
//
//	engine run                          — рабочий цикл над ClickHouse
//	engine rules list                   — какие правила загружены
//	engine rules test --replay f.ndjson — прогнать правила по записанному трафику
//	engine rules test                   — тесты из rules/tests/*.yml
package main

import (
	"bufio"
	"encoding/json"
	"flag"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"time"

	"gopkg.in/yaml.v3"

	"github.com/devitex-soft/argus/engine/internal/eval"
	"github.com/devitex-soft/argus/engine/internal/model"
	"github.com/devitex-soft/argus/engine/internal/rules"
)

func env(key, def string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return def
}

func envInt(key string, def int) int {
	if n, err := strconv.Atoi(strings.TrimSpace(os.Getenv(key))); err == nil && n >= 0 {
		return n
	}
	return def
}

func orDefault(v, def string) string {
	if v == "" {
		return def
	}
	return v
}

func main() {
	slog.SetDefault(slog.New(slog.NewTextHandler(os.Stderr, nil)))
	rulesDir := env("RULES_DIR", "rules")
	args := os.Args[1:]
	if len(args) == 0 {
		args = []string{"run"}
	}
	switch args[0] {
	case "run":
		run(rulesDir)
	case "rules":
		if len(args) < 2 {
			fmt.Fprintln(os.Stderr, "engine rules list | test [--replay file] [--dir rules]")
			os.Exit(2)
		}
		switch args[1] {
		case "list":
			for _, r := range mustLoad(rulesDir) {
				fmt.Printf("%-28s %-9s %-40s %s\n", r.ID, r.Level, r.Title, r.File)
			}
		case "test":
			os.Exit(rulesTest(rulesDir, args[2:]))
		default:
			fmt.Fprintln(os.Stderr, "неизвестная подкоманда rules", args[1])
			os.Exit(2)
		}
	default:
		fmt.Fprintln(os.Stderr, "неизвестная команда", args[0])
		os.Exit(2)
	}
}

func mustLoad(dir string) []*rules.Rule {
	rs, err := rules.Load(dir)
	if err != nil {
		slog.Error("rules", "err", err)
		os.Exit(1)
	}
	return rs
}

func readNDJSON(path string) ([]*model.Event, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	var out []*model.Event
	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 1<<20), 16<<20)
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		var e model.Event
		if err := json.Unmarshal([]byte(line), &e); err != nil {
			return nil, fmt.Errorf("%s: %w", path, err)
		}
		e.Ensure()
		out = append(out, &e)
	}
	return out, sc.Err()
}

/* ===== rules test ===== */

type ruleTest struct {
	Rule            string `yaml:"rule"`
	Fixture         string `yaml:"fixture"`
	ExpectIncidents int    `yaml:"expect_incidents"`
	ExpectActor     string `yaml:"expect_actor"`
	MinEvents       int    `yaml:"min_events"`
	NowOffset       string `yaml:"now_offset"`                // absence: «сейчас» = последнее событие + смещение
	RespondMin      int    `yaml:"expect_respond_min_events"` // порог respond.min_events правила (0 — не проверять)
}

func rulesTest(defaultDir string, argv []string) int {
	fs := flag.NewFlagSet("rules test", flag.ExitOnError)
	replay := fs.String("replay", "", "NDJSON с событиями единой схемы: показать сработки всех правил")
	dir := fs.String("dir", defaultDir, "каталог правил")
	_ = fs.Parse(argv)
	rs := mustLoad(*dir)

	if *replay != "" {
		events, err := readNDJSON(*replay)
		if err != nil {
			slog.Error("replay", "err", err)
			return 1
		}
		dets := eval.Run(rs, events)
		byRule := map[string][]eval.Detection{}
		for _, d := range dets {
			byRule[d.Rule.ID] = append(byRule[d.Rule.ID], d)
		}
		fmt.Printf("→ %d событий, %d правил, %d сработок\n", len(events), len(rs), len(dets))
		for _, r := range rs {
			ds := byRule[r.ID]
			mark := "  "
			if len(ds) > 0 {
				mark = "✳ "
			}
			fmt.Printf("%s%-28s %-9s %3d", mark, r.ID, r.Level, len(ds))
			if len(ds) > 0 {
				fmt.Printf("   %s · %d событий", ds[0].Key, len(ds[0].Events))
				if ds[0].Reason != "" {
					fmt.Printf(" · %s", ds[0].Reason)
				}
			}
			fmt.Println()
		}
		return 0
	}

	paths, _ := filepath.Glob(filepath.Join(*dir, "tests", "*.yml"))
	sort.Strings(paths)
	if len(paths) == 0 {
		fmt.Println("нет тестов в", filepath.Join(*dir, "tests"))
		return 0
	}
	ruleByID := map[string]*rules.Rule{}
	for _, r := range rs {
		ruleByID[r.ID] = r
	}
	failed := 0
	for _, p := range paths {
		raw, err := os.ReadFile(p)
		var tc ruleTest
		if err == nil {
			err = yaml.Unmarshal(raw, &tc)
		}
		if err != nil {
			fmt.Printf("FAIL %s: %v\n", filepath.Base(p), err)
			failed++
			continue
		}
		r, ok := ruleByID[tc.Rule]
		if !ok {
			fmt.Printf("FAIL %s: правило %q не найдено\n", filepath.Base(p), tc.Rule)
			failed++
			continue
		}
		fixture := tc.Fixture
		if !filepath.IsAbs(fixture) {
			fixture = filepath.Join(filepath.Dir(*dir), fixture)
		}
		events, err := readNDJSON(fixture)
		if err != nil {
			fmt.Printf("FAIL %s: %v\n", filepath.Base(p), err)
			failed++
			continue
		}
		in := eval.Input{Rules: []*rules.Rule{r}, Events: events}
		if tc.NowOffset != "" && len(events) > 0 {
			if d, err := time.ParseDuration(tc.NowOffset); err == nil {
				last := time.Time{}
				for _, e := range events {
					if t := e.Time(); t.After(last) {
						last = t
					}
				}
				in.Now = last.Add(d)
			}
		}
		dets, _ := eval.Evaluate(in)
		var problems []string
		if len(dets) != tc.ExpectIncidents {
			problems = append(problems, fmt.Sprintf("сработок %d, ожидалось %d", len(dets), tc.ExpectIncidents))
		}
		if tc.ExpectActor != "" && (len(dets) == 0 || dets[0].Key != tc.ExpectActor) {
			got := "—"
			if len(dets) > 0 {
				got = dets[0].Key
			}
			problems = append(problems, fmt.Sprintf("субъект %q, ожидался %q", got, tc.ExpectActor))
		}
		if tc.MinEvents > 0 && (len(dets) == 0 || len(dets[0].Events) < tc.MinEvents) {
			problems = append(problems, fmt.Sprintf("в сработке меньше %d событий", tc.MinEvents))
		}
		if tc.RespondMin > 0 && r.RespondMinEvents() != tc.RespondMin {
			problems = append(problems, fmt.Sprintf("respond.min_events %d, ожидалось %d", r.RespondMinEvents(), tc.RespondMin))
		}
		if len(problems) > 0 {
			failed++
			fmt.Printf("FAIL %-32s %s\n", filepath.Base(p), strings.Join(problems, "; "))
		} else {
			fmt.Printf("ok   %-32s %s · %d событий\n", filepath.Base(p), tc.Rule, len(events))
		}
	}
	fmt.Printf("→ %d тестов, %d провалено\n", len(paths), failed)
	if failed > 0 {
		return 1
	}
	return 0
}
