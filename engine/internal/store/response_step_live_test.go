package store

import (
	"context"
	"fmt"
	"path/filepath"
	"testing"
	"time"
)

// Шаг автомата (0037) пишется и читается ResponsesSince; строки без шага и без
// адреса и строки старше since не возвращаются.
func TestResponsesSinceStepLive(t *testing.T) {
	c := liveStore(t)
	ctx := context.Background()
	for _, m := range []string{"0037_response_log_step.sql", "0038_response_log_until.sql"} {
		for _, stmt := range migrationStatements(t, filepath.Join("..", "..", "..", "clickhouse", "migrations", m)) {
			if _, err := c.do(ctx, stmt, nil, nil); err != nil {
				t.Fatal(err)
			}
		}
	}
	id := fmt.Sprintf("INC-STEP-%d", time.Now().UnixNano())
	now := time.Now().UTC().Truncate(time.Second)
	ts := func(d time.Duration) string { return now.Add(d).Format("2006-01-02 15:04:05") }
	rows := []ResponseRow{
		{TS: ts(-72 * time.Hour), IncidentID: id, IP: "203.0.113.7", Mode: "ips", Executor: "argus", Step: "blocked"},
		{TS: ts(0), IncidentID: id, IP: "203.0.113.7", Mode: "ips", Executor: "argus", Step: "reserve", RuleID: "t-waf"},
		{TS: ts(0), IncidentID: id, IP: "203.0.113.7", Mode: "ips", Executor: "ngfw", OK: 1, Step: "blocked", RuleID: "t-waf"},
		{TS: ts(0), IncidentID: id, IP: "203.0.113.8", Mode: "ips", Executor: "ngfw", OK: 1},
		{TS: ts(0), IncidentID: id, Mode: "ips", Executor: "argus", Step: "capped"},
	}
	// Исключение адреса (0038): за 30 дней читается и вне окна решений, старше — нет.
	exclIP := "198.51.100.7"
	rows = append(rows,
		ResponseRow{TS: ts(-10 * 24 * time.Hour), IP: exclIP, Mode: "manual", Executor: "argus", Step: "exclude", Until: ts(10 * 24 * time.Hour), Actor: id},
		ResponseRow{TS: ts(-40 * 24 * time.Hour), IP: exclIP, Mode: "manual", Executor: "argus", Step: "exclude", Until: ts(-39 * 24 * time.Hour), Actor: id},
		// ключ, отложенный исключением 4 суток назад, и его более поздняя строка manual
		// (3 суток) — оба за окном исключений; чужой ключ без excluded — нет
		ResponseRow{TS: ts(-96 * time.Hour), IncidentID: id + "-X", IP: exclIP, Mode: "manual", Executor: "argus", Step: "excluded", Actor: id},
		ResponseRow{TS: ts(-72 * time.Hour), IncidentID: id + "-X", IP: exclIP, Mode: "manual", Executor: "argus", Step: "manual", Actor: id},
		ResponseRow{TS: ts(-72 * time.Hour), IncidentID: id + "-Y", IP: exclIP, Mode: "ips", Executor: "argus", Step: "blocked", Actor: id},
	)
	if err := c.InsertResponses(ctx, rows); err != nil {
		t.Fatal(err)
	}
	got, err := c.ResponsesSince(ctx, now.Add(-48*time.Hour), now.Add(-30*24*time.Hour))
	if err != nil {
		t.Fatal(err)
	}
	var mine, excl []ResponseRow
	for _, r := range got {
		if r.IncidentID == id {
			mine = append(mine, r)
		}
		if r.IP == exclIP && r.Actor == id {
			excl = append(excl, r)
		}
	}
	if len(excl) != 3 || excl[0].Step != "exclude" || excl[0].Until != ts(10*24*time.Hour) || excl[0].IncidentID != "" ||
		excl[1].Step != "excluded" || excl[2].Step != "manual" || excl[2].IncidentID != id+"-X" {
		t.Fatalf("исключение адреса за 30 дней: %+v", excl)
	}
	if len(mine) != 2 || mine[0].TS != ts(0) || mine[0].RuleID != "t-waf" {
		t.Fatalf("строки с шагом и адресом в окне: %+v", mine)
	}
	steps := map[string]bool{}
	for _, r := range mine {
		steps[r.Step] = true
	}
	if !steps["reserve"] || !steps["blocked"] {
		t.Fatalf("шаги: %+v", mine)
	}
}
