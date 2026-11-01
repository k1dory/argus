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
	for _, stmt := range migrationStatements(t, filepath.Join("..", "..", "..", "clickhouse", "migrations", "0037_response_log_step.sql")) {
		if _, err := c.do(ctx, stmt, nil, nil); err != nil {
			t.Fatal(err)
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
	if err := c.InsertResponses(ctx, rows); err != nil {
		t.Fatal(err)
	}
	got, err := c.ResponsesSince(ctx, now.Add(-48*time.Hour))
	if err != nil {
		t.Fatal(err)
	}
	var mine []ResponseRow
	for _, r := range got {
		if r.IncidentID == id {
			mine = append(mine, r)
		}
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
