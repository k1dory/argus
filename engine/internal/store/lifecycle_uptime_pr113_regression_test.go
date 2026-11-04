package store

import (
	"context"
	"fmt"
	"testing"
	"time"
)

// Uses the existing ARGUS_TEST_CLICKHOUSE_URL convention. Run only against an
// isolated disposable ClickHouse. The query is tested by ClickHouse itself,
// with server-side timestamps, not by a mock interpreting the SQL string.
func TestPR113LifecycleKeepsStartOfLongRunningEngine(t *testing.T) {
	configured := liveStore(t)
	db := "argus_pr113_lifecycle_" + suffix(t)
	sys := New(configured.base, "default", configured.user, configured.pass)
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	if _, err := sys.do(ctx, "CREATE DATABASE "+db, nil, nil); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		cleanup, stop := context.WithTimeout(context.Background(), 10*time.Second)
		defer stop()
		if _, err := sys.do(cleanup, "DROP DATABASE "+db+" SYNC", nil, nil); err != nil {
			t.Errorf("cleanup fixture database: %v", err)
		}
	})
	c := New(configured.base, db, configured.user, configured.pass)
	// The columns used by LastEngineLifecycle and the production 180-day TTL
	// from migration 0005. A 31-day-old start is still retained and readable.
	if _, err := c.do(ctx, `CREATE TABLE events (
		ts DateTime64(3, 'UTC'), source String, source_class String,
		product String, node String, action String, attrs Map(String, String)
	) ENGINE = MergeTree ORDER BY ts TTL toDateTime(ts) + INTERVAL 180 DAY`, nil, nil); err != nil {
		t.Fatal(err)
	}
	for _, days := range []int{1, 31} {
		node := fmt.Sprintf("fixture-engine-%d", days)
		if _, err := c.do(ctx, `INSERT INTO events
			SELECT now() - toIntervalDay({age:UInt32}), 'argus.system', 'telemetry',
			'engine', {node:String}, 'engine.started', map('transport', 'internal')`, nil,
			map[string]string{"age": fmt.Sprint(days), "node": node}); err != nil {
			t.Fatal(err)
		}
		// A newer external stop must not hide the engine's own start.
		if _, err := c.do(ctx, `INSERT INTO events
			SELECT now(), 'argus.system', 'telemetry', 'engine', {node:String},
			'engine.stopped', map('transport', 'http')`, nil,
			map[string]string{"node": node}); err != nil {
			t.Fatal(err)
		}
		t.Run(fmt.Sprintf("uptime_%d_days", days), func(t *testing.T) {
			action, at, err := c.LastEngineLifecycle(ctx, node)
			if err != nil {
				t.Fatal(err)
			}
			if action != "engine.started" || at == "" {
				t.Fatalf("after %d days of uptime the retained start was lost: action=%q at=%q; next crash would be treated as a first run", days, action, at)
			}
		})
	}
}
