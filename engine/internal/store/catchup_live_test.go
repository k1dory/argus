package store

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"testing"
	"time"
)

// Живой ClickHouse (ARGUS_TEST_CLICKHOUSE_URL): ключ event_id из миграции 0029 и
// догон срезами received_at. Без переменной тесты пропускаются.
func catchupLiveStore(t *testing.T) *ClickHouse {
	t.Helper()
	url := os.Getenv("ARGUS_TEST_CLICKHOUSE_URL")
	if url == "" {
		t.Skip("нет ARGUS_TEST_CLICKHOUSE_URL — тест живого ClickHouse пропущен")
	}
	user := os.Getenv("ARGUS_TEST_CLICKHOUSE_USER")
	if user == "" {
		user = "default"
	}
	pass := os.Getenv("ARGUS_TEST_CLICKHOUSE_PASSWORD")
	ctx := context.Background()
	// Все миграции по порядку (идемпотентны): CREATE DATABASE — клиентом без базы argus.
	boot := New(url, "default", user, pass)
	dir := filepath.Join("..", "..", "..", "clickhouse", "migrations")
	files, err := filepath.Glob(filepath.Join(dir, "*.sql"))
	if err != nil || len(files) == 0 {
		t.Fatalf("миграции: %v", err)
	}
	sort.Strings(files)
	comment := regexp.MustCompile(`(?m)^--.*$`)
	for _, f := range files {
		raw, err := os.ReadFile(f)
		if err != nil {
			t.Fatal(err)
		}
		for _, stmt := range regexp.MustCompile(`;\s*\n`).Split(comment.ReplaceAllString(string(raw), ""), -1) {
			if stmt = strings.TrimSpace(stmt); stmt == "" {
				continue
			}
			if _, err := boot.do(ctx, stmt, nil, nil); err != nil {
				t.Fatalf("%s: %v", filepath.Base(f), err)
			}
		}
	}
	return New(url, "argus", user, pass)
}

func liveSuffix(t *testing.T) string {
	b := make([]byte, 4)
	if _, err := rand.Read(b); err != nil {
		t.Fatal(err)
	}
	return hex.EncodeToString(b)
}

// Две строки одной секунды, различающиеся только raw, — разные ключи, и курсор
// отдаёт обе; догон по пустым и плотным срезам отдаёт каждую строку ровно один раз.
func TestLiveCatchupSlicesAndEventID(t *testing.T) {
	c := catchupLiveStore(t)
	ctx := context.Background()
	src := "catchup.live." + liveSuffix(t)
	base := time.Now().UTC().Add(-3 * time.Hour).Truncate(time.Second)
	// пара с разным raw в одной секунде
	if _, err := c.do(ctx, fmt.Sprintf(`INSERT INTO events (ts, received_at, source, action, attrs, raw) VALUES
		('%[1]s', '%[1]s', '%[2]s', 'dup', map('id','dup-a'), 'raw-A'), ('%[1]s', '%[1]s', '%[2]s', 'dup', map('id','dup-b'), 'raw-B')`,
		base.Format("2006-01-02 15:04:05"), src), nil, nil); err != nil {
		t.Fatal(err)
	}
	var ids []string
	if out, err := c.do(ctx, `SELECT toString(event_id) FROM events WHERE source = {s:String} AND action = 'dup' FORMAT TSV`, nil, map[string]string{"s": src}); err != nil {
		t.Fatal(err)
	} else {
		ids = strings.Fields(string(out))
	}
	if len(ids) != 2 || ids[0] == ids[1] {
		t.Fatalf("event_id строк с разным raw: %v", ids)
	}
	// 12 000 строк: плотный час (10 000 строк за 20 минут) и разреженный хвост с часовой дырой
	if _, err := c.do(ctx, fmt.Sprintf(`INSERT INTO events (ts, received_at, source, action, attrs)
		SELECT toDateTime64('%[1]s', 3, 'UTC') + number, toDateTime('%[1]s', 'UTC') + if(number < 10000, toUInt32(intDiv(number * 1200, 10000)), toUInt32(5400 + (toInt64(number) - 10000) * 2)),
		       '%[2]s', 'flow', map('id', toString(number))
		FROM numbers(12000)`, base.Add(time.Minute).Format("2006-01-02 15:04:05"), src), nil, nil); err != nil {
		t.Fatal(err)
	}
	cur := StartCursor(base.Add(-30 * time.Second))
	seen := map[string]int{}
	queries := 0
	for queries < 5000 {
		evs, next, err := c.EventsSince(ctx, cur, 1000)
		if err != nil {
			t.Fatal(err)
		}
		queries++
		for _, e := range evs {
			if e.Source == src {
				seen[e.Attrs["id"]]++
			}
		}
		cur = next
		if !next.More || next.At.After(base.Add(3*time.Hour)) {
			break
		}
	}
	if len(seen) != 12002 {
		t.Fatalf("прочитано %d уникальных строк из 12002 за %d запросов", len(seen), queries)
	}
	for id, n := range seen {
		if n != 1 {
			t.Fatalf("строка %s отдана %d раз", id, n)
		}
	}
	if seen["dup-a"] != 1 || seen["dup-b"] != 1 {
		t.Fatalf("пара с разным raw: %v %v", seen["dup-a"], seen["dup-b"])
	}
	t.Logf("12002 строки за %d запросов, курсор %v, срез %v", queries, cur.At, cur.Step)
}
