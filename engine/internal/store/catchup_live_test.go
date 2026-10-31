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
	"strconv"
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
		('%[1]s', '%[1]s', '%[2]s', 'dup', map('id','dup'), 'raw-A'), ('%[1]s', '%[1]s', '%[2]s', 'dup', map('id','dup'), 'raw-B')`,
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
	if len(seen) != 12001 {
		t.Fatalf("прочитано %d уникальных id из 12001 за %d запросов", len(seen), queries)
	}
	for id, n := range seen {
		want := 1
		if id == "dup" {
			want = 2 // эти события различает только raw, а не action/attrs/ts
		}
		if n != want {
			t.Fatalf("строка %s отдана %d раз", id, n)
		}
	}
	t.Logf("12002 строки за %d запросов, курсор %v, срез %v", queries, cur.At, cur.Step)
}

// Все поля, кроме raw, одинаковы. Маленький LIMIT заставляет курсор пройти
// несколько страниц одной секунды; raw не передаётся движку, но участвует в
// event_id и поэтому не может быть заменён пустым алиасом в SELECT.
func TestLiveCatchupRawOnlyPages(t *testing.T) {
	c := catchupLiveStore(t)
	ctx := context.Background()
	src := "catchup.raw." + liveSuffix(t)
	at := time.Now().UTC().Add(-time.Hour).Truncate(time.Second)
	params := map[string]string{"s": src, "at": at.Format("2006-01-02 15:04:05")}
	if _, err := c.do(ctx, `INSERT INTO events (ts, received_at, source, action, attrs, raw)
		SELECT toDateTime64({at:String}, 3, 'UTC'), toDateTime({at:String}, 'UTC'), {s:String}, 'raw-only', map('same', 'value'), concat('raw-', toString(number)) FROM numbers(8)`, nil, params); err != nil {
		t.Fatal(err)
	}
	cur := StartCursor(at)
	cur.Step = time.Second
	count := 0
	for page := 0; page < 20; page++ {
		events, next, err := c.EventsSince(ctx, cur, 3)
		if err != nil {
			t.Fatal(err)
		}
		for _, e := range events {
			if e.Source == src {
				count++
				if e.Raw != "" {
					t.Fatal("raw не должен загружаться в движок")
				}
			}
		}
		cur = next
		if cur.At.After(at) {
			break
		}
	}
	if count != 8 || !cur.At.After(at) {
		t.Fatalf("8 raw-only событий должны быть прочитаны один раз, курсор должен продвинуться: count=%d cursor=%+v", count, cur)
	}
}

// На одной грануле EXPLAIN с именем индекса ничего не доказывает. Здесь две
// группы idx_received_at (GRANULARITY 4): окно в минуту должно прочитать лишь
// часть гранул, даже без условия по ts из первичного ключа.
func TestLiveCatchupReceivedAtIndexPrunes(t *testing.T) {
	c := catchupLiveStore(t)
	ctx := context.Background()
	src := "catchup.index." + liveSuffix(t)
	base := time.Now().UTC().Add(-48 * time.Hour).Truncate(time.Second)
	params := map[string]string{"s": src, "at": base.Format("2006-01-02 15:04:05")}
	if _, err := c.do(ctx, `INSERT INTO events (ts, received_at, source, action)
		SELECT toDateTime64({at:String}, 3, 'UTC') + number, toDateTime({at:String}, 'UTC') + toUInt32(number), {s:String}, 'index-fixture' FROM numbers(65536)`, nil, params); err != nil {
		t.Fatal(err)
	}
	params["from"] = base.Add(time.Hour).Format("2006-01-02 15:04:05")
	params["to"] = base.Add(time.Hour + time.Minute).Format("2006-01-02 15:04:05")
	query := `SELECT ` + eventsSelectColumns() + `, event_id FROM events
		WHERE received_at >= {from:DateTime} AND received_at < {to:DateTime}
		ORDER BY received_at, event_id LIMIT 1000`
	plan, err := c.do(ctx, "EXPLAIN indexes = 1 "+query+" FORMAT TSV", nil, params)
	if err != nil {
		t.Fatal(err)
	}
	m := regexp.MustCompile(`(?s)Name: idx_received_at\b.*?Granules:\s*(\d+)\s*/\s*(\d+)`).FindStringSubmatch(string(plan))
	if len(m) != 3 {
		t.Fatalf("idx_received_at не применён:\n%s", plan)
	}
	selected, _ := strconv.Atoi(m[1])
	total, _ := strconv.Atoi(m[2])
	if selected == 0 || selected >= total {
		t.Fatalf("минутный срез обязан отсечь гранулы, содержащие остальной хвост:\n%s", plan)
	}
	out, err := c.do(ctx, `SELECT count() FROM events WHERE source = {s:String}
		AND received_at >= {from:DateTime} AND received_at < {to:DateTime} FORMAT TSV`, nil, params)
	if err != nil || strings.TrimSpace(string(out)) != "60" {
		t.Fatalf("минутное окно должно сохранить 60 событий: count=%q err=%v", out, err)
	}
}
