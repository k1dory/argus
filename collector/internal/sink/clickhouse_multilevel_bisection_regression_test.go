package sink

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/devitex-soft/argus/collector/internal/model"
)

type pr41BisectionTransport func(*http.Request) (*http.Response, error)

func (f pr41BisectionTransport) RoundTrip(r *http.Request) (*http.Response, error) {
	return f(r)
}

// MEMORY_LIMIT_EXCEEDED can depend on batch size, without any poison rows.
// Two failing halves do not establish that their smaller parts will fail.
// Go through the real HTTP client and writer, including the >4 KiB error path
// changed by PR #41. Transport responses model an async flush that accepts at
// most two rows. No socket, database, sleeps, or durable queue are required.
func TestPR41LargeMemoryExceptionContinuesSplittingValidRows(t *testing.T) {
	const marker = "PrivatePR41MemoryDiagnostic"
	detail := "Code: 241. DB::Exception: Memory limit exceeded: " + strings.Repeat(marker, 200)
	if len(detail) <= 4<<10 {
		t.Fatal("fixture must exceed the response-body limit")
	}
	for _, size := range []int{2, 4, 8} {
		t.Run(fmt.Sprintf("rows=%d", size), func(t *testing.T) {
			ch := New("http://clickhouse.invalid", "argus", "fixture", "fixture")
			accepted := make(map[string]int)
			var rejected []Reject
			calls := 0
			ch.http.Transport = pr41BisectionTransport(func(r *http.Request) (*http.Response, error) {
				calls++
				if calls > 32 {
					t.Fatal("unexpected retry loop in the bounded fixture")
				}
				q := r.URL.Query()
				for _, setting := range []string{"async_insert", "wait_for_async_insert", "wait_end_of_query"} {
					if q.Get(setting) != "1" {
						t.Fatalf("%s=%q, want 1 on every INSERT", setting, q.Get(setting))
					}
				}
				header, responseBody := make(http.Header), ""
				dec := json.NewDecoder(r.Body)
				switch q.Get("query") {
				case "INSERT INTO argus.events FORMAT JSONEachRow":
					var rows []model.Event
					for {
						var row model.Event
						if err := dec.Decode(&row); err == io.EOF {
							break
						} else if err != nil {
							t.Fatal(err)
						}
						rows = append(rows, row)
					}
					if len(rows) > 2 {
						header.Set("X-ClickHouse-Exception-Code", "241")
						responseBody = detail
					} else {
						for _, row := range rows {
							accepted[row.Object]++
						}
					}
				case "INSERT INTO argus.ingest_rejects FORMAT JSONEachRow":
					for {
						var row Reject
						if err := dec.Decode(&row); err == io.EOF {
							break
						} else if err != nil {
							t.Fatal(err)
						}
						rejected = append(rejected, row)
					}
				default:
					t.Fatalf("unexpected query %q", q.Get("query"))
				}
				return &http.Response{StatusCode: http.StatusOK, Header: header, Body: io.NopCloser(strings.NewReader(responseBody))}, nil
			})
			var logs bytes.Buffer
			previous := slog.Default()
			slog.SetDefault(slog.New(slog.NewTextHandler(&logs, nil)))
			t.Cleanup(func() { slog.SetDefault(previous) })
			stats := &Stats{}
			queue := NewQueue(100, stats)
			writer := NewWriter(ch, queue, stats)
			writer.Attempts = 1
			writer.Sleep = func(context.Context, time.Duration) bool { return true }
			var rows []any
			for i := 0; i < size; i++ {
				rows = append(rows, model.Event{Source: "pr41", TS: "2026-11-01 00:00:00.000", Object: fmt.Sprintf("valid-%d", i)})
			}
			writer.Write(context.Background(), rows)
			for i := 0; i < size; i++ {
				key := fmt.Sprintf("valid-%d", i)
				if accepted[key] != 1 {
					t.Errorf("%s inserted %d times, want exactly once; rejected=%d", key, accepted[key], len(rejected))
				}
			}
			if stats.Inserted.Load() != uint64(size) || stats.DeadLetter.Load() != 0 || len(rejected) != 0 {
				t.Errorf("valid rows lost to the bisection cap: inserted=%d dead=%d rejects=%d", stats.Inserted.Load(), stats.DeadLetter.Load(), len(rejected))
			}
			if stats.Retries.Load() != 0 || stats.Requeued.Load() != 0 || queue.Rows() != 0 {
				t.Errorf("memory error became a transport retry: retries=%d requeued=%d pending=%d", stats.Retries.Load(), stats.Requeued.Load(), queue.Rows())
			}
			if strings.Contains(logs.String(), marker) {
				t.Error("ClickHouse diagnostic text escaped into the collector log")
			}
		})
	}
}
