package store

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"reflect"
	"strings"
	"testing"
	"time"
)

type pr39StreamTransport func(*http.Request) (*http.Response, error)

func (f pr39StreamTransport) RoundTrip(r *http.Request) (*http.Response, error) {
	return f(r)
}

const pr39EngineQueryID = "fce0e745-a310-4bd5-8137-6d2cd57f49ac"

func pr39StreamResponse(body string) *http.Response {
	h := make(http.Header)
	h.Set("X-ClickHouse-Query-Id", pr39EngineQueryID)
	return &http.Response{
		StatusCode: http.StatusOK, Status: "200 OK", Header: h,
		Body: io.NopCloser(strings.NewReader(body)),
	}
}

// ClickHouse 24.8 can append an exception as a JSONEachRow object after
// sending HTTP 200. See JSONEachRowRowOutputFormat::writeSuffix in v24.8.14.39-lts.
// Exercise OpenIncidents -> restoreGroupKeys -> the startup logger, including
// an outer %w wrapper; only HTTP is replaced, with no listening sockets.
func TestPR39StreamedGroupKeyExceptionDoesNotDiscloseData(t *testing.T) {
	const marker = "PrivatePR39GroupKeyFixture"
	const detail = "Code: 241. DB::Exception: Memory limit exceeded while reading '" + marker + "'"
	exception, err := json.Marshal(map[string]string{"exception": detail})
	if err != nil {
		t.Fatal(err)
	}
	for _, partial := range []bool{false, true} {
		t.Run(fmt.Sprintf("partial=%t", partial), func(t *testing.T) {
			c := New("http://clickhouse.invalid", "argus", "fixture", "fixture")
			calls := 0
			c.http.Transport = pr39StreamTransport(func(r *http.Request) (*http.Response, error) {
				calls++
				query, err := io.ReadAll(r.Body)
				if err != nil {
					t.Fatal(err)
				}
				switch {
				case strings.Contains(string(query), "FROM incidents_current"):
					return pr39StreamResponse("{\"incident_id\":\"INC-39\",\"status\":\"new\"}\n"), nil
				case strings.Contains(string(query), "argMax(group_key"):
					body := string(exception) + "\n"
					if partial {
						body = "{\"incident_id\":\"INC-39\",\"group_key\":\"fixture\"}\n" + body
					}
					return pr39StreamResponse(body), nil
				default:
					t.Fatalf("unexpected query: %s", query)
					return nil, nil
				}
			})
			_, _, err := c.OpenIncidents(context.Background())
			if err == nil || calls != 2 {
				t.Fatalf("want failed group-key restoration after two requests; calls=%d err=%v", calls, err)
			}
			wrapped := fmt.Errorf("startup: %w", err)
			var logs bytes.Buffer
			log := slog.New(slog.NewTextHandler(&logs, nil))
			log.Warn("clickhouse недоступен, жду", "err", wrapped)
			if strings.Contains(wrapped.Error(), marker) || strings.Contains(logs.String(), marker) {
				t.Error("JSONEachRow exception text reaches the startup error/log through restoreGroupKeys")
			}
			for _, metadata := range []string{"HTTP 200", "code 241", "query_id " + pr39EngineQueryID} {
				if !strings.Contains(wrapped.Error(), metadata) {
					t.Errorf("missing safe diagnostic %q: %v", metadata, wrapped)
				}
			}
		})
	}
}

// Missing a streamed exception also acknowledges an incomplete events page.
// Test the public cursor API, not just the regular expression in do().
func TestPR39EventsSinceDoesNotAdvancePastStreamedException(t *testing.T) {
	const marker = "PrivatePR39StreamFixture"
	for _, tc := range []struct {
		name, tail, code string
	}{
		{"json", `{"exception":"Code: 241. DB::Exception: Memory limit exceeded for '` + marker + `'"}`, "241"},
		{"poco", "Poco::Exception. Code: 1000, e.code() = 0, I/O error: " + marker, "1000"},
		{"std", "std::exception. Code: 1001, type: std::runtime_error, e.what() = " + marker, "1001"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			cur := StartCursor(time.Now().UTC().Add(-time.Hour))
			row := fmt.Sprintf("{\"ts\":%q,\"source\":\"fixture\",\"received_str\":%q,\"event_id\":1}\n",
				cur.At.Format("2006-01-02 15:04:05"), cur.At.Format("2006-01-02 15:04:05"))
			c := New("http://clickhouse.invalid", "argus", "fixture", "fixture")
			c.http.Transport = pr39StreamTransport(func(r *http.Request) (*http.Response, error) {
				return pr39StreamResponse(row + tc.tail + "\n"), nil
			})
			rows, next, err := c.EventsSince(context.Background(), cur, 100)
			if err == nil {
				t.Error("incomplete events page was accepted as success")
			} else {
				if strings.Contains(err.Error(), marker) {
					t.Error("streamed exception text escapes in the returned error")
				}
				for _, metadata := range []string{"HTTP 200", "code " + tc.code, "query_id " + pr39EngineQueryID} {
					if !strings.Contains(err.Error(), metadata) {
						t.Errorf("missing safe diagnostic %q: %v", metadata, err)
					}
				}
			}
			if len(rows) != 0 || !reflect.DeepEqual(next, cur) {
				t.Errorf("failed page must return no events and preserve cursor; rows=%d cursor advanced=%t",
					len(rows), !reflect.DeepEqual(next, cur))
			}
		})
	}
}

// Negative control: exception-looking text in a real event is ordinary data.
func TestPR39EventsSinceAcceptsQuotedExceptionFixture(t *testing.T) {
	cur := StartCursor(time.Now().UTC().Add(-time.Hour))
	const object = `{"exception":"Code: 241. DB::Exception: example"}`
	row, err := json.Marshal(map[string]any{
		"received_str": cur.At.Format("2006-01-02 15:04:05"),
		"event_id":     1, "object": object, "source": "fixture",
	})
	if err != nil {
		t.Fatal(err)
	}
	c := New("http://clickhouse.invalid", "argus", "fixture", "fixture")
	c.http.Transport = pr39StreamTransport(func(r *http.Request) (*http.Response, error) {
		return pr39StreamResponse(string(row) + "\n"), nil
	})
	rows, _, err := c.EventsSince(context.Background(), cur, 100)
	if err != nil || len(rows) != 1 || rows[0].Object != object {
		t.Fatalf("valid event containing an exception example was rejected: rows=%v err=%v", rows, err)
	}
}
