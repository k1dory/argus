package sink

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"strconv"
	"strings"
	"testing"
	"time"
)

type pr39CollectorTransport func(*http.Request) (*http.Response, error)

func (f pr39CollectorTransport) RoundTrip(r *http.Request) (*http.Response, error) {
	return f(r)
}

// A bounded body read must not discard an already available exception code.
// A single rejected row must reach ingest_rejects, rather than re-entering the
// transport retry queue indefinitely while no other batches make progress.
func TestPR39LargeHTTP200ExceptionKeepsWriterClassification(t *testing.T) {
	const marker = "PrivatePR39CollectorFixture"
	for _, status := range []int{http.StatusBadRequest, http.StatusOK} {
		for _, code := range []int{27, 241} {
			for _, header := range []bool{false, true} {
				t.Run(fmt.Sprintf("status=%d/code=%d/header=%t", status, code, header), func(t *testing.T) {
					// A long diagnostic from a late INSERT failure, not a large
					// successful query result. The exception code is at the start.
					detail := fmt.Sprintf("Code: %d. DB::Exception: ", code) + strings.Repeat(marker, 200)
					if len(detail) <= 4<<10 {
						t.Fatal("fixture must exceed the diagnostic body limit")
					}
					ch := New("http://clickhouse.invalid", "argus", "fixture", "fixture")
					var rejects []Reject
					eventCalls, rejectCalls := 0, 0
					ch.http.Transport = pr39CollectorTransport(func(r *http.Request) (*http.Response, error) {
						h := make(http.Header)
						responseStatus, responseBody := http.StatusOK, ""
						switch r.URL.Query().Get("query") {
						case "INSERT INTO argus.events FORMAT JSONEachRow":
							eventCalls++
							responseStatus, responseBody = status, detail
							if header {
								h.Set("X-ClickHouse-Exception-Code", strconv.Itoa(code))
							}
						case "INSERT INTO argus.ingest_rejects FORMAT JSONEachRow":
							rejectCalls++
							var row Reject
							if err := json.NewDecoder(r.Body).Decode(&row); err != nil {
								t.Fatal(err)
							}
							rejects = append(rejects, row)
						default:
							t.Fatalf("unexpected query: %s", r.URL.Query().Get("query"))
						}
						return &http.Response{
							StatusCode: responseStatus, Header: h,
							Body: io.NopCloser(strings.NewReader(responseBody)),
						}, nil
					})
					var logs bytes.Buffer
					previous := slog.Default()
					slog.SetDefault(slog.New(slog.NewJSONHandler(&logs, nil)))
					t.Cleanup(func() { slog.SetDefault(previous) })
					stats := &Stats{}
					queue := NewQueue(100, stats)
					w := NewWriter(ch, queue, stats)
					w.Attempts = 2
					w.Sleep = func(context.Context, time.Duration) bool { return true }
					w.Write(context.Background(), []any{ev("single-rejected-row")})
					if eventCalls != 1 || rejectCalls != 1 || queue.Rows() != 0 || stats.Retries.Load() != 0 || stats.DeadLetter.Load() != 1 {
						t.Errorf("code %d lost to transport retries: event calls=%d reject calls=%d pending=%d retries=%d dead=%d",
							code, eventCalls, rejectCalls, queue.Rows(), stats.Retries.Load(), stats.DeadLetter.Load())
					}
					if len(rejects) == 1 && !strings.Contains(rejects[0].Reason, marker) {
						t.Error("restricted ingest_rejects.reason lost the exception detail")
					}
					if strings.Contains(logs.String(), marker) {
						t.Error("exception detail escaped into the collector log")
					}
				})
			}
		}
	}
}

// Control for PR #39 itself: wrapping a typed error must retain retry
// classification and reject detail, while keeping the public error/log safe.
func TestPR39WrappedErrorRetainsPrivateRejectDetail(t *testing.T) {
	const marker = "PrivatePR39WrappedFixture"
	ce := parseError("events", http.StatusBadRequest, "27", "Code: 27. DB::Exception: Cannot parse '"+marker+"'")
	err := fmt.Errorf("write batch: %w", ce)
	if !IsPermanent(err) || IsDivisible(err) {
		t.Fatal("wrapped error lost its data-error classification")
	}
	if strings.Contains(err.Error(), marker) || !strings.Contains(full(err), marker) {
		t.Fatal("public error and restricted reject detail no longer have separate disclosure policies")
	}
	var logs bytes.Buffer
	log := slog.New(slog.NewJSONHandler(&logs, nil))
	log.Error("insert failed", slog.Any("err", err))
	if strings.Contains(logs.String(), marker) || !strings.Contains(logs.String(), "code 27") {
		t.Fatal("structured logging must preserve the code without exposing exception data")
	}
}
