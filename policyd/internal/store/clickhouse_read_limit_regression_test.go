package store_test

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/devitex-soft/argus/policyd/internal/server"
	"github.com/devitex-soft/argus/policyd/internal/store"
)

type pr43TruncatedHTTPTransport func(*http.Request) (*http.Response, error)

func (f pr43TruncatedHTTPTransport) RoundTrip(r *http.Request) (*http.Response, error) {
	return f(r)
}

// Use the actual net/http body reader, not a fabricated error from a custom
// Reader. Content-Length promises one more byte than the server delivered.
// io.LimitReader must not turn reaching a diagnostic-size limit into success.
func TestPR43PolicyReadLimitDoesNotHideTruncatedResponse(t *testing.T) {
	for _, operation := range []string{"insert", "describe"} {
		limit := 4 << 10
		if operation == "describe" {
			limit = 64 << 10
		}
		for _, extra := range []int{-1, 0, 1} {
			t.Run(fmt.Sprintf("%s/bytes=%d", operation, limit+extra), func(t *testing.T) {
				size := limit + extra
				body := strings.Repeat("\n", size)
				if operation == "describe" {
					const prefix = "status\tString\t\t\t\t\t\ncommented\tString\t\t\t"
					const suffix = "\t\t\n"
					body = prefix + strings.Repeat("x", size-len(prefix)-len(suffix)) + suffix
				}
				wire := fmt.Sprintf("HTTP/1.1 200 OK\r\nContent-Length: %d\r\n\r\n%s", len(body)+1, body)
				response := func(r *http.Request) (*http.Response, error) {
					return http.ReadResponse(bufio.NewReader(strings.NewReader(wire)), r)
				}
				probe, err := response(nil)
				if err != nil {
					t.Fatal(err)
				}
				_, readErr := io.ReadAll(probe.Body)
				_ = probe.Body.Close()
				if !errors.Is(readErr, io.ErrUnexpectedEOF) {
					t.Fatalf("fixture must fail during body reading, got %v", readErr)
				}

				original := http.DefaultTransport
				t.Cleanup(func() { http.DefaultTransport = original })
				calls := 0
				http.DefaultTransport = pr43TruncatedHTTPTransport(func(r *http.Request) (*http.Response, error) {
					calls++
					return response(r)
				})
				ch := store.New("http://clickhouse.invalid", "argus", "fixture", "fixture")
				rows := []store.VerdictRow{{EntityID: "pr43-limit", Status: store.StatusFail}}
				if operation == "insert" {
					err = ch.InsertVerdicts(context.Background(), rows)
				} else {
					_, err = ch.HasStatusColumn(context.Background())
				}
				if calls != 1 {
					t.Fatalf("expected one store request, got %d", calls)
				}
				if err == nil {
					t.Error("truncated HTTP response was accepted at the body read limit")
				}
				if operation == "insert" {
					snap := server.NewSnapshot(time.Minute)
					snap.Set(rows)
					if err != nil {
						snap.SetError(fmt.Errorf("store verdicts: %w", err))
					}
					rr := httptest.NewRecorder()
					server.Handler(snap, "fixture-token").ServeHTTP(rr, httptest.NewRequest(http.MethodGet, "/healthz", nil))
					if rr.Code != http.StatusServiceUnavailable {
						t.Errorf("incomplete INSERT left health green: status=%d body=%q", rr.Code, rr.Body.String())
					}
				}
			})
		}
	}
}
