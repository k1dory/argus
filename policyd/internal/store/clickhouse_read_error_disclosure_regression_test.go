package store_test

import (
	"bufio"
	"bytes"
	"context"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/devitex-soft/argus/policyd/internal/server"
	"github.com/devitex-soft/argus/policyd/internal/store"
)

type pr43TrailerTransport func(*http.Request) (*http.Response, error)

func (f pr43TrailerTransport) RoundTrip(r *http.Request) (*http.Response, error) {
	return f(r)
}

// net/http can quote upstream bytes in a response-body read error: an invalid
// HTTP trailer is parsed by net/textproto after the final chunk. Wrapping that
// error with %w must not bypass ClickHouse error redaction in logs or /healthz.
// All HTTP framing is parsed in memory; no listener or database is needed.
func TestPR43PolicyBodyReadErrorDoesNotDiscloseUpstreamData(t *testing.T) {
	const marker = "PrivatePR43UpstreamDiagnostic"
	for _, operation := range []string{"insert", "describe"} {
		t.Run(operation, func(t *testing.T) {
			const wire = "HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n" +
				"0\r\nX-Internal-Diagnostic: " + marker + "\x00\r\n\r\n"
			response := func(r *http.Request) (*http.Response, error) {
				return http.ReadResponse(bufio.NewReader(strings.NewReader(wire)), r)
			}
			probe, err := response(nil)
			if err != nil {
				t.Fatal(err)
			}
			_, readErr := io.ReadAll(probe.Body)
			_ = probe.Body.Close()
			if readErr == nil || !strings.Contains(readErr.Error(), marker) {
				t.Fatalf("fixture must trigger a real body-parser error quoting the trailer, got %v", readErr)
			}

			original := http.DefaultTransport
			t.Cleanup(func() { http.DefaultTransport = original })
			http.DefaultTransport = pr43TrailerTransport(response)
			ch := store.New("http://clickhouse.invalid", "argus", "fixture", "fixture")
			rows := []store.VerdictRow{{EntityID: "pr43-trailer", Status: store.StatusFail}}
			if operation == "insert" {
				err = ch.InsertVerdicts(context.Background(), rows)
			} else {
				_, err = ch.HasStatusColumn(context.Background())
			}
			if err == nil {
				t.Fatal("malformed HTTP body must remain an error")
			}
			if strings.Contains(err.Error(), marker) {
				t.Error("store error exposes private bytes quoted by the HTTP parser")
			}
			var logs bytes.Buffer
			slog.New(slog.NewTextHandler(&logs, nil)).Error("ClickHouse request failed", "err", err)
			if strings.Contains(logs.String(), marker) {
				t.Error("policyd log exposes private response bytes through the read error")
			}
			if operation == "insert" {
				snap := server.NewSnapshot(time.Minute)
				snap.Set(rows)
				snap.SetError(fmt.Errorf("store verdicts: %w", err))
				rr := httptest.NewRecorder()
				server.Handler(snap, "fixture-token").ServeHTTP(rr, httptest.NewRequest(http.MethodGet, "/healthz", nil))
				if rr.Code != http.StatusServiceUnavailable {
					t.Errorf("failed INSERT must make health red, got %d", rr.Code)
				}
				if strings.Contains(rr.Body.String(), marker) {
					t.Error("unauthenticated /healthz exposes private upstream diagnostics")
				}
			}
		})
	}
}
