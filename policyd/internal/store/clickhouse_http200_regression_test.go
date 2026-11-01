package store_test

import (
	"context"
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

type pr39PolicyTransport func(*http.Request) (*http.Response, error)

func (f pr39PolicyTransport) RoundTrip(r *http.Request) (*http.Response, error) {
	return f(r)
}

// HTTP 200 does not imply query success. Neither the INSERT nor DESCRIBE
// client may silently discard a ClickHouse exception. Transport replacement
// and ResponseRecorder keep the whole check in-process, without sockets.
func TestPR39PolicyHTTP200ExceptionsAreFailures(t *testing.T) {
	const marker = "PrivatePR39PolicyFixture"
	const detail = "Code: 6. DB::Exception: Cannot parse string '" + marker + "' as UInt8"
	const queryID = "ef385952-33e6-4136-ad8e-abdf16c85e8a"
	for _, operation := range []string{"insert", "describe"} {
		for _, tc := range []struct {
			name, header, body, code string
		}{
			{"header_only", "209", "", "209"},
			{"header_and_body", "6", detail, "6"},
			{"body_only", "", detail, "6"},
		} {
			t.Run(operation+"/"+tc.name, func(t *testing.T) {
				original := http.DefaultTransport
				t.Cleanup(func() { http.DefaultTransport = original })
				calls := 0
				http.DefaultTransport = pr39PolicyTransport(func(r *http.Request) (*http.Response, error) {
					calls++
					query := r.URL.Query().Get("query")
					if operation == "insert" {
						body, err := io.ReadAll(r.Body)
						if err != nil || !strings.Contains(string(body), marker) || !strings.HasPrefix(query, "INSERT INTO ") {
							t.Fatalf("fixture did not exercise real INSERT serialization: query=%q err=%v", query, err)
						}
					} else if !strings.HasPrefix(query, "DESCRIBE TABLE ") {
						t.Fatalf("unexpected query: %s", query)
					}
					h := make(http.Header)
					h.Set("X-ClickHouse-Query-Id", queryID)
					if tc.header != "" {
						h.Set("X-ClickHouse-Exception-Code", tc.header)
					}
					return &http.Response{
						StatusCode: http.StatusOK, Status: "200 OK", Header: h,
						Body: io.NopCloser(strings.NewReader(tc.body)),
					}, nil
				})
				ch := store.New("http://clickhouse.invalid", "argus", "fixture", "fixture")
				rows := []store.VerdictRow{{EntityID: "001", EntityName: marker, Status: store.StatusFail}}
				var err error
				if operation == "insert" {
					err = ch.InsertVerdicts(context.Background(), rows)
				} else {
					_, err = ch.HasStatusColumn(context.Background())
				}
				if calls != 1 {
					t.Fatalf("expected one real request, got %d", calls)
				}
				if err == nil {
					t.Error("HTTP 200 ClickHouse exception was silently accepted")
				} else {
					if strings.Contains(err.Error(), marker) {
						t.Error("exception data escapes through Error()")
					}
					for _, metadata := range []string{"HTTP 200", "code " + tc.code, "query_id " + queryID} {
						if !strings.Contains(err.Error(), metadata) {
							t.Errorf("missing safe diagnostic %q: %v", metadata, err)
						}
					}
				}
				if operation == "insert" {
					// Match runRound/evaluate: Set(rows) before the INSERT, SetError
					// only if the store returns an error to the caller.
					snap := server.NewSnapshot(time.Minute)
					snap.Set(rows)
					if err != nil {
						snap.SetError(fmt.Errorf("store verdicts: %w", err))
					}
					rr := httptest.NewRecorder()
					server.Handler(snap, "fixture-token").ServeHTTP(rr, httptest.NewRequest(http.MethodGet, "/healthz", nil))
					if rr.Code != http.StatusServiceUnavailable {
						t.Errorf("failed INSERT leaves health green: status=%d body=%q", rr.Code, rr.Body.String())
					}
					if strings.Contains(rr.Body.String(), marker) {
						t.Error("public health response contains exception data")
					}
				}
			})
		}
	}
}
