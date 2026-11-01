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

type pr27ErrorTransport func(*http.Request) (*http.Response, error)

func (f pr27ErrorTransport) RoundTrip(r *http.Request) (*http.Response, error) {
	return f(r)
}

// PR #27: store -> runRound -> log.Error / Snapshot.SetError -> GET /healthz.
// Ошибка хранилища не должна переносить цитату данных ни в лог, ни в открытый
// health endpoint. HTTP заменён RoundTripper; ResponseRecorder не слушает порт.
func TestPR27PolicyClickHouseErrorsDoNotDiscloseData(t *testing.T) {
	const marker = "PrivatePolicyVerdictFixture"
	const detail = "Code: 6. DB::Exception: Cannot parse string '" + marker + "' as UInt8. (CANNOT_PARSE_TEXT)"
	for _, operation := range []string{"insert", "describe"} {
		t.Run(operation, func(t *testing.T) {
			original := http.DefaultTransport
			t.Cleanup(func() { http.DefaultTransport = original })
			calls := 0
			http.DefaultTransport = pr27ErrorTransport(func(r *http.Request) (*http.Response, error) {
				calls++
				if operation == "insert" {
					body, err := io.ReadAll(r.Body)
					if err != nil {
						return nil, err
					}
					if !strings.Contains(string(body), marker) {
						t.Fatal("fixture data did not reach the INSERT serializer")
					}
				}
				return &http.Response{
					StatusCode: http.StatusBadRequest, Status: "400 Bad Request",
					Header: http.Header{"X-Clickhouse-Exception-Code": {"6"}},
					Body:   io.NopCloser(strings.NewReader(detail)),
				}, nil
			})
			ch := store.New("http://clickhouse.invalid", "argus", "fixture", "fixture")
			var err error
			if operation == "insert" {
				err = ch.InsertVerdicts(context.Background(), []store.VerdictRow{{EntityID: "001", EntityName: marker}})
			} else {
				_, err = ch.HasStatusColumn(context.Background())
			}
			if err == nil || calls != 1 {
				t.Fatalf("want a failed real request, calls=%d err=%v", calls, err)
			}
			if strings.Contains(err.Error(), marker) {
				t.Error("the error logged by policyd contains exception data")
			}
			if operation == "insert" {
				snap := server.NewSnapshot(time.Minute)
				snap.SetError(fmt.Errorf("store verdicts: %w", err))
				rr := httptest.NewRecorder()
				server.Handler(snap, "fixture-required-token").ServeHTTP(rr, httptest.NewRequest(http.MethodGet, "/healthz", nil))
				if rr.Code != http.StatusServiceUnavailable {
					t.Errorf("failed insert must make health unhealthy, status=%d", rr.Code)
				}
				if strings.Contains(rr.Body.String(), marker) {
					t.Error("unauthenticated /healthz discloses the failed INSERT's data")
				}
			}
		})
	}
}
