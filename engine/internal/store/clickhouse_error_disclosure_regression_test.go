package store

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"strings"
	"testing"
)

type pr27ErrorTransport func(*http.Request) (*http.Response, error)

func (f pr27ErrorTransport) RoundTrip(r *http.Request) (*http.Response, error) {
	return f(r)
}

// PR #27: другой клиент ClickHouse всё ещё отдаёт цитату вердикта через
// error.Error(). engine/cmd/engine/analyze.go логирует эту ошибку как "verdict
// insert". Подменён только RoundTripper, сокеты и живой сервер не нужны.
func TestPR27VerdictErrorDoesNotDiscloseExceptionText(t *testing.T) {
	const marker = "PrivateEngineVerdictFixture"
	const detail = "Code: 27. DB::Exception: Cannot parse input: '" + marker + "'. (CANNOT_PARSE_INPUT_ASSERTION_FAILED)"
	for _, tc := range []struct {
		name   string
		status int
		header string
	}{
		{"http_error", http.StatusBadRequest, "27"},
		{"exception_header_after_200", http.StatusOK, "27"},
		{"exception_body_after_200", http.StatusOK, ""},
	} {
		t.Run(tc.name, func(t *testing.T) {
			c := New("http://clickhouse.invalid", "argus", "fixture", "fixture")
			calls := 0
			c.http.Transport = pr27ErrorTransport(func(r *http.Request) (*http.Response, error) {
				calls++
				body, err := io.ReadAll(r.Body)
				if err != nil {
					return nil, err
				}
				if !strings.Contains(string(body), marker) {
					t.Fatal("fixture verdict did not reach the real INSERT serializer")
				}
				if r.URL.Query().Get("query") != "INSERT INTO incident_verdicts FORMAT JSONEachRow" {
					t.Fatalf("unexpected query: %s", r.URL.Query().Get("query"))
				}
				h := make(http.Header)
				if tc.header != "" {
					h.Set("X-ClickHouse-Exception-Code", tc.header)
				}
				return &http.Response{
					StatusCode: tc.status, Status: fmt.Sprintf("%d %s", tc.status, http.StatusText(tc.status)),
					Header: h, Body: io.NopCloser(strings.NewReader(detail)),
				}, nil
			})
			err := c.InsertVerdict(context.Background(), Verdict{IncidentID: "INC-4", SummaryRU: marker})
			if err == nil || calls != 1 {
				t.Fatalf("want a failed real INSERT, calls=%d err=%v", calls, err)
			}
			if !strings.Contains(err.Error(), "27") {
				t.Errorf("diagnostic code was lost: %v", err)
			}
			if strings.Contains(err.Error(), marker) {
				t.Error("exception text escapes through the error consumed by the verdict logger")
			}
		})
	}
}
