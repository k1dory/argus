package store_test

import (
	"bytes"
	"context"
	"errors"
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

type pr41PolicyTransport func(*http.Request) (*http.Response, error)

func (f pr41PolicyTransport) RoundTrip(r *http.Request) (*http.Response, error) {
	return f(r)
}

type pr41IncompleteBody struct {
	prefix string
	err    error
	closed bool
}

func (b *pr41IncompleteBody) Read(p []byte) (int, error) {
	if b.prefix == "" {
		return 0, b.err
	}
	n := copy(p, b.prefix)
	b.prefix = b.prefix[n:]
	if b.prefix == "" {
		return n, b.err
	}
	return n, nil
}

func (b *pr41IncompleteBody) Close() error {
	b.closed = true
	return nil
}

// A response-body failure must reach runRound/evaluate and /healthz. Replace
// only the transport: exercise the real INSERT serializer, Snapshot, and HTTP
// handler without opening sockets. Header/status errors remain authoritative
// even when reading their diagnostic body fails.
func TestPR41PolicyIncompleteInsertResponseFailsHealth(t *testing.T) {
	const marker = "PrivatePR41IncompleteResponse"
	for _, tc := range []struct {
		name, code, prefix string
		status             int
		readErr            error
		wantError          bool
	}{
		{name: "complete_empty_success", status: http.StatusOK, readErr: io.EOF},
		{name: "missing_final_chunk", status: http.StatusOK, readErr: io.ErrUnexpectedEOF, wantError: true},
		{name: "truncated_body", status: http.StatusOK, prefix: marker, readErr: io.ErrUnexpectedEOF, wantError: true},
		{name: "body_timeout", status: http.StatusOK, readErr: context.DeadlineExceeded, wantError: true},
		{name: "exception_header_control", status: http.StatusOK, code: "209", prefix: marker, readErr: io.ErrUnexpectedEOF, wantError: true},
		{name: "error_status_control", status: http.StatusServiceUnavailable, prefix: marker, readErr: io.ErrUnexpectedEOF, wantError: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			original := http.DefaultTransport
			t.Cleanup(func() { http.DefaultTransport = original })
			body := &pr41IncompleteBody{prefix: tc.prefix, err: tc.readErr}
			calls := 0
			http.DefaultTransport = pr41PolicyTransport(func(r *http.Request) (*http.Response, error) {
				calls++
				if r.Method != http.MethodPost || r.URL.Query().Get("query") != "INSERT INTO argus.policy_verdicts FORMAT JSONEachRow" {
					t.Fatalf("unexpected INSERT request: %s %s", r.Method, r.URL)
				}
				if r.URL.Query().Get("wait_end_of_query") != "1" {
					t.Fatal("INSERT must wait for query completion")
				}
				h := make(http.Header)
				if tc.code != "" {
					h.Set("X-ClickHouse-Exception-Code", tc.code)
				}
				return &http.Response{StatusCode: tc.status, Header: h, Body: body}, nil
			})

			ch := store.New("http://clickhouse.invalid", "argus", "fixture", "fixture")
			rows := []store.VerdictRow{{EntityID: "fixture-41", Status: store.StatusFail}}
			snap := server.NewSnapshot(time.Minute)
			snap.Set(rows) // runRound updates the snapshot before INSERT.
			err := ch.InsertVerdicts(context.Background(), rows)
			if calls != 1 || !body.closed {
				t.Fatalf("calls=%d response body closed=%t", calls, body.closed)
			}
			if (err != nil) != tc.wantError {
				t.Errorf("read error %v: INSERT error=%v, wantError=%t", tc.readErr, err, tc.wantError)
			}
			if tc.wantError && tc.status == http.StatusOK && tc.code == "" && !errors.Is(err, tc.readErr) {
				t.Errorf("INSERT discarded the transport read error: got %v, want %v", err, tc.readErr)
			}
			var logs bytes.Buffer
			if err != nil {
				wrapped := fmt.Errorf("store verdicts: %w", err)
				snap.SetError(wrapped)
				slog.New(slog.NewTextHandler(&logs, nil)).Error("evaluation round failed", "err", wrapped)
			}
			rr := httptest.NewRecorder()
			server.Handler(snap, "fixture-token").ServeHTTP(rr, httptest.NewRequest(http.MethodGet, "/healthz", nil))
			wantStatus := http.StatusOK
			if tc.wantError {
				wantStatus = http.StatusServiceUnavailable
			}
			if rr.Code != wantStatus {
				t.Errorf("/healthz=%d, want %d after read error %v", rr.Code, wantStatus, tc.readErr)
			}
			if strings.Contains(rr.Body.String(), marker) || strings.Contains(logs.String(), marker) {
				t.Error("partial ClickHouse response leaked to health/log output")
			}
		})
	}
}

// DESCRIBE returns TSV data, including unquoted column names. A valid extension:
//
//	ADD COLUMN `Code: 27.` String DEFAULT '';
//
// The name must not turn a successful schema response into a DB exception.
func TestPR41PolicyDescribeDoesNotInterpretColumnNamesAsErrors(t *testing.T) {
	const schema = "Code: 27.\tString\tDEFAULT\t''\t\t\t\nstatus\tString\tDEFAULT\t''\t\t\t\n"
	for _, tc := range []struct {
		name, code string
		status     int
		wantError  bool
	}{
		{name: "success_without_exception_header", status: http.StatusOK},
		{name: "success_with_zero_exception_header", status: http.StatusOK, code: "0"},
		{name: "exception_header_control", status: http.StatusOK, code: "241", wantError: true},
		{name: "error_status_control", status: http.StatusInternalServerError, wantError: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			original := http.DefaultTransport
			t.Cleanup(func() { http.DefaultTransport = original })
			calls := 0
			http.DefaultTransport = pr41PolicyTransport(func(r *http.Request) (*http.Response, error) {
				calls++
				if r.Method != http.MethodGet || r.URL.Query().Get("query") != "DESCRIBE TABLE argus.policy_verdicts FORMAT TSV" {
					t.Fatalf("unexpected DESCRIBE request: %s %s", r.Method, r.URL)
				}
				if r.URL.Query().Get("wait_end_of_query") != "1" {
					t.Fatal("DESCRIBE must wait for query completion")
				}
				h := make(http.Header)
				if tc.code != "" {
					h.Set("X-ClickHouse-Exception-Code", tc.code)
				}
				return &http.Response{StatusCode: tc.status, Header: h, Body: io.NopCloser(strings.NewReader(schema))}, nil
			})
			ch := store.New("http://clickhouse.invalid", "argus", "fixture", "fixture")
			hasStatus, err := ch.HasStatusColumn(context.Background())
			if calls != 1 {
				t.Fatalf("DESCRIBE calls=%d, want 1", calls)
			}
			wantStatus := !tc.wantError
			if (err != nil) != tc.wantError || hasStatus != wantStatus {
				t.Errorf("valid TSV column name treated as an exception: hasStatus=%t err=%v wantError=%t", hasStatus, err, tc.wantError)
			}
		})
	}
}
