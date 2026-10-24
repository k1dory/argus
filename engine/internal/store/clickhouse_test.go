package store

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"unicode/utf8"

	"github.com/devitex-soft/argus/engine/internal/model"
)

func TestSimilarIncidentsDecodesDatabaseColumns(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprintln(w, `{"incident_id":"INC-42","created_at":"2026-09-25 12:00:00","status":"closed","rule_title":"SSH","note":"checked"}`)
	}))
	defer srv.Close()
	got, err := New(srv.URL, "argus", "", "").SimilarIncidents(context.Background(), "ssh", "", "", "INC-43", 5)
	if err != nil {
		t.Fatal(err)
	}
	want := "INC-42 · 2026-09-25 · closed · SSH · checked"
	if len(got) != 1 || got[0] != want {
		t.Fatalf("got %v, want %q", got, want)
	}
}

func TestDoRejectsExceptionAfterSuccessHeaders(t *testing.T) {
	for _, tc := range []struct{ name, body, code string }{
		{"insert", "Code: 241. DB::Exception: Memory limit exceeded", ""},
		{"partial select", "{\"c\":1}\nCode: 159. DB::Exception: Timeout exceeded", ""},
		{"header only", "", "241"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if tc.code != "" {
					w.Header().Set("X-ClickHouse-Exception-Code", tc.code)
				}
				fmt.Fprint(w, tc.body)
			}))
			defer srv.Close()
			if _, err := New(srv.URL, "argus", "", "").do(context.Background(), "SELECT 1", nil, nil); err == nil {
				t.Fatal("HTTP 200 with an exception must fail")
			}
		})
	}
}

func TestSimilarIncidentsPreservesUnicodeAndExceptionText(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprintf(w, `{"incident_id":"INC-42","created_at":"","note":%q}`, strings.Repeat("я", 121)+" Code: 241. DB::Exception: sample")
	}))
	defer srv.Close()
	got, err := New(srv.URL, "argus", "", "").SimilarIncidents(context.Background(), "ssh", "", "", "INC-43", 5)
	if err != nil || len(got) != 1 {
		t.Fatalf("got %v, err %v", got, err)
	}
	if !utf8.ValidString(got[0]) || !strings.HasSuffix(got[0], strings.Repeat("я", 119)+"…") {
		t.Fatalf("invalid shortened note: %q", got[0])
	}
}

func TestDoRejectsTruncatedHTTPResponse(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Length", "1000")
		fmt.Fprintln(w, `{"incident_id":"INC-42"}`)
	}))
	defer srv.Close()
	_, err := New(srv.URL, "argus", "", "").do(context.Background(), "SELECT 1", nil, nil)
	if err == nil || !strings.Contains(err.Error(), "unexpected EOF") {
		t.Fatalf("truncated response must fail: %v", err)
	}
}

func TestInsertEventsAndHost(t *testing.T) {
	var query, body string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		b, _ := io.ReadAll(r.Body)
		query, body = r.URL.Query().Get("query"), string(b)
	}))
	defer srv.Close()
	c := New(srv.URL, "argus", "", "")
	ev := &model.Event{TS: "2026-10-20 10:45:00.000", Source: "argus.system", SourceClass: "telemetry", Action: "disk.usage", Node: "clickhouse", Value: 91.5, Unit: "percent"}
	ev.Ensure()
	if err := c.InsertEvents(context.Background(), []*model.Event{ev}); err != nil {
		t.Fatal(err)
	}
	if query != "INSERT INTO events FORMAT JSONEachRow" {
		t.Fatalf("запрос %q", query)
	}
	for _, want := range []string{`"value":91.5`, `"unit":"percent"`, `"source":"argus.system"`, `"outcome":"unknown"`} {
		if !strings.Contains(body, want) {
			t.Fatalf("в строке нет %s: %s", want, body)
		}
	}
	if strings.Contains(body, "ReceivedAt") || strings.Contains(body, "received") {
		t.Fatalf("received_at ставит база: %s", body)
	}
	if New("http://clickhouse:8123", "a", "", "").Host() != "clickhouse" || New("https://ch.internal/", "a", "", "").Host() != "ch.internal" || New("", "a", "", "").Host() != "clickhouse" {
		t.Fatal("Host")
	}
	// SELECT событий читает новые колонки
	if !strings.Contains(eventsSelectColumns(), "value, unit") {
		t.Fatal("EventsSince должен читать value и unit")
	}
}
