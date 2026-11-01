package store

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// fakeCH эмулирует HTTP-интерфейс ClickHouse: DESCRIBE отдаёт схему с
// колонкой status или без, INSERT запоминает тело.
func fakeCH(t *testing.T, withStatus bool) (*httptest.Server, *string) {
	t.Helper()
	var inserted string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if u, p, ok := r.BasicAuth(); !ok || u != "argus" || p != "pw" {
			http.Error(w, "auth", http.StatusUnauthorized)
			return
		}
		q := r.URL.Query().Get("query")
		switch {
		case strings.HasPrefix(q, "DESCRIBE TABLE argus.policy_verdicts"):
			schema := "evaluated_at\tDateTime('UTC')\t\t\t\t\t\nentity_type\tLowCardinality(String)\t\t\t\t\t\ncompliant\tUInt8\t\t\t\t\t\nviolations\tArray(String)\t\t\t\t\t\n"
			if withStatus {
				schema += "status\tString\tDEFAULT\t''\t\t\t\n"
			}
			_, _ = w.Write([]byte(schema))
		case strings.HasPrefix(q, "INSERT INTO argus.policy_verdicts"):
			b, _ := io.ReadAll(r.Body)
			inserted = string(b)
			_, _ = w.Write([]byte("Ok."))
		default:
			http.Error(w, "unexpected query "+q, http.StatusBadRequest)
		}
	}))
	t.Cleanup(srv.Close)
	return srv, &inserted
}

func TestHasStatusColumn(t *testing.T) {
	for _, withStatus := range []bool{false, true} {
		srv, _ := fakeCH(t, withStatus)
		ch := New(srv.URL, "argus", "argus", "pw")
		got, err := ch.HasStatusColumn(context.Background())
		if err != nil {
			t.Fatal(err)
		}
		if got != withStatus {
			t.Fatalf("withStatus=%v: detected %v", withStatus, got)
		}
	}
}

func TestHasStatusColumnReportsError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "Code: 60. DB::Exception: Table missing", http.StatusNotFound)
	}))
	t.Cleanup(srv.Close)
	ch := New(srv.URL, "argus", "argus", "pw")
	if _, err := ch.HasStatusColumn(context.Background()); err == nil || !strings.Contains(err.Error(), "code 60") || strings.Contains(err.Error(), "Table missing") {
		t.Fatalf("expected ClickHouse code without exception text, got %v", err)
	}
}

// Поле status шлётся всегда — и на схеме без колонки (skip_unknown_fields
// на стороне ClickHouse), и с ней; DESCRIBE перед INSERT не нужен.
func TestInsertAlwaysSendsStatus(t *testing.T) {
	for _, withStatus := range []bool{false, true} {
		srv, body := fakeCH(t, withStatus)
		ch := New(srv.URL, "argus", "argus", "pw")
		row := VerdictRow{EvaluatedAt: "2026-09-13 10:00:00", EntityType: "agent", EntityID: "001",
			Policy: "wazuh/agent", Compliant: 0, Violations: []string{"x"}, Status: StatusUnknown}
		if err := ch.InsertVerdicts(context.Background(), []VerdictRow{row}); err != nil {
			t.Fatal(err)
		}
		if !strings.Contains(*body, `"status":"unknown"`) {
			t.Fatalf("withStatus=%v: status must always be sent: %s", withStatus, *body)
		}
		if !strings.Contains(*body, `"violations":["x"]`) {
			t.Fatalf("other fields must be intact: %s", *body)
		}
	}
}

func TestInsertSetsSkipUnknownFields(t *testing.T) {
	var gotQuery string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotQuery = r.URL.RawQuery
		_, _ = w.Write([]byte("Ok."))
	}))
	t.Cleanup(srv.Close)
	ch := New(srv.URL, "argus", "argus", "pw")
	if err := ch.InsertVerdicts(context.Background(), []VerdictRow{{EntityID: "x", Violations: []string{}}}); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(gotQuery, "input_format_skip_unknown_fields=1") {
		t.Fatalf("INSERT must tolerate the pre-0011 schema via skip_unknown_fields: %s", gotQuery)
	}
}

func TestInsertReportsClickHouseError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "Code: 60. DB::Exception: Table missing", http.StatusNotFound)
	}))
	t.Cleanup(srv.Close)
	ch := New(srv.URL, "argus", "argus", "pw")
	err := ch.InsertVerdicts(context.Background(), []VerdictRow{{EntityID: "x", Violations: []string{}}})
	// Код и статус — да, текст исключения — нет (цитирует данные; полный — в query_log).
	if err == nil || !strings.Contains(err.Error(), "code 60") || !strings.Contains(err.Error(), "HTTP 404") || strings.Contains(err.Error(), "Table missing") {
		t.Fatalf("expected ClickHouse status and code without exception text, got %v", err)
	}
}
