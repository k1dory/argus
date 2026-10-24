package sink

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestDurableWriterKeepsBatchOnIncompleteSuccessResponse(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Length", "1000")
		fmt.Fprint(w, "incomplete response")
	}))
	defer srv.Close()
	stats := &Stats{}
	q, err := NewDurableQueue(t.TempDir(), 1<<20, stats)
	if err != nil {
		t.Fatal(err)
	}
	if err := q.Push([]any{ev("keep-until-confirmed")}); err != nil {
		t.Fatal(err)
	}
	w := NewWriter(New(srv.URL, "argus", "", ""), q, stats)
	w.Attempts = 1
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	b, _ := q.Pop()
	w.WriteBatch(ctx, b)
	if q.Rows() != 1 || q.SpoolBytes() == 0 || stats.Inserted.Load() != 0 {
		t.Fatal("incomplete HTTP response acknowledged the durable batch")
	}
}

func TestInsertRejectsExceptionWithSuccessStatus(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprint(w, "Code: 241. DB::Exception: Memory limit exceeded")
	}))
	defer srv.Close()
	err := New(srv.URL, "argus", "", "").InsertEvents(context.Background(), []any{ev("one")})
	if !IsDivisible(err) {
		t.Fatalf("expected ClickHouse exception, got %v", err)
	}
}
