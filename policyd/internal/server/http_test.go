package server

import (
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/devitex-soft/argus/policyd/internal/store"
)

func newSnap(interval time.Duration) (*Snapshot, *time.Time) {
	now := time.Date(2026, 9, 13, 10, 0, 0, 0, time.UTC)
	s := NewSnapshot(interval)
	s.now = func() time.Time { return now }
	return s, &now
}

func get(t *testing.T, h http.Handler, path, auth string) *httptest.ResponseRecorder {
	t.Helper()
	req := httptest.NewRequest(http.MethodGet, path, nil)
	if auth != "" {
		req.Header.Set("Authorization", auth)
	}
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, req)
	return rr
}

func TestHealthzStartingBeforeFirstRound(t *testing.T) {
	snap, _ := newSnap(5 * time.Minute)
	rr := get(t, Handler(snap, ""), "/healthz", "")
	if rr.Code != http.StatusOK || !strings.Contains(rr.Body.String(), "starting") {
		t.Fatalf("before first round expect 200 starting, got %d %q", rr.Code, rr.Body.String())
	}
}

func TestHealthzFresh(t *testing.T) {
	snap, _ := newSnap(5 * time.Minute)
	snap.Set(nil)
	rr := get(t, Handler(snap, ""), "/healthz", "")
	if rr.Code != http.StatusOK {
		t.Fatalf("fresh snapshot must be healthy, got %d %q", rr.Code, rr.Body.String())
	}
}

func TestHealthzStale(t *testing.T) {
	snap, now := newSnap(5 * time.Minute)
	snap.Set(nil)
	*now = now.Add(10*time.Minute + time.Second) // > 2×POLL_INTERVAL
	rr := get(t, Handler(snap, ""), "/healthz", "")
	if rr.Code != http.StatusServiceUnavailable || !strings.Contains(rr.Body.String(), "stale") {
		t.Fatalf("stale snapshot must give 503, got %d %q", rr.Code, rr.Body.String())
	}
	// Ровно на границе 2× — ещё здоров.
	*now = now.Add(-2 * time.Second)
	if rr := get(t, Handler(snap, ""), "/healthz", ""); rr.Code != http.StatusOK {
		t.Fatalf("within 2×interval must be healthy, got %d", rr.Code)
	}
}

func TestHealthzLastRoundError(t *testing.T) {
	snap, _ := newSnap(5 * time.Minute)
	snap.Set(nil)
	snap.SetError(errors.New("wazuh api: connection refused"))
	rr := get(t, Handler(snap, ""), "/healthz", "")
	if rr.Code != http.StatusServiceUnavailable || !strings.Contains(rr.Body.String(), "connection refused") {
		t.Fatalf("failed round must give 503 with reason, got %d %q", rr.Code, rr.Body.String())
	}
	// Следующий успешный раунд снимает ошибку.
	snap.Set(nil)
	if rr := get(t, Handler(snap, ""), "/healthz", ""); rr.Code != http.StatusOK {
		t.Fatalf("successful round must clear error, got %d", rr.Code)
	}
}

func TestVerdictsWithoutTokenIsOpen(t *testing.T) {
	snap, _ := newSnap(time.Minute)
	snap.Set([]store.VerdictRow{{EntityID: "001", Status: store.StatusFail, Violations: []string{"x"}}})
	rr := get(t, Handler(snap, ""), "/verdicts", "")
	if rr.Code != http.StatusOK {
		t.Fatalf("no POLICYD_TOKEN → open endpoint, got %d", rr.Code)
	}
	var out struct {
		Verdicts []store.VerdictRow `json:"verdicts"`
	}
	if err := json.Unmarshal(rr.Body.Bytes(), &out); err != nil || len(out.Verdicts) != 1 || out.Verdicts[0].Status != "fail" {
		t.Fatalf("bad body: %v %s", err, rr.Body.String())
	}
}

func TestVerdictsRequiresBearer(t *testing.T) {
	snap, _ := newSnap(time.Minute)
	h := Handler(snap, "s3cret")
	if rr := get(t, h, "/verdicts", ""); rr.Code != http.StatusUnauthorized || rr.Header().Get("WWW-Authenticate") == "" {
		t.Fatalf("missing bearer must give 401 + WWW-Authenticate, got %d", rr.Code)
	}
	if rr := get(t, h, "/verdicts", "Bearer wrong"); rr.Code != http.StatusUnauthorized {
		t.Fatalf("wrong bearer must give 401, got %d", rr.Code)
	}
	if rr := get(t, h, "/verdicts", "Basic s3cret"); rr.Code != http.StatusUnauthorized {
		t.Fatalf("non-bearer scheme must give 401, got %d", rr.Code)
	}
	if rr := get(t, h, "/verdicts", "Bearer s3cret"); rr.Code != http.StatusOK {
		t.Fatalf("correct bearer must pass, got %d", rr.Code)
	}
	// healthz остаётся открытым для контейнерного healthcheck.
	if rr := get(t, h, "/healthz", ""); rr.Code != http.StatusOK {
		t.Fatalf("healthz must not require token, got %d", rr.Code)
	}
}
