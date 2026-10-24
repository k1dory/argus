// Package server exposes health and the latest policy evaluation snapshot.
package server

import (
	"crypto/sha256"
	"crypto/subtle"
	"encoding/json"
	"fmt"
	"net/http"
	"sync"
	"time"

	"github.com/devitex-soft/argus/policyd/internal/store"
)

// Snapshot — последний раунд оценки: вердикты, время и ошибка раунда.
type Snapshot struct {
	mu        sync.RWMutex
	updatedAt time.Time
	lastErr   error
	rows      []store.VerdictRow

	// pollInterval нужен /healthz: снимок старше 2×интервала — сервис нездоров.
	pollInterval time.Duration
	now          func() time.Time
}

// NewSnapshot создаёт снимок с интервалом опроса для проверки свежести.
func NewSnapshot(pollInterval time.Duration) *Snapshot {
	return &Snapshot{pollInterval: pollInterval, now: func() time.Time { return time.Now().UTC() }}
}

// Set фиксирует успешный раунд.
func (s *Snapshot) Set(rows []store.VerdictRow) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.updatedAt = s.now()
	s.lastErr = nil
	s.rows = rows
}

// SetError фиксирует раунд, завершившийся ошибкой (API недоступен, INSERT
// упал). Вердикты предыдущего раунда сохраняются, updatedAt не двигается.
func (s *Snapshot) SetError(err error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.lastErr = err
}

// Health возвращает (здоров, причина).
func (s *Snapshot) Health() (bool, string) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	if s.lastErr != nil {
		return false, "last round failed: " + s.lastErr.Error()
	}
	if s.updatedAt.IsZero() {
		// До первого раунда: он может занять минуты на большом парке,
		// healthcheck контейнера не должен убивать сервис на старте.
		return true, "starting"
	}
	if s.pollInterval > 0 {
		age := s.now().Sub(s.updatedAt)
		if age > 2*s.pollInterval {
			return false, fmt.Sprintf("snapshot is stale: %s old (limit %s)", age.Truncate(time.Second), 2*s.pollInterval)
		}
	}
	return true, "ok"
}

// Handler отдаёт /healthz и /verdicts. Если token не пуст, /verdicts требует
// Authorization: Bearer <token>.
func Handler(snap *Snapshot, token string) http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /healthz", func(w http.ResponseWriter, r *http.Request) {
		ok, reason := snap.Health()
		w.Header().Set("Content-Type", "text/plain; charset=utf-8")
		if !ok {
			w.WriteHeader(http.StatusServiceUnavailable)
		}
		_, _ = fmt.Fprintln(w, reason)
	})
	mux.Handle("GET /verdicts", requireBearer(token, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		snap.mu.RLock()
		defer snap.mu.RUnlock()
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{
			"updated_at": snap.updatedAt,
			"verdicts":   snap.rows,
		})
	})))
	return mux
}

// requireBearer — сравнение токена за постоянное время; пустой token
// отключает проверку (совместимость со стендом без POLICYD_TOKEN).
func requireBearer(token string, next http.Handler) http.Handler {
	if token == "" {
		return next
	}
	want := sha256.Sum256([]byte(token))
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		const prefix = "Bearer "
		auth := r.Header.Get("Authorization")
		if len(auth) <= len(prefix) || auth[:len(prefix)] != prefix {
			w.Header().Set("WWW-Authenticate", `Bearer realm="policyd"`)
			http.Error(w, "bearer token required", http.StatusUnauthorized)
			return
		}
		got := sha256.Sum256([]byte(auth[len(prefix):]))
		if subtle.ConstantTimeCompare(got[:], want[:]) != 1 {
			http.Error(w, "invalid token", http.StatusUnauthorized)
			return
		}
		next.ServeHTTP(w, r)
	})
}
