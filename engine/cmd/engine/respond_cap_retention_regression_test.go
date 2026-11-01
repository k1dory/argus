package main

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/devitex-soft/argus/engine/internal/incidents"
	"github.com/devitex-soft/argus/engine/internal/store"
)

// A valid block_cap_window longer than respStateTTL must remain effective
// through routine pruning and restart. The HTTP fixture implements the actual
// ResponsesSince time filter, unlike saveJournal's unfiltered canned response.
func TestPR67CapWindowSurvivesStateRetention(t *testing.T) {
	for _, restart := range []bool{false, true} {
		name := "prune"
		if restart {
			name = "restart"
		}
		t.Run(name, func(t *testing.T) {
			f := newFakeCH(t)
			x := newKeyExecutor(t)
			x.available.Store(true)
			rule := strings.Replace(capRule(1), "block_cap_window: 1h", "block_cap_window: 72h", 1)
			dir := rulesDirWith(t, map[string]string{"r.yml": rule})
			newEngineForWindow := func() *engine {
				return testEngine(t, f, dir, ipsConfig(x.srv), "s", "s")
			}
			e := newEngineForWindow()
			ctx, t0 := context.Background(), time.Now().UTC().Truncate(time.Second)
			e.autoRespond(ctx, []*incidents.Incident{capInc("INC-1", "203.0.113.7")}, t0)
			if x.blocks.Load() != 1 {
				t.Fatal("fixture: initial block must consume the only slot")
			}
			now := t0.Add(49 * time.Hour)
			if restart {
				journal := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
					if r.URL.Query().Get("query") != "" {
						f.srv.Config.Handler.ServeHTTP(w, r)
						return
					}
					body, err := io.ReadAll(r.Body)
					if err != nil {
						http.Error(w, err.Error(), http.StatusBadRequest)
						return
					}
					if !strings.Contains(string(body), "FROM response_log WHERE ip != ''") {
						r.Body = io.NopCloser(strings.NewReader(string(body)))
						f.srv.Config.Handler.ServeHTTP(w, r)
						return
					}
					since := r.URL.Query().Get("param_since")
					for _, line := range f.rows("response_log") {
						var row store.ResponseRow
						if err := json.Unmarshal([]byte(line), &row); err != nil {
							t.Errorf("invalid journal fixture: %v", err)
							return
						}
						if row.Step != "" && row.IP != "" && row.TS >= since {
							_, _ = io.WriteString(w, line+"\n")
						}
					}
				}))
				t.Cleanup(journal.Close)
				e = newEngineForWindow()
				e.ch = store.New(journal.URL, "argus", "default", "")
			} else {
				e.pruneRespState(now, respStateTTL)
			}
			e.autoRespond(ctx, []*incidents.Incident{capInc("INC-2", "203.0.113.8")}, now)
			if got := x.blocks.Load(); got != 1 {
				t.Fatalf("%s forgot an unexpired cap slot: %d blocks in 49h with block_cap=1 / 72h", name, got)
			}
		})
	}
}
