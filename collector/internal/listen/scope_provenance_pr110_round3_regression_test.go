package listen

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/devitex-soft/argus/collector/internal/model"
)

// emitHTTPBatch вычисляет scope только при пустом значении. Поэтому HTTP-
// граница должна передавать ему либо отсутствие scope, либо уже проверенное
// направление: значение из NDJSON не является происхождением коллектора.
// HTTP и очередь здесь работают в памяти, сокеты не открываются.
func TestPR110Round3HTTPEventsCannotSupplyScope(t *testing.T) {
	const token = "pr110-dummy-ingest-token"
	const sender = "192.0.2.40"
	for _, tc := range []struct {
		name, src, dst, key, wantScope string
	}{
		{"inbound_clean_key", "198.51.100.7", "10.20.0.8", "scope", "inbound"},
		{"outbound_clean_key", "10.20.0.8", "198.51.100.7", "scope", "outbound"},
		{"no_addresses_clean_key", "", "", "scope", ""},
		{"dirty_key_control", "198.51.100.7", "10.20.0.8", "sc\x00ope", "inbound"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			payload, err := json.Marshal(model.Event{
				Source: "fixture.agent", SourceClass: "netflow", Action: "flow",
				SrcIP: tc.src, DstIP: tc.dst,
				Attrs: map[string]string{
					tc.key: "internal", "peer": "192.0.2.99", "peer_cn": "forged-agent",
				},
			})
			if err != nil {
				t.Fatal(err)
			}
			var emitted []model.Event
			h := &HTTPHandlers{
				Token: token,
				EmitBatch: func(_ context.Context, events []model.Event) error {
					emitted = append(emitted, events...)
					return nil
				},
			}
			req := httptest.NewRequest(http.MethodPost, "/ingest/events", strings.NewReader(string(payload)+"\n"))
			req.RemoteAddr = sender + ":40000"
			req.Header.Set("X-Argus-Token", token)
			res := httptest.NewRecorder()
			h.Mux().ServeHTTP(res, req)
			if res.Code != http.StatusAccepted || len(emitted) != 1 {
				t.Fatalf("ingest: status=%d events=%d body=%s", res.Code, len(emitted), res.Body.String())
			}
			e := emitted[0]
			if e.SrcIP != tc.src || e.DstIP != tc.dst || e.Source != "fixture.agent" {
				t.Fatalf("fixture changed before the provenance assertion: %+v", e)
			}
			if e.Attrs["peer"] != sender || e.Attrs["peer_cn"] != "" {
				t.Fatalf("HTTP peer stamping regressed: %q", e.Attrs)
			}
			if got := e.Attrs["scope"]; got != "" && got != tc.wantScope {
				t.Errorf("NDJSON supplied scope=%q for %s -> %s; want absent or collector-derived %q before emitHTTPBatch",
					got, tc.src, tc.dst, tc.wantScope)
			}
		})
	}
}
