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

func TestHTTPEventsDNSQueryContract(t *testing.T) {
	for _, tc := range []struct {
		name, action string
		attrs        map[string]string
		want         string
	}{
		{"query_name alias", "event.dns", map[string]string{"query_name": " a.example.test "}, "a.example.test"},
		{"nested vendor key", "dns.query", map[string]string{"dns.question.name": "b.example.test"}, "b.example.test"},
		{"uppercase action", "DNS.Query", map[string]string{"qname": "c.example.test"}, "c.example.test"},
		{"canonical value wins", "event.dns", map[string]string{"dns_query": "own.example.test", "query": "other.example.test"}, "own.example.test"},
		{"vendor alias priority", "event.dns", map[string]string{"query": "first.example.test", "qname": "second.example.test"}, "first.example.test"},
		{"blank aliases are skipped", "event.dns", map[string]string{"query": " \t", "qname": " q.example.test "}, "q.example.test"},
		{"query is sanitized", "event.dns", map[string]string{"domain": "safe\x1b[31m.example.test\x1b[0m\x00"}, "safe.example.test"},
		{"ordinary session stays a session", "session.allow", map[string]string{"domain": "example.test"}, ""},
		{"NetFlow stays a flow", "flow", map[string]string{"qname": "example.test"}, ""},
		{"missing name is not synthesized", "event.dns", map[string]string{}, ""},
	} {
		t.Run(tc.name, func(t *testing.T) {
			input := model.Event{Action: tc.action, SourceClass: "ngfw", SrcIP: "10.30.1.8", DstIP: "203.0.113.53", DstPort: 53, Proto: "udp", Bytes: 300, Attrs: tc.attrs}
			body, err := json.Marshal(input)
			if err != nil {
				t.Fatal(err)
			}
			var saved []model.Event
			h := &HTTPHandlers{Token: "dns-contract-token", EmitBatch: func(_ context.Context, events []model.Event) error {
				saved = append(saved, events...)
				return nil
			}}
			req := httptest.NewRequest(http.MethodPost, "/ingest/events", strings.NewReader(string(body)))
			req.Header.Set("X-Argus-Token", "dns-contract-token")
			rec := httptest.NewRecorder()
			h.Mux().ServeHTTP(rec, req)
			if rec.Code != http.StatusAccepted || len(saved) != 1 {
				t.Fatalf("status=%d saved=%d body=%s", rec.Code, len(saved), rec.Body.String())
			}
			if got := saved[0]; got.Attrs["dns_query"] != tc.want || got.Action != tc.action || got.SrcIP != input.SrcIP || got.DstPort != 53 || got.Bytes != 300 {
				t.Fatalf("HTTP ingestion DNS contract: want query=%q, event=%+v", tc.want, got)
			}
		})
	}
}
