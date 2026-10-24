package store

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/devitex-soft/argus/engine/internal/webhook"
)

func TestWebhookDeliveryRoundTrip(t *testing.T) {
	var inserted, query string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		if q := r.URL.Query().Get("query"); strings.HasPrefix(q, "INSERT INTO webhook_deliveries") {
			inserted = string(body)
			return
		}
		query = string(body) + " " + r.URL.Query().Get("param_target") + " " + r.URL.Query().Get("param_key")
		if r.URL.Query().Get("param_key") == "INC-1|incident.created" {
			fmt.Fprintln(w, `{"incident_id":"INC-1","event":"incident.created","state":"delivered","ref":"200","updated_ms":1760263200000}`)
		}
	}))
	defer srv.Close()
	c := New(srv.URL, "argus", "", "")
	at := time.Date(2026, 10, 12, 10, 0, 0, 0, time.UTC)
	if err := c.SaveWebhookDelivery(context.Background(), webhook.Record{Target: "soc", Key: "INC-1|incident.created", IncidentID: "INC-1",
		Event: "incident.created", State: "delivered", Ref: "200", UpdatedAt: at}); err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{`"target":"soc"`, `"dedup_key":"INC-1|incident.created"`, `"state":"delivered"`, `"ref":"200"`, `"updated_at":"2026-10-12 10:00:00.000"`} {
		if !strings.Contains(inserted, want) {
			t.Fatalf("в строке нет %s: %s", want, inserted)
		}
	}
	if strings.Contains(inserted, "task_id") {
		t.Fatalf("колонка task_id больше не пишется: %s", inserted)
	}
	r, ok, err := c.LookupWebhookDelivery(context.Background(), "soc", "INC-1|incident.created")
	if err != nil || !ok || r.State != "delivered" || r.Ref != "200" || !r.UpdatedAt.Equal(time.UnixMilli(1760263200000)) {
		t.Fatalf("lookup %+v ok=%v err=%v", r, ok, err)
	}
	if !strings.Contains(query, "{target:String}") || !strings.Contains(query, "soc INC-1|incident.created") {
		t.Fatalf("запрос без параметров: %s", query)
	}
	if _, ok, err := c.LookupWebhookDelivery(context.Background(), "soc", "INC-2|incident.created"); ok || err != nil {
		t.Fatalf("нет отметки: ok=%v err=%v", ok, err)
	}
}
