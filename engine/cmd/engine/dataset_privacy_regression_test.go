package main

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/devitex-soft/argus/engine/internal/enrich"
	"github.com/devitex-soft/argus/engine/internal/eval"
	"github.com/devitex-soft/argus/engine/internal/incidents"
	"github.com/devitex-soft/argus/engine/internal/model"
	"github.com/devitex-soft/argus/engine/internal/rules"
	"github.com/devitex-soft/argus/engine/internal/store"
	"github.com/devitex-soft/argus/engine/internal/systemone"
)

// These fixtures never dial a socket or use a real API key. Capture the actual
// export -> Decide HTTP request, after all production sanitization has run.
type pr64DatasetTransport func(*http.Request) (*http.Response, error)

func (f pr64DatasetTransport) RoundTrip(r *http.Request) (*http.Response, error) {
	return f(r)
}

func pr64ExportToJev(t *testing.T, inc incidents.Incident) (states []string, output string) {
	t.Helper()
	jev := &systemone.Client{
		Name: "jev", Endpoint: "https://decisions.example.invalid/v1/systemone",
		APIKey: "pr64-dummy-key", Model: "fixture-model",
		HTTP: &http.Client{Transport: pr64DatasetTransport(func(req *http.Request) (*http.Response, error) {
			var payload struct {
				State string `json:"state"`
			}
			if err := json.NewDecoder(req.Body).Decode(&payload); err != nil {
				t.Fatal(err)
			}
			states = append(states, payload.State)
			// A non-200 response is sufficient: the privacy boundary has already
			// been crossed when RoundTrip receives the request body.
			return &http.Response{StatusCode: http.StatusServiceUnavailable, Header: make(http.Header),
				Body: io.NopCloser(strings.NewReader("fixture unavailable")), Request: req}, nil
		})},
	}
	var out bytes.Buffer
	_, err := exportDataset(context.Background(), fakeLabeled{{
		Incident: inc, Label: store.ClosureLabel{Disposition: "malicious", LabeledByHuman: true},
	}}, &out, datasetOpts{Source: "prod", Models: []string{"jev"}}, nil, jev)
	if err != nil {
		t.Fatal(err)
	}
	return states, out.String()
}

func pr64PrivacyIncident() incidents.Incident {
	return incidents.Incident{
		IncidentID: "INC-64001", RuleID: "pr64-privacy", RuleTitle: "Authentication failure", Level: "high",
		Status: incidents.StatusClosed, ActorName: "203.0.113.7", Node: "web-01", PII: 0,
		FirstTS: "2026-11-01 10:00:00.000", LastTS: "2026-11-01 10:01:00.000",
	}
}

func pr64AssertNoPrivateState(t *testing.T, inc incidents.Incident, private ...string) {
	t.Helper()
	states, output := pr64ExportToJev(t, inc)
	// A fix may refuse unsafe cloud context altogether, or sanitize it. The
	// independently exported training state must be sanitized in either case.
	for _, value := range private {
		for _, state := range states {
			if strings.Contains(state, value) {
				t.Errorf("Jev request discloses private fixture %q with incident pii=%d", value, inc.PII)
			}
		}
		if strings.Contains(output, value) {
			t.Errorf("exported JSONL discloses private fixture %q", value)
		}
	}
}

func TestPR64DatasetPrivacyChainAccounts(t *testing.T) {
	// Reproduce the real chain builder: grouping a brute-force detection by
	// src.ip makes the actor an IP, while the attempted accounts stay in chain.
	rule := &rules.Rule{ID: "pr64-auth", Title: "SSH brute force", Level: "high"}
	rule.Detection.GroupBy = "src.ip"
	now := time.Date(2026, 11, 1, 10, 0, 0, 0, time.UTC)
	events := []*model.Event{
		{TS: model.FormatTS(now), Source: "host.sshd", Action: "auth.login", ActorName: "audit.alice", Node: "web-01", SrcIP: "203.0.113.7"},
		{TS: model.FormatTS(now.Add(time.Second)), Source: "host.sshd", Action: "auth.login", ActorName: "audit.bob", Node: "web-01", SrcIP: "203.0.113.7"},
	}
	created, _, _ := incidents.NewRegistry(64000, nil).Apply([]eval.Detection{{
		Rule: rule, Key: "203.0.113.7", Events: events, First: now, Last: now.Add(time.Second),
	}}, now.Add(time.Second))
	if len(created) != 1 || created[0].ActorName != "203.0.113.7" || created[0].PII != 0 {
		t.Fatalf("unexpected incident fixture: %+v", created)
	}
	inc := *created[0]
	inc.Status = incidents.StatusClosed
	for _, account := range []string{"audit.alice", "audit.bob"} {
		if !strings.Contains(strings.Join(inc.Chain, "\n"), account) {
			t.Fatalf("chain fixture does not contain %q", account)
		}
	}
	pr64AssertNoPrivateState(t, inc, "audit.alice", "audit.bob")
}

func TestPR64DatasetPrivacyChainNodes(t *testing.T) {
	rule := &rules.Rule{ID: "pr64-hosts", Title: "Activity across hosts", Level: "high"}
	rule.Detection.GroupBy = "actor.name"
	now := time.Date(2026, 11, 1, 10, 0, 0, 0, time.UTC)
	events := []*model.Event{
		{TS: model.FormatTS(now), Source: "host.sshd", Action: "auth.login", ActorName: "audit.primary", Node: "audit-alice-workstation"},
		{TS: model.FormatTS(now.Add(time.Second)), Source: "host.sshd", Action: "auth.login", ActorName: "audit.primary", Node: "audit-bob-pc"},
	}
	created, _, _ := incidents.NewRegistry(64100, nil).Apply([]eval.Detection{{
		Rule: rule, Key: "audit.primary", Events: events, First: now, Last: now.Add(time.Second),
	}}, now.Add(time.Second))
	if len(created) != 1 || created[0].Node != events[0].Node {
		t.Fatalf("unexpected incident fixture: %+v", created)
	}
	inc := *created[0]
	inc.Status = incidents.StatusClosed
	chain := strings.Join(inc.Chain, "\n")
	if strings.Contains(chain, events[0].Node) || !strings.Contains(chain, "audit-alice") || !strings.Contains(chain, "audit-bob-pc") {
		t.Fatalf("fixture must contain the truncated primary node and a second node: %q", chain)
	}
	pr64AssertNoPrivateState(t, inc, "audit-alice", "audit-bob-pc")
}

type pr64EnrichmentSource struct{ events []*model.Event }

func (s pr64EnrichmentSource) EventsAround(context.Context, string, string, string, string, time.Time, time.Time, int) ([]*model.Event, error) {
	return s.events, nil
}

func TestPR64DatasetPrivacyEnrichment(t *testing.T) {
	t.Run("cmdb owner and free-text note", func(t *testing.T) {
		inc := pr64PrivacyIncident()
		path := filepath.Join(t.TempDir(), "cmdb.yml")
		const cmdb = "nodes:\n  web-01:\n    owner: audit.owner\n    team: platform\n    criticality: high\n    note: 'Контакт: Тестов Тест Тестович'\n"
		if err := os.WriteFile(path, []byte(cmdb), 0o600); err != nil {
			t.Fatal(err)
		}
		inc.Enrichment = enrich.New(nil, path).Run(context.Background(), &inc, []any{"cmdb.owner"})
		if len(inc.Enrichment) != 1 || !strings.Contains(inc.Enrichment[0], "audit.owner") {
			t.Fatalf("CMDB fixture was not enriched: %v", inc.Enrichment)
		}
		pr64AssertNoPrivateState(t, inc, "audit.owner", "Тестов Тест Тестович")
	})
	t.Run("PII in a related EDR event", func(t *testing.T) {
		inc := pr64PrivacyIncident()
		source := pr64EnrichmentSource{events: []*model.Event{{
			TS: inc.FirstTS, Source: "edr.fixture", Action: "process.start", Node: inc.Node,
			Object: "/home/audit.private/Documents/report.txt", PII: 1,
		}}}
		inc.Enrichment = enrich.New(source, "").Run(context.Background(), &inc, []any{"edr.process_tree"})
		if !strings.Contains(strings.Join(inc.Enrichment, "\n"), "audit.private") {
			t.Fatal("EDR fixture did not reach the enrichment formatter")
		}
		pr64AssertNoPrivateState(t, inc, "audit.private")
	})
}

func TestPR64DatasetPrivacyPrivateIPv6(t *testing.T) {
	inc := pr64PrivacyIncident()
	inc.ActorName = "fd12:3456:789a::1234"
	inc.Node = "fd12:3456:789a::5678"
	inc.Chain = []string{"auth.login from fd12:3456:789a::1234 to fd12:3456:789a::5678"}
	inc.Enrichment = []string{"ngfw.sessions: destination fd12:3456:789a::9abc"}
	pr64AssertNoPrivateState(t, inc, "fd12:3456:789a::1234", "fd12:3456:789a::5678", "fd12:3456:789a::9abc")
}

func TestPR64DatasetPrivacyGateAndExcludedFields(t *testing.T) {
	for _, pii := range []uint8{0, 1, 2} {
		inc := pr64PrivacyIncident()
		inc.PII = pii
		inc.ActorName = "audit.primary"
		inc.Owner, inc.Note = "audit.analyst", "PRIVATE_CLOSURE_COMMENT"
		inc.Similar = []string{"INC-63 · 2026-10-31 · closed · SSH rule · PRIVATE_SIMILAR_COMMENT"}
		inc.RuleTitle = "Rule contact fixture@example.invalid"
		inc.Sources = []string{"fixture@example.invalid"}
		inc.Chain = []string{"audit.primary web-01 phone +7 912 345-67-89 fixture@example.invalid"}
		states, _ := pr64ExportToJev(t, inc)
		if pii != 0 {
			if len(states) != 0 {
				t.Errorf("pii=%d: Jev received %d requests", pii, len(states))
			}
			continue
		}
		if len(states) != 1 {
			t.Fatalf("safe pii=0 fixture must make exactly one request, got %d", len(states))
		}
		for _, private := range []string{"audit.primary", "web-01", "audit.analyst", "PRIVATE_CLOSURE_COMMENT", "PRIVATE_SIMILAR_COMMENT", "fixture@example.invalid", "912 345"} {
			if strings.Contains(states[0], private) {
				t.Errorf("unexpected private field in Jev state: %q", private)
			}
		}
	}
}
