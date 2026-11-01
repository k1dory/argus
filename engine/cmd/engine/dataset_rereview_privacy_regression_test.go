package main

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/devitex-soft/argus/engine/internal/analyst"
	"github.com/devitex-soft/argus/engine/internal/dataset"
	"github.com/devitex-soft/argus/engine/internal/enrich"
	"github.com/devitex-soft/argus/engine/internal/eval"
	"github.com/devitex-soft/argus/engine/internal/incidents"
	"github.com/devitex-soft/argus/engine/internal/model"
	"github.com/devitex-soft/argus/engine/internal/rules"
)

// Exercise both real formatters before exportDataset sends the state to the
// socket-free Jev transport in dataset_privacy_regression_test.go. In particular,
// none of these tests injects a hand-written, possibly unreachable chain row.
func pr64RereviewEventIncident(t *testing.T, event *model.Event, enrichment bool) incidents.Incident {
	t.Helper()
	e := *event
	e.TS = "2026-11-01 10:00:00.000"
	e.Source, e.SourceClass, e.Action = "edr.fixture", "edr", "file.access"
	e.Node, e.SrcIP = "web-01", "203.0.113.7"
	if enrichment {
		inc := pr64PrivacyIncident()
		inc.Enrichment = enrich.New(pr64EnrichmentSource{events: []*model.Event{&e}}, "").Run(
			context.Background(), &inc, []any{"edr.process_tree"})
		return inc
	}
	rule := &rules.Rule{ID: "pr64-privacy", Title: "File access", Level: "high"}
	rule.Detection.GroupBy = "src.ip"
	now := time.Date(2026, 11, 1, 10, 0, 0, 0, time.UTC)
	created, _, _ := incidents.NewRegistry(64000, nil).Apply([]eval.Detection{{
		Rule: rule, Key: e.SrcIP, Events: []*model.Event{&e}, First: now, Last: now,
	}}, now)
	if len(created) != 1 {
		t.Fatalf("fixture must create one incident, got %d", len(created))
	}
	inc := *created[0]
	inc.Status = incidents.StatusClosed
	return inc
}

func pr64RereviewObjectPrivacy(t *testing.T, object, private string) {
	t.Helper()
	for _, enrichment := range []bool{false, true} {
		name := "chain"
		if enrichment {
			name = "enrichment"
		}
		t.Run(name, func(t *testing.T) {
			inc := pr64RereviewEventIncident(t, &model.Event{Object: object}, enrichment)
			if !strings.Contains(strings.Join(append(inc.Chain, inc.Enrichment...), "\n"), private) {
				t.Fatalf("private fixture %q was lost before anonymization", private)
			}
			pr64AssertNoPrivateState(t, inc, private)
		})
	}
}

func TestPR64RereviewSystemPathsDoNotDisclosePeople(t *testing.T) {
	for _, tc := range []struct{ object, private string }{
		{"/var/log/users/alice.smirnov/session.log", "alice.smirnov"},
		{"/tmp/anna-petrova-salary.csv", "anna-petrova"},
		{"/srv/www/customers/ivanov/report.pdf", "ivanov"},
		{"/opt/backups/10.64.12.34/config.json", "10.64.12.34"},
		{"/etc/service/accounts/svc-alice.conf", "svc-alice"},
		{"/var/mail/smirnov", "smirnov"},
		{"/tmp/../home/ivanov/private.pdf", "ivanov"},
		{"/library/ivanov/private.pdf", "ivanov"},
	} {
		t.Run(tc.object, func(t *testing.T) {
			pr64RereviewObjectPrivacy(t, tc.object, tc.private)
		})
	}
}

func TestPR64RereviewPathSuffixIsNotNecessarilyAnExtension(t *testing.T) {
	// These are account/directory names, not files with a known extension.
	// Keeping the last dotted component discloses the surname on every path.
	for _, object := range []string{
		"/home/alice.smirnov",
		"/root/contacts/alice.smirnov",
		"/data/users/alice.smirnov",
		`C:\Users\alice.smirnov`,
		"https://example.invalid/users/alice.smirnov",
	} {
		t.Run(object, func(t *testing.T) {
			pr64RereviewObjectPrivacy(t, object, "smirnov")
		})
	}
}

func TestPR64RereviewFreeTextDoesNotBecomeAMeasurement(t *testing.T) {
	for _, tc := range []struct{ object, private string }{
		{"uid=1000 alice", "alice"},
		{"owner_id 42 smirnov", "smirnov"},
	} {
		t.Run(tc.object, func(t *testing.T) {
			// Unit is empty: this is free-text object, not numeric telemetry.
			pr64RereviewObjectPrivacy(t, tc.object, tc.private)
		})
	}
}

func TestPR64RereviewCMDBNoteCannotBecomeCriticality(t *testing.T) {
	inc := pr64PrivacyIncident()
	p := filepath.Join(t.TempDir(), "cmdb.yml")
	const body = "nodes:\n  web-01:\n    owner: fixture-owner\n    team: platform\n    criticality: high\n    note: 'служебная запись, критичность audit.owner'\n"
	if err := os.WriteFile(p, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	inc.Enrichment = enrich.New(nil, p).Run(context.Background(), &inc, []any{"cmdb.owner"})
	if len(inc.Enrichment) != 1 || !strings.Contains(inc.Enrichment[0], "audit.owner") {
		t.Fatalf("note did not reach the production CMDB formatter: %v", inc.Enrichment)
	}
	pr64AssertNoPrivateState(t, inc, "audit.owner", "fixture-owner", "platform")
}

func TestPR64RereviewExcludedTextControls(t *testing.T) {
	for _, enrichment := range []bool{false, true} {
		inc := pr64RereviewEventIncident(t, &model.Event{
			Object: "Alice Smirnov opened the customer document",
			Attrs: map[string]string{
				"user_agent": "Browser/1.0 (private-user-agent-alice)",
				"message":    "private-attrs-alice",
			},
			Raw: "private-raw-alice",
		}, enrichment)
		pr64AssertNoPrivateState(t, inc, "Alice Smirnov", "private-user-agent-alice", "private-attrs-alice", "private-raw-alice")
	}
	pr64RereviewObjectPrivacy(t, "/etc/mail/alice@example.invalid/cache", "alice@example.invalid")
	pr64RereviewObjectPrivacy(t, "https://example.invalid/x?email=alice@example.org", "alice@example.org")
	pr64RereviewObjectPrivacy(t, "/home/svc-alice/report.pdf", "svc-alice")
}

func TestPR64RereviewKnownServiceAccountAndMeasureSurvive(t *testing.T) {
	for _, tc := range []struct {
		event model.Event
		want  string
	}{
		{model.Event{ActorName: "root"}, "root"},
		{model.Event{Object: "/var/lib/clickhouse", Value: 91.5, Unit: "percent"}, "91.5 percent"},
	} {
		inc := pr64RereviewEventIncident(t, &tc.event, false)
		states, _ := pr64ExportToJev(t, inc)
		if len(states) != 1 || !strings.Contains(states[0], tc.want) {
			t.Errorf("safe known-format context %q must survive: %v", tc.want, states)
		}
	}
}

func TestPR64RereviewEnrichmentPIIControlsBothCloudRoutes(t *testing.T) {
	inc := pr64RereviewEventIncident(t, &model.Event{
		Object: "/home/private-person/report.pdf", PII: 1,
	}, true)
	if inc.PII != 1 {
		t.Fatalf("enrichment must propagate PII before either cloud route: %d", inc.PII)
	}
	states, output := pr64ExportToJev(t, inc)
	if len(states) != 0 {
		t.Errorf("Jev received %d PII requests", len(states))
	}
	var record dataset.Record
	if err := json.Unmarshal([]byte(output), &record); err != nil {
		t.Fatal(err)
	}
	if !record.PII || record.Models["jev"].Error == "" {
		t.Errorf("JSONL must retain the PII gate result: %+v", record.Models)
	}
	for _, piiProfile := range []string{"", "local"} {
		t.Run("pii_profile="+piiProfile, func(t *testing.T) {
			an := analyst.New(analyst.Config{
				DefaultProfile: "cloud", ForceProfile: "cloud", PIIProfile: piiProfile,
				Profiles: map[string]analyst.Profile{
					"cloud": {Endpoint: "https://analyst.example.invalid/v1", Model: "fixture"},
					"local": {Backend: "mock"},
				},
			})
			// IsCloud is used by scheduleAnalyze; Analyze calls Route again.
			if an.IsCloud(&inc, "cloud") {
				t.Error("the primary analyst scheduler still sees a cloud route")
			}
			name, profile, err := an.Route(&inc, "cloud")
			if piiProfile == "" {
				if err == nil {
					t.Error("PII without a local override must be rejected")
				}
			} else if err != nil || name != "local" || profile.Cloud() {
				t.Errorf("PII must override the forced cloud profile: %q %+v %v", name, profile, err)
			}
		})
	}
}
