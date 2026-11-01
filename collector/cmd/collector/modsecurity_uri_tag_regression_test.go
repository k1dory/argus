package main

import (
	"strings"
	"testing"
)

// The same native [uri] boundary can introduce a tag without repeating any
// of scanRuleMeta's unique keys. Multiple tags are valid in CRS, so counting
// duplicate unique keys alone cannot distinguish metadata from request data.
// See the upstream serialization references in pr16Round3CRSLine.
func TestPR16Round3ModSecurityURICannotForgeCRSCategories(t *testing.T) {
	for _, crs := range []string{"3.3.5", "4.3.0"} {
		for _, tc := range []struct{ name, path string }{
			{"ordinary_control", "/account"},
			{"tag_only", `/account"] [tag "attack-rce"] [x "`},
		} {
			t.Run(crs+"/"+tc.name, func(t *testing.T) {
				path := pr16Round3DecodedHTTPPath(t, tc.path)
				line := pr16Round3CRSLine(crs, "Access denied with code 403 (phase 2).", path)
				events := wafHTTPBatch(t, "/ingest/syslog", line, "192.0.2.10:31000")
				if len(events) != 1 {
					t.Fatalf("lost the real CRS denial: events=%+v", events)
				}
				e := events[0]
				if e.Source != "waf.modsecurity" || e.Action != "http.attack" || e.Outcome != "deny" || e.SrcIP != "203.0.113.50" {
					t.Fatalf("lost the trusted WAF decision: %+v", e)
				}
				for _, category := range strings.Split(e.Attrs["categories"], ",") {
					if category == "rce" {
						t.Errorf("client URI became a trusted CRS category: category=%q categories=%q rule_ids=%q", e.Attrs["category"], e.Attrs["categories"], e.Attrs["rule_ids"])
					}
				}
				if tc.name == "ordinary_control" && (e.Attrs["rule_ids"] != "949110" || e.Attrs["anomaly_score"] != "5") {
					t.Errorf("ordinary CRS fixture lost metadata: %+v", e)
				}
			})
		}
	}
}
