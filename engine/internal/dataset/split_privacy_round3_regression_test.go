package dataset

import (
	"bytes"
	"crypto/sha256"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"io"
	"strings"
	"testing"

	"github.com/devitex-soft/argus/engine/internal/incidents"
	"github.com/devitex-soft/argus/engine/internal/store"
)

func TestPR64Round3SplitDoesNotRevealSubnetByDictionary(t *testing.T) {
	// These shipped rules all group by src.ip. A scanner can appear under
	// several of them, and the exported Subject pseudonym links those rows.
	ruleIDs := []string{
		"a41c-auth-031", "a41c-auth-032", "a41c-auth-033",
		"a41c-net-070", "a41c-net-071", "a41c-net-072", "a41c-net-073",
		"a41c-net-074", "a41c-net-075", "a41c-net-076",
	}
	subject := func(state string) string {
		for _, line := range strings.Split(state, "\n") {
			if value, ok := strings.CutPrefix(line, "Subject: "); ok {
				return value
			}
		}
		return ""
	}
	var records []*Record
	truth := map[string]string{}
	var targetPseudonym string
	for _, octet := range []int{0, 1, 2, 3, 4, 5, 12, 113} {
		subnet := fmt.Sprintf("203.0.%d.0/24", octet)
		for _, ruleID := range ruleIDs {
			inc := incidents.Incident{
				IncidentID: fmt.Sprintf("INC-%d", len(records)+1), RuleID: ruleID,
				RuleTitle: "Network activity", Level: "high", Status: incidents.StatusClosed,
				ActorName: fmt.Sprintf("203.0.%d.7", octet), Node: "fixture-web", EventCount: 60,
			}
			record := Build(store.LabeledIncident{
				Incident: inc,
				Label: store.ClosureLabel{
					Disposition: "malicious", Escalate: bp(true), SeverityCorrect: bp(true), LabeledByHuman: true,
				},
			}, "prod")
			if record == nil {
				t.Fatal("human-labeled fixture must be exported")
			}
			pseudonym := subject(record.State)
			if pseudonym == "" || strings.Contains(record.State, subnet) || strings.Contains(record.State, inc.ActorName) {
				t.Fatal("fixture must have a pseudonymized subject, with no plaintext address")
			}
			truth[pseudonym] = subnet // Ground truth for assertions, not given to the attacker.
			if octet == 113 {
				targetPseudonym = pseudonym
			}
			records = append(records, record)
		}
	}
	// Eight rows per rule fit the default cap. No special export flags or
	// group_id salt are needed for this attack.
	var output bytes.Buffer
	enc := json.NewEncoder(&output)
	for _, record := range Cap(records, MaxPerRule) {
		if err := enc.Encode(record); err != nil {
			t.Fatal(err)
		}
	}

	// Attacker side: only exported fields and a 256-entry candidate dictionary.
	// Deliberately do not call groupKey, bucket, GroupID or analyst.Process.
	type observation struct {
		RuleID string `json:"rule_id"`
		Split  string `json:"split"`
		State  string `json:"state"`
	}
	groups := map[string][]observation{}
	dec := json.NewDecoder(&output)
	for {
		var row observation
		if err := dec.Decode(&row); err == io.EOF {
			break
		} else if err != nil {
			t.Fatal(err)
		}
		groups[subject(row.State)] = append(groups[subject(row.State)], row)
	}
	publicSplit := func(ruleID, candidate string) string {
		digest := sha256.Sum256([]byte("split|" + ruleID + "|" + candidate))
		if int(binary.BigEndian.Uint16(digest[:2]))%100 < 25 {
			return "holdout"
		}
		return "train"
	}
	var matches []string
	for octet := 0; octet < 256; octet++ {
		candidate := fmt.Sprintf("203.0.%d.0/24", octet)
		match := true
		for _, row := range groups[targetPseudonym] {
			if publicSplit(row.RuleID, candidate) != row.Split {
				match = false
				break
			}
		}
		if match {
			matches = append(matches, candidate)
		}
	}

	// A keyed split can accidentally match a few public bits. Require the
	// entire 80-row fixture to remain publicly predictable before reporting
	// the regression, so a future keyed implementation is not flaky.
	if len(groups) != len(truth) || len(groups[targetPseudonym]) != len(ruleIDs) {
		t.Fatal("fixture lost subjects or rule observations during export")
	}
	allPublic := true
	for pseudonym, rows := range groups {
		for _, row := range rows {
			if publicSplit(row.RuleID, truth[pseudonym]) != row.Split {
				allPublic = false
			}
		}
	}
	if allPublic {
		if len(matches) != 1 || matches[0] != "203.0.113.0/24" {
			t.Fatalf("public split dictionary fixture is no longer decisive: %v", matches)
		}
		t.Errorf("JSONL reveals subnet %s from ten split bits and a shared Subject pseudonym; salted group_id is not consulted", matches[0])
	}
}
