package dataset

import (
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"testing"

	"github.com/devitex-soft/argus/engine/internal/store"
)

func TestPR64RereviewExportedGroupDoesNotAllowSubjectDictionaryAttack(t *testing.T) {
	for _, tc := range []struct {
		name, actor, node string
		dictionary        []string
	}{
		{"account", "alice.smirnov", "web-01", []string{"root", "bob.petrov", "alice.smirnov"}},
		{"host", "", "alice-laptop", []string{"web-01", "alice-laptop", "db-01"}},
		{"private_subnet", "10.64.12.34", "web-01", []string{"10.64.11.0/24", "10.64.12.0/24", "10.64.13.0/24"}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			inc := secIncident("INC-64001", tc.actor)
			inc.Node = tc.node
			record := Build(human(inc, store.ClosureLabel{Disposition: "malicious"}), "prod")
			if record == nil {
				t.Fatal("labeled fixture must be exported")
			}
			raw, err := json.Marshal(record)
			if err != nil {
				t.Fatal(err)
			}
			// The recipient only needs these public JSONL fields. It never gets
			// analyst.processPseudonyms or its salt, nor the original incident.
			var exported struct {
				RuleID  string `json:"rule_id"`
				GroupID string `json:"group_id"`
			}
			if err := json.Unmarshal(raw, &exported); err != nil {
				t.Fatal(err)
			}
			for _, guess := range tc.dictionary {
				sum := sha256.Sum256([]byte(exported.RuleID + "|" + guess))
				if fmt.Sprintf("g-%x", sum[:6]) == exported.GroupID {
					t.Errorf("JSONL reveals subject %q by a public hash comparison; salted state pseudonyms do not protect group_id", guess)
				}
			}
		})
	}
}
