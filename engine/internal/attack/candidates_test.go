package attack

import (
	"encoding/json"
	"os"
	"slices"
	"testing"
)

// golden — testdata/attack-candidates.json: тот же эталон читает
// web/tests/attack-candidates.test.ts (перегенерация — UPDATE_GOLDEN=1 там).
type golden struct {
	Version string `json:"version"`
	Max     int    `json:"max"`
	Cases   []struct {
		Tags          []string            `json:"tags"`
		DefaultTactic string              `json:"default_tactic"`
		Candidates    map[string][]string `json:"candidates"`
	} `json:"cases"`
}

func TestCandidatesGolden(t *testing.T) {
	raw, err := os.ReadFile("../../../testdata/attack-candidates.json")
	if err != nil {
		t.Fatal(err)
	}
	var g golden
	if err := json.Unmarshal(raw, &g); err != nil {
		t.Fatal(err)
	}
	if g.Version != Version() || g.Max != MaxCandidates || len(g.Cases) == 0 {
		t.Fatalf("эталон: версия %q (справочник %q), max %d, кейсов %d", g.Version, Version(), g.Max, len(g.Cases))
	}
	for _, c := range g.Cases {
		if got := DefaultTactic(c.Tags); got != c.DefaultTactic {
			t.Errorf("%v: тактика по умолчанию %q, эталон %q", c.Tags, got, c.DefaultTactic)
		}
		if len(c.Candidates) != len(tacticList)+1 {
			t.Errorf("%v: в эталоне %d ключей, ждали %d тактик + other", c.Tags, len(c.Candidates), len(tacticList))
		}
		for tactic, want := range c.Candidates {
			if got := Candidates(c.Tags, tactic); !slices.Equal(got, want) {
				t.Errorf("%v / %s:\n got  %v\n want %v", c.Tags, tactic, got, want)
			}
		}
	}
}
