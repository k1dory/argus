package attack

import (
	"regexp"
	"slices"
	"strings"
)

// Кандидаты техники для вопроса attack_technique — порт web/src/lib/shared/attack.ts
// (techniqueCandidates, defaultTactic). Обе реализации сверяются с одним эталоном
// testdata/attack-candidates.json (TestCandidatesGolden здесь,
// web/tests/attack-candidates.test.ts в консоли): расхождение роняет CI.

// MaxCandidates — потолок кандидатов техники; «другое» в список не входит.
const MaxCandidates = 20

// TacticInfo — тактика в порядке матрицы.
type TacticInfo struct {
	Shortname string `json:"shortname"`
	Name      string `json:"name"`
}

// TechniqueInfo — техника или подтехника справочника.
type TechniqueInfo struct {
	ID      string   `json:"id"`
	Name    string   `json:"name"`
	Tactics []string `json:"tactics"`
}

// Tactics — тактики в порядке матрицы (копия).
func Tactics() []TacticInfo { return slices.Clone(tacticList) }

// TechniqueByID — техника справочника; ok=false — такой нет.
func TechniqueByID(id string) (TechniqueInfo, bool) {
	t, ok := byID[id]
	return t, ok
}

var (
	reTacticTag    = regexp.MustCompile(`^attack\.([a-z][a-z_-]*)$`)
	reTechniqueTag = regexp.MustCompile(`^attack\.(t\d{4}(?:\.\d{3})?)$`)
)

func parentOf(id string) string { p, _, _ := strings.Cut(id, "."); return p }

// RuleTactics — тактики из тегов attack.<tactic> (credential_access →
// credential-access), которые есть в справочнике, без повторов, в порядке тегов.
func RuleTactics(tags []string) []string {
	var out []string
	for _, tag := range tags {
		m := reTacticTag.FindStringSubmatch(strings.ToLower(strings.TrimSpace(tag)))
		if m == nil {
			continue
		}
		short := strings.ReplaceAll(m[1], "_", "-")
		if tactics[short] && !slices.Contains(out, short) {
			out = append(out, short)
		}
	}
	return out
}

// RuleTechniques — техники из тегов attack.tNNNN[.NNN], которые есть в
// справочнике, без повторов, в порядке тегов.
func RuleTechniques(tags []string) []string {
	var out []string
	for _, tag := range tags {
		m := reTechniqueTag.FindStringSubmatch(strings.ToLower(strings.TrimSpace(tag)))
		if m == nil {
			continue
		}
		id := strings.ToUpper(m[1])
		if _, ok := byID[id]; ok && !slices.Contains(out, id) {
			out = append(out, id)
		}
	}
	return out
}

// DefaultTactic — первая тактика из тегов; иначе общая тактика всех техник из
// тегов, если она одна; иначе "".
func DefaultTactic(tags []string) string {
	if ts := RuleTactics(tags); len(ts) > 0 {
		return ts[0]
	}
	techs := RuleTechniques(tags)
	if len(techs) == 0 {
		return ""
	}
	common := slices.Clone(byID[techs[0]].Tactics)
	for _, id := range techs[1:] {
		common = slices.DeleteFunc(common, func(x string) bool { return !slices.Contains(byID[id].Tactics, x) })
	}
	if len(common) == 1 {
		return common[0]
	}
	return ""
}

// Candidates — ID кандидатов техники для выбранной тактики, не больше
// MaxCandidates: техники из тегов; родитель и подтехники того же родителя;
// остальные техники тактики (сначала без точки, потом подтехники) в порядке
// справочника. Шаги 2–3 — в выбранной тактике; без неё (Other или "") — в
// тактиках техник из тегов.
func Candidates(tags []string, tactic string) []string {
	tagged := RuleTechniques(tags)
	scope := map[string]bool{}
	if tactics[tactic] {
		scope[tactic] = true
	} else {
		for _, id := range tagged {
			for _, x := range byID[id].Tactics {
				scope[x] = true
			}
		}
	}
	out := make([]string, 0, MaxCandidates)
	add := func(id string) {
		if len(out) < MaxCandidates && !slices.Contains(out, id) {
			out = append(out, id)
		}
	}
	inScope := func(t TechniqueInfo) bool {
		return slices.ContainsFunc(t.Tactics, func(x string) bool { return scope[x] })
	}
	for _, id := range tagged {
		add(id)
	}
	for _, id := range tagged {
		parent := parentOf(id)
		for _, t := range techniqueList {
			if (t.ID == parent || parentOf(t.ID) == parent) && inScope(t) {
				add(t.ID)
			}
		}
	}
	for _, t := range techniqueList {
		if !strings.Contains(t.ID, ".") && inScope(t) {
			add(t.ID)
		}
	}
	for _, t := range techniqueList {
		if strings.Contains(t.ID, ".") && inScope(t) {
			add(t.ID)
		}
	}
	return out
}
