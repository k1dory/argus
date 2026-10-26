package identity

import (
	"fmt"
	"os"
	"sort"
	"strings"
	"time"

	"gopkg.in/yaml.v3"
)

// Set — содержимое identities.yml после проверки и нормализации: персоны и
// их алиасы в детерминированном порядке (по person_id, затем по порядку в
// файле) и политики алиасов из событий (policy.go).
type Set struct {
	Persons  []Person
	Aliases  []Alias
	Policies Policies
}

// Формат identities.yml:
//
//	persons:
//	  i.petrov:
//	    display: "Иван Петров"
//	    kind: person          # person | service, по умолчанию person
//	    team: platform
//	    note: ""
//	    aliases:
//	      - {kind: email, value: i.petrov@example.org}
//	      - {kind: login, value: ipetrov}
//	      - {kind: ip, value: 10.77.0.11, from: 2026-10-01, to: 2026-10-20, confidence: 0.9, note: "ноутбук"}
//
//	policies:
//	  ip: { sources: ["event:vpn.*"], max_open: 2, churn: { max: 20, window: 24h }, on_violation: flag }
//
// from/to — YYYY-MM-DD или RFC3339; нет from — алиас действует всегда
// (1970-01-01), нет to — действует по сей день. Неизвестные ключи и
// недопустимые значения — ошибка с путём до поля. policies — ограничения
// на алиасы из событий по виду (policy.go); к алиасам файла не применяются.
type fileDoc struct {
	Persons  map[string]filePerson `yaml:"persons"`
	Policies map[string]filePolicy `yaml:"policies"`
}

type filePerson struct {
	Display string      `yaml:"display"`
	Kind    string      `yaml:"kind"`
	Team    string      `yaml:"team"`
	Note    string      `yaml:"note"`
	Aliases []fileAlias `yaml:"aliases"`
}

type fileAlias struct {
	Kind       string   `yaml:"kind"`
	Value      string   `yaml:"value"`
	From       string   `yaml:"from"`
	To         string   `yaml:"to"`
	Confidence *float64 `yaml:"confidence"`
	Note       string   `yaml:"note"`
}

// LoadFile — разбор identities.yml. Пустой файл (или без persons) — пустой Set.
func LoadFile(path string) (Set, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return Set{}, err
	}
	set, err := Parse(raw)
	if err != nil {
		return Set{}, fmt.Errorf("%s: %w", path, err)
	}
	return set, nil
}

// Parse — разбор содержимого identities.yml.
func Parse(raw []byte) (Set, error) {
	dec := yaml.NewDecoder(strings.NewReader(string(raw)))
	dec.KnownFields(true)
	var doc fileDoc
	err := dec.Decode(&doc)
	if err != nil && !strings.Contains(err.Error(), "EOF") {
		return Set{}, err
	}
	ids := make([]string, 0, len(doc.Persons))
	for id := range doc.Persons {
		ids = append(ids, id)
	}
	sort.Strings(ids)
	var set Set
	if set.Policies, err = parsePolicies(doc.Policies); err != nil {
		return Set{}, err
	}
	for _, id := range ids {
		p := doc.Persons[id]
		path := "persons." + id
		if !ValidPersonID(id) {
			return Set{}, fmt.Errorf("%s: недопустимый person_id (ожидается ^[a-z0-9][a-z0-9._-]{0,63}$)", path)
		}
		kind := strings.TrimSpace(p.Kind)
		switch kind {
		case "":
			kind = PersonKind
		case PersonKind, ServiceKind:
		default:
			return Set{}, fmt.Errorf("%s.kind: %q (ожидается person | service)", path, p.Kind)
		}
		display := strings.TrimSpace(p.Display)
		if display == "" {
			display = id
		}
		set.Persons = append(set.Persons, Person{ID: id, Display: display, Kind: kind, Team: strings.TrimSpace(p.Team), Note: strings.TrimSpace(p.Note)})
		seen := map[string]bool{}
		for i, a := range p.Aliases {
			apath := fmt.Sprintf("%s.aliases[%d]", path, i)
			alias, err := a.alias(id, apath)
			if err != nil {
				return Set{}, err
			}
			if seen[alias.Key()] {
				return Set{}, fmt.Errorf("%s: алиас %s %s с тем же from уже объявлен", apath, alias.Kind, alias.Value)
			}
			seen[alias.Key()] = true
			set.Aliases = append(set.Aliases, alias)
		}
	}
	return set, nil
}

func (a fileAlias) alias(personID, path string) (Alias, error) {
	value, err := Normalize(strings.TrimSpace(a.Kind), a.Value)
	if err != nil {
		return Alias{}, fmt.Errorf("%s: %w", path, err)
	}
	from := Epoch
	if s := strings.TrimSpace(a.From); s != "" {
		if from, err = ParseTime(s); err != nil {
			return Alias{}, fmt.Errorf("%s.from: %w", path, err)
		}
	}
	var to *time.Time
	if s := strings.TrimSpace(a.To); s != "" {
		t, err := ParseTime(s)
		if err != nil {
			return Alias{}, fmt.Errorf("%s.to: %w", path, err)
		}
		if !t.After(from) {
			return Alias{}, fmt.Errorf("%s.to: %s не позже from (%s)", path, t.Format(time.RFC3339), from.Format(time.RFC3339))
		}
		to = &t
	}
	conf := float32(1)
	if a.Confidence != nil {
		if *a.Confidence <= 0 || *a.Confidence > 1 {
			return Alias{}, fmt.Errorf("%s.confidence: %v (ожидается в (0, 1])", path, *a.Confidence)
		}
		conf = float32(*a.Confidence)
	}
	return Alias{PersonID: personID, Kind: strings.TrimSpace(a.Kind), Value: value, ValidFrom: from, ValidTo: to,
		Source: SourceYAML, Confidence: conf, Note: strings.TrimSpace(a.Note)}, nil
}
