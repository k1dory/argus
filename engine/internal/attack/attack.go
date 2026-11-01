// Package attack — справочник ATT&CK Enterprise для проверки метки закрытия.
// enterprise.json генерирует scripts/attack-enterprise.py; та же копия лежит в
// консоли (web/src/lib/shared/attack-enterprise.json), где по ней строятся
// кандидаты техники. Движок проверяет, что тактика и техника есть в справочнике.
package attack

import (
	_ "embed"
	"encoding/json"
)

// Other — ответ «другое» для тактики и техники.
const Other = "other"

//go:embed enterprise.json
var raw []byte

type dictionary struct {
	Version    string          `json:"version"`
	Tactics    []TacticInfo    `json:"tactics"`
	Techniques []TechniqueInfo `json:"techniques"`
}

var (
	version       string
	tactics       = map[string]bool{}
	techniques    = map[string]bool{}
	tacticList    []TacticInfo
	techniqueList []TechniqueInfo // порядок файла — по возрастанию ID
	byID          = map[string]TechniqueInfo{}
)

func init() {
	var d dictionary
	if err := json.Unmarshal(raw, &d); err != nil {
		panic("attack: enterprise.json: " + err.Error())
	}
	version = d.Version
	tacticList, techniqueList = d.Tactics, d.Techniques
	for _, t := range d.Tactics {
		tactics[t.Shortname] = true
	}
	for _, t := range d.Techniques {
		techniques[t.ID] = true
		byID[t.ID] = t
	}
	if version == "" || len(tactics) == 0 || len(techniques) == 0 {
		panic("attack: enterprise.json пуст")
	}
}

// Version — версия справочника (attrs метки attack_version).
func Version() string { return version }

// Tactic — shortname тактики из справочника или Other.
func Tactic(s string) bool { return s == Other || tactics[s] }

// Technique — ID техники или подтехники (T1110, T1110.001) из справочника или Other.
func Technique(s string) bool { return s == Other || techniques[s] }
