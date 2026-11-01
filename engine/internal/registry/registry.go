// Package registry — реестр поставляемого набора ARGUS: правила из rules/ (id,
// заголовок, теги) и значения source/action, на которые эти правила и фикстуры
// fixtures/events совпадают точно. Реестр не хранится в репозитории: образ
// движка несёт копию rules/ и fixtures/events своей версии (engine/Dockerfile,
// именованные контексты rules и fixtures), а Load читает их при запуске.
//
// Нужен состоянию моделей решений (analyst.DecisionState) и датасету: туда
// попадают только значения из реестра, остальное — «[rule]», «[source]»,
// «[action]». Пользовательские правила (в RULES_DIR рядом с поставляемыми) и
// источники могут называть людей и узлы. Пока реестр не загружен, он пуст:
// любое правило — пользовательское (безопасное направление).
package registry

import (
	"bufio"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"

	"github.com/devitex-soft/argus/engine/internal/attack"
	"github.com/devitex-soft/argus/engine/internal/rules"
)

// DefaultDir — копия поставляемого набора в образе движка.
const DefaultDir = "/usr/share/argus/shipped"

// Rule — поставляемое правило.
type Rule struct {
	Title string
	Tags  []string
}

type snapshot struct {
	rules            map[string]Rule
	sources, actions map[string]bool
	tags             map[string]bool
}

var current atomic.Pointer[snapshot]

func get() *snapshot {
	if s := current.Load(); s != nil {
		return s
	}
	return &snapshot{}
}

// Loaded — реестр загружен (выгрузка датасета без него не запускается).
func Loaded() bool { s := current.Load(); return s != nil && len(s.rules) > 0 }

// Load читает dir/rules (без rules/tests) и dir/fixtures/*.ndjson.
func Load(dir string) error {
	return LoadDirs(filepath.Join(dir, "rules"), filepath.Join(dir, "fixtures"))
}

// LoadDirs — реестр из каталога правил и каталога фикстур событий.
func LoadDirs(rulesDir, fixturesDir string) error {
	s := &snapshot{rules: map[string]Rule{}, sources: map[string]bool{}, actions: map[string]bool{}, tags: map[string]bool{}}
	err := filepath.WalkDir(rulesDir, func(p string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			if d.Name() == "tests" {
				return filepath.SkipDir
			}
			return nil
		}
		if !strings.HasSuffix(p, ".yml") {
			return nil
		}
		r, err := rules.LoadFile(p)
		if err != nil {
			return fmt.Errorf("%s: %w", p, err)
		}
		s.rules[r.ID] = Rule{Title: r.Title, Tags: r.Tags}
		for _, t := range r.Tags {
			s.tags[t] = true
		}
		for _, m := range []map[string]any{r.Detection.Selection, r.Detection.Filter, r.Detection.Reset, r.CloseOn} {
			exact(m, "source", s.sources)
			exact(m, "action", s.actions)
		}
		return nil
	})
	if err != nil {
		return fmt.Errorf("registry: %w", err)
	}
	if len(s.rules) == 0 {
		return errors.New("registry: в " + rulesDir + " нет правил")
	}
	// Фикстуры обязательны отдельно от правил: значения source/action из
	// селекторов правил не заменяют словарь фикстур, и без него состояния
	// молча теряли бы действия (edr.kaspersky / file.read → [action]).
	if st, err := os.Stat(fixturesDir); err != nil || !st.IsDir() {
		return errors.New("registry: нет каталога фикстур " + fixturesDir)
	}
	files, _ := filepath.Glob(filepath.Join(fixturesDir, "*.ndjson"))
	fromFixtures := 0
	for _, f := range files {
		n, err := readFixture(f, s)
		if err != nil {
			return fmt.Errorf("registry: %s: %w", f, err)
		}
		fromFixtures += n
	}
	if fromFixtures == 0 {
		return errors.New("registry: в " + fixturesDir + " нет событий с source и action")
	}
	current.Store(s)
	return nil
}

// LoadEnv — Load(ARGUS_SHIPPED_DIR или DefaultDir).
func LoadEnv() error {
	dir := os.Getenv("ARGUS_SHIPPED_DIR")
	if dir == "" {
		dir = DefaultDir
	}
	return Load(dir)
}

// readFixture — значения source/action из NDJSON; n — событий с обоими полями.
func readFixture(path string, s *snapshot) (n int, err error) {
	f, err := os.Open(path)
	if err != nil {
		return 0, err
	}
	defer f.Close()
	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 1<<20), 1<<24)
	for sc.Scan() {
		var e struct{ Source, Action string }
		if json.Unmarshal(sc.Bytes(), &e) == nil {
			if e.Source != "" {
				s.sources[e.Source] = true
			}
			if e.Action != "" {
				s.actions[e.Action] = true
			}
			if e.Source != "" && e.Action != "" {
				n++
			}
		}
	}
	return n, sc.Err()
}

// exact — точные значения поля key (без модификаторов |contains и т. п.).
func exact(m map[string]any, key string, into map[string]bool) {
	switch x := m[key].(type) {
	case string:
		into[x] = true
	case []any:
		for _, v := range x {
			if v, ok := v.(string); ok {
				into[v] = true
			}
		}
	}
}

// LookupRule — поставляемое правило по id.
func LookupRule(id string) (Rule, bool) {
	r, ok := get().rules[id]
	return r, ok
}

// Source, Action — значение из реестра.
func Source(s string) bool { return get().sources[s] }
func Action(s string) bool { return get().actions[s] }

// Tag — тег поставляемых правил или тег ATT&CK из справочника.
func Tag(t string) bool { return CleanTag(t, true) != "" }

// CleanTag — тег для состояния и записи: тег поставляемых правил как есть
// (shipped), канонический тег ATT&CK из справочника, иначе "".
func CleanTag(t string, shipped bool) string {
	if shipped && get().tags[t] {
		return t
	}
	return NormalizeAttackTag(t)
}

// AttackTag — тег тактики или техники, которая есть в справочнике ATT&CK
// (engine/internal/attack): «attack.alice_smirnov» по форме похож на тактику,
// но в справочнике его нет — это не тег ATT&CK, а свободный текст.
func AttackTag(t string) bool { return NormalizeAttackTag(t) != "" }

// NormalizeAttackTag — канонический вид тега ATT&CK (trim, нижний регистр:
// attack.credential_access, attack.t1558.003) или "", если тактики или
// техники нет в справочнике. Так же теги понимает attack.Candidates.
func NormalizeAttackTag(t string) string {
	t = strings.ToLower(strings.TrimSpace(t))
	if len(attack.RuleTactics([]string{t})) == 1 || len(attack.RuleTechniques([]string{t})) == 1 {
		return t
	}
	return ""
}
