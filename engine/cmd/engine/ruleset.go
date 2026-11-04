package main

import (
	"errors"
	"fmt"
	"io/fs"
	"os"

	"github.com/devitex-soft/argus/engine/internal/rules"
)

/* ===== каталоги правил =====
   Поставляемые правила (RULES_DIR) в проде — копия своей версии внутри образа
   (/usr/share/argus/shipped/rules, та же, что у реестра internal/registry):
   версия правил всегда совпадает с версией движка, и обновление кода на хосте
   не меняет их под ещё работающим старым движком (rc34, дубль INC-5312).
   Пользовательские правила — отдельный каталог хоста (RULES_USER_DIR,
   необязателен). Поставляемое правило главнее: пользовательское с тем же id
   отвергается (shipped_id_taken), а не подменяет штатный детект; повтор id внутри
   пользовательских — duplicate_id; сбой разбора пользовательского каталога
   отвергает его целиком, но движок работает на поставляемых. Отказы обоих
   каталогов идут одним путём (rules_events.go): журнал, метрика
   argus_engine_rules_rejected и событие argus.system / rules.rejected, object —
   файл с префиксом каталога (shipped/ или user/); его ловит правило ops. */

// ruleSet — поставляемый и пользовательский каталоги правил.
type ruleSet struct {
	shipped string
	user    string // "" — без пользовательских правил
}

// userPrefix — префикс Rule.File пользовательского правила: в списке правил и
// в событии отказа видно, откуда оно. shippedPrefix — префикс поставляемого
// файла в событии отказа (Rule.File поставляемого — без префикса, как в rules list).
const (
	userPrefix    = "user/"
	shippedPrefix = "shipped/"
)

// Причины отказа (attrs.reason события rules.rejected), кроме тех, что даёт
// пакет rules (schema_unknown_field, invalid_value).
const (
	rejectShippedIDTaken = "shipped_id_taken"
	rejectDuplicateID    = "duplicate_id"
	rejectParseError     = "parse_error"
)

// ruleKey — файл правила с префиксом каталога: ключ прежней версии при
// перечитывании и object события отказа. Происхождение — по каталогу загрузки
// (Rule.User), не по пути: поставляемый user/x.yml — shipped/user/x.yml.
func ruleKey(r *rules.Rule) string {
	if r.User {
		return r.File
	}
	return shippedPrefix + r.File
}

// rejectKey — то же для отвергнутого файла.
func rejectKey(re rules.RuleError) string {
	if re.User {
		return re.File
	}
	return shippedPrefix + re.File
}

// signature — отпечаток обоих каталогов: перечитывание при изменении любого.
func (s ruleSet) signature() string {
	sig := signature(s.shipped)
	if s.user != "" {
		sig += "||" + signature(s.user)
	}
	return sig
}

// loadEach — правила обоих каталогов по файлам, без проверки повторов id (её
// делает resolveRuleSet, зная прежний набор). Отвергнутые файлы поставляемого
// каталога — в rejected по одному; ошибка — только если он не прочитан. Любой
// сбой пользовательского каталога (нечитаемый каталог или файл, FIFO, сверх
// предела размера, ошибка разбора) отвергает его целиком: одна запись user/.
func (s ruleSet) loadEach() (shipped, user []*rules.Rule, rejected []rules.RuleError, err error) {
	shipped, rejected, err = rules.LoadEach(s.shipped)
	if err != nil {
		return nil, nil, nil, err
	}
	if s.user == "" {
		return shipped, nil, rejected, nil
	}
	if _, err := os.Stat(s.user); errors.Is(err, fs.ErrNotExist) {
		return shipped, nil, rejected, nil
	}
	us, bad, err := rules.LoadEach(s.user)
	if err == nil && len(bad) > 0 {
		errs := make([]error, len(bad))
		for i := range bad {
			errs[i] = bad[i]
		}
		err = errors.Join(errs...)
	}
	if err != nil {
		return shipped, nil, append(rejected, rules.RuleError{File: userPrefix, Reason: rejectParseError, Err: err, User: true}), nil
	}
	for _, r := range us {
		r.File, r.User = userPrefix+r.File, true
	}
	return shipped, us, rejected, nil
}

// resolveRuleSet — по одному правилу на id. Внутри каждого каталога — DedupeIDs
// (остаётся файл, активный с этим id; без него — первый по пути); затем
// пользовательское с id поставляемого отвергается: поставляемое главнее, даже
// если пользовательское было активно раньше. activeShipped / activeUser: id →
// Rule.File прежнего набора по каталогам (nil — старт).
func resolveRuleSet(shipped, user []*rules.Rule, activeShipped, activeUser map[string]string) (keptShipped, keptUser []*rules.Rule, rejected []rules.RuleError) {
	keptShipped, rejected = rules.DedupeIDs(shipped, activeShipped)
	taken := make(map[string]string, len(keptShipped))
	for _, r := range keptShipped {
		taken[r.ID] = r.File
	}
	free := make([]*rules.Rule, 0, len(user))
	for _, r := range user {
		if f, ok := taken[r.ID]; ok {
			rejected = append(rejected, rules.RuleError{File: r.File, ID: r.ID, Reason: rejectShippedIDTaken, User: true,
				Err: fmt.Errorf("id %s занят поставляемым правилом %s — пользовательское не применено", r.ID, shippedPrefix+f)})
			continue
		}
		free = append(free, r)
	}
	keptUser, dup := rules.DedupeIDs(free, activeUser)
	for i := range dup {
		dup[i].User = true
	}
	return keptShipped, keptUser, append(rejected, dup...)
}

// uniqueRejections — по одной записи на файл (первая причина): сохранённая
// прежняя версия, отвергнутая повторно, не удваивает отказ в метрике и событиях.
func uniqueRejections(rejected []rules.RuleError) []rules.RuleError {
	seen := make(map[string]bool, len(rejected))
	out := rejected[:0]
	for _, re := range rejected {
		if k := rejectKey(re); !seen[k] {
			seen[k] = true
			out = append(out, re)
		}
	}
	return out
}

// load — набор правил для CLI (rules list, rules test без --dir): поставляемые
// строго — любой отказ в них ошибка (как rules.Load), пользовательские — как у
// движка: битый каталог отвергнут целиком, повторы и занятые id — в rejected.
func (s ruleSet) load() ([]*rules.Rule, []rules.RuleError, error) {
	shipped, user, rejected, err := s.loadEach()
	if err != nil {
		return nil, nil, err
	}
	shipped, user, dup := resolveRuleSet(shipped, user, nil, nil)
	rejected = append(rejected, dup...)
	var userRejected []rules.RuleError
	var errs []error
	for _, re := range rejected {
		if re.User {
			userRejected = append(userRejected, re)
		} else {
			errs = append(errs, re)
		}
	}
	if len(errs) > 0 {
		return nil, nil, errors.Join(errs...)
	}
	return append(shipped, user...), userRejected, nil
}
