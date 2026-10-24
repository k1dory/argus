// Package filter — точные структурированные фильтры поиска ARGUS вместо
// свободной строки запроса. Значения из событий (субъект, узел, IOC) пишет
// атакующий: подставленные в строку как есть, они становятся операторами
// («svc-backup -action:secret_read» → actor=svc-backup И НЕ action=secret_read).
// Здесь каждое значение валидируется и уходит литералом в кавычках: консоль
// не трактует внутри кавычек ни операторы, ни маску «*».
package filter

import (
	"errors"
	"fmt"
	"net/netip"
	"regexp"
	"strconv"
	"strings"
	"unicode"
	"unicode/utf8"
)

// Filters — условия по И. Пустое поле — без условия.
type Filters struct {
	Actor  string // субъект (events)
	Node   string // узел: node (events) / agent (alerts)
	SrcIP  string // src (events) / srcip (alerts)
	DstIP  string // dst (events)
	Action string // действие (events)
	Source string // источник (events)
	Domain string // IOC-домен: литеральная подстрока по всей записи
	Hash   string // IOC-хеш md5/sha1/sha256: литеральная подстрока по всей записи
	RuleID int    // правило Wazuh (alerts)
}

// Empty — ни одного условия.
func (f Filters) Empty() bool { return f == Filters{} }

const maxValueLen = 256

var (
	hashRe   = regexp.MustCompile(`^(?:[0-9A-Fa-f]{32}|[0-9A-Fa-f]{40}|[0-9A-Fa-f]{64})$`)
	domainRe = regexp.MustCompile(`^(?i)[a-z0-9_](?:[a-z0-9_-]{0,61}[a-z0-9])?(?:\.[a-z0-9_](?:[a-z0-9_-]{0,61}[a-z0-9])?)+\.?$`)
)

// Quote — значение литералом в кавычках синтаксиса поиска ARGUS
// (web/src/lib/shared/search-query.ts: внутри кавычек \", \\ и \* — экранирование;
// неэкранированная «*» в кавычках консолью отклоняется как старая маска).
func Quote(v string) string {
	return `"` + strings.NewReplacer(`\`, `\\`, `"`, `\"`, `*`, `\*`).Replace(v) + `"`
}

// Value — проверка значения: не пусто, не длиннее maxValueLen, без
// управляющих символов и невалидного UTF-8.
func Value(name, v string) (string, error) {
	v = strings.TrimSpace(v)
	switch {
	case v == "":
		return "", fmt.Errorf("%s: пустое значение", name)
	case !utf8.ValidString(v):
		return "", fmt.Errorf("%s: невалидный UTF-8", name)
	case utf8.RuneCountInString(v) > maxValueLen:
		return "", fmt.Errorf("%s: длиннее %d символов", name, maxValueLen)
	case strings.IndexFunc(v, unicode.IsControl) >= 0:
		return "", fmt.Errorf("%s: управляющие символы в значении", name)
	}
	return v, nil
}

// IP — адрес IPv4/IPv6 в канонической форме.
func IP(name, v string) (string, error) {
	a, err := netip.ParseAddr(strings.TrimSpace(v))
	if err != nil {
		return "", fmt.Errorf("%s: не IP-адрес: %q", name, v)
	}
	return a.String(), nil
}

// Hash — md5/sha1/sha256 в нижнем регистре.
func Hash(v string) (string, error) {
	v = strings.TrimSpace(v)
	if !hashRe.MatchString(v) {
		return "", errors.New("hash: ожидается md5, sha1 или sha256 в hex")
	}
	return strings.ToLower(v), nil
}

// Domain — имя хоста без схемы, пути и порта, в нижнем регистре.
func Domain(v string) (string, error) {
	v = strings.TrimSpace(v)
	if len(v) > 253 || !domainRe.MatchString(v) {
		return "", fmt.Errorf("domain: не доменное имя: %q", v)
	}
	return strings.TrimSuffix(strings.ToLower(v), "."), nil
}

// fields — имя поля строки поиска для индекса; пусто — фильтр не поддержан.
var fields = map[string]map[string]string{
	"events": {"actor": "actor", "node": "node", "src_ip": "src", "dst_ip": "dst", "action": "action", "source": "source"},
	"alerts": {"node": "agent", "src_ip": "srcip"},
}

// minDomainLen — короче полного доменного имени не ищем: в строгом режиме
// фильтр не должен служить посимвольным оракулом.
const minDomainLen = 4

var tldRe = regexp.MustCompile(`^[a-z]{2,63}$|^xn--[a-z0-9-]{2,59}$`)

// StrictDomain — полное доменное имя: не меньше двух меток, TLD из букв
// (или punycode), не короче minDomainLen.
func StrictDomain(v string) (string, error) {
	d, err := Domain(v)
	if err != nil {
		return "", err
	}
	labels := strings.Split(d, ".")
	if len(d) < minDomainLen || len(labels) < 2 || !tldRe.MatchString(labels[len(labels)-1]) {
		return "", fmt.Errorf("domain: нужно полное доменное имя с буквенным TLD: %q", v)
	}
	return d, nil
}

// QueryStrict — фильтры для профиля triage. Ищется только равенство по
// отдельным полям, не подстрока по всей записи (raw): иначе total и наличие
// строк стали бы оракулом по нередактированным данным. domain — равенство
// attr.domain (поле нормализатора NGFW/DNS), hash отклоняется: поля хеша в
// схеме событий нет, а подстрока по raw в triage закрыта.
func QueryStrict(index string, f Filters) (string, error) {
	if f.Hash != "" {
		return "", errors.New("hash: в профиле triage не поддержан — в схеме событий нет поля хеша, а поиск по сырой записи закрыт; ищите хеш в консоли")
	}
	var dom string
	if f.Domain != "" {
		if index != "events" {
			return "", errors.New("domain: в профиле triage только для индекса events (attr.domain)")
		}
		d, err := StrictDomain(f.Domain)
		if err != nil {
			return "", err
		}
		dom = "attr.domain:" + Quote(d)
		f.Domain = ""
	}
	q, err := Query(index, f)
	if err != nil {
		return "", err
	}
	return strings.TrimSpace(q + " " + dom), nil
}

// Query — строка поиска ARGUS из фильтров для индекса alerts или events.
// domain и hash — литеральная подстрока по всей записи (профиль full).
func Query(index string, f Filters) (string, error) {
	fm, ok := fields[index]
	if !ok {
		return "", fmt.Errorf("неизвестный индекс %q", index)
	}
	var terms []string
	add := func(name, value string, check func(string, string) (string, error)) error {
		if value == "" {
			return nil
		}
		field := fm[name]
		if field == "" {
			return fmt.Errorf("фильтр %s не поддержан для индекса %s", name, index)
		}
		v, err := check(name, value)
		if err != nil {
			return err
		}
		terms = append(terms, field+":"+Quote(v))
		return nil
	}
	for _, x := range []struct {
		name, value string
		check       func(string, string) (string, error)
	}{
		{"actor", f.Actor, Value}, {"node", f.Node, Value}, {"src_ip", f.SrcIP, IP}, {"dst_ip", f.DstIP, IP},
		{"action", f.Action, Value}, {"source", f.Source, Value},
	} {
		if err := add(x.name, x.value, x.check); err != nil {
			return "", err
		}
	}
	if f.Domain != "" {
		v, err := Domain(f.Domain)
		if err != nil {
			return "", err
		}
		terms = append(terms, Quote(v))
	}
	if f.Hash != "" {
		v, err := Hash(f.Hash)
		if err != nil {
			return "", err
		}
		terms = append(terms, Quote(v))
	}
	if f.RuleID != 0 {
		if index != "alerts" {
			return "", fmt.Errorf("фильтр rule_id только для индекса alerts")
		}
		if f.RuleID < 0 {
			return "", errors.New("rule_id: отрицательный")
		}
		terms = append(terms, "rule:"+strconv.Itoa(f.RuleID))
	}
	return strings.Join(terms, " "), nil
}

// Damage — почему исходное значение из события нельзя брать в точный фильтр
// разбора: пусто — значение чистое, иначе причина в терминах damaged_values
// схемы вердикта (operator, wildcard, whitespace, quote, leading_dash,
// too_long, other). Шлюз разбора проверяет значение до псевдонимизации:
// под subj-… модель повреждение не увидит. Литерал в кавычках (Quote)
// безопасен и для таких значений, но значение с оператором — признак
// подложенного атакующим ввода, искать по нему агенту нечего.
func Damage(v string) string {
	switch {
	case v == "":
		return ""
	case !utf8.ValidString(v) || strings.IndexFunc(v, func(r rune) bool { return unicode.IsControl(r) || unicode.Is(unicode.Cf, r) }) >= 0:
		return "other" // в том числе невидимые символы и смена направления текста
	case utf8.RuneCountInString(v) > maxValueLen:
		return "too_long"
	case strings.ContainsAny(v, "\"'`«»"):
		return "quote"
	case strings.Contains(v, "*"):
		return "wildcard"
	case strings.IndexFunc(v, unicode.IsSpace) >= 0:
		return "whitespace"
	case strings.HasPrefix(v, "-"):
		return "leading_dash"
	case strings.ContainsAny(v, `<>=!()|&;\{}[]$`):
		return "operator"
	}
	return ""
}

// DamageIP — Damage для поля-адреса: не IP — bad_ip.
func DamageIP(v string) string {
	if v == "" {
		return ""
	}
	if _, err := netip.ParseAddr(v); err != nil {
		return "bad_ip"
	}
	return ""
}
