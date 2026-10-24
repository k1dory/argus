// Package identity — паспорт субъекта: персоны и их алиасы во времени.
// Паспорт — представление над журналом событий, а не отдельная база: пакет
// лишь ведёт таблицы argus.identities и argus.identity_aliases, по которым
// консоль затем собирает срез журнала по человеку. Алиасы приходят тремя
// путями — из identities.yml (source = yaml), из API консоли (source = api)
// и событиями identity.alias любого экспортера (source = event:<source>).
//
// Алиас действует на событие, если valid_from <= ts AND (valid_to IS NULL
// OR ts < valid_to). Значения нормализованы на записи (Normalize), чтобы
// «I.Petrov@Example.org» и «i.petrov@example.org» были одним алиасом.
package identity

import (
	"context"
	"fmt"
	"net/netip"
	"regexp"
	"strings"
	"time"
)

// Виды алиасов. Что именно стоит за uid/sid/peer, решает источник
// (идентификатор в IdP, SID в домене, пир VPN-контроллера).
const (
	KindEmail = "email"
	KindLogin = "login"
	KindUID   = "uid"
	KindIP    = "ip"
	KindHost  = "host"
	KindSID   = "sid"
	KindPeer  = "peer"
)

// Kinds — допустимые виды алиасов в порядке объявления.
var Kinds = []string{KindEmail, KindLogin, KindUID, KindIP, KindHost, KindSID, KindPeer}

// Виды персон.
const (
	PersonKind  = "person"
	ServiceKind = "service"
)

// Epoch — valid_from алиаса без явного начала: действует всегда.
var Epoch = time.Unix(0, 0).UTC()

// personIDRe — стабильный идентификатор персоны: slug (i.petrov) или uuid.
var personIDRe = regexp.MustCompile(`^[a-z0-9][a-z0-9._-]{0,63}$`)

// ValidPersonID — person_id допустим: строчные латинские буквы, цифры,
// точка, дефис, подчёркивание; от 1 до 64 символов; начинается с буквы или цифры.
func ValidPersonID(id string) bool { return personIDRe.MatchString(id) }

// Person — человек или сервисная учётка.
type Person struct {
	ID      string // person_id
	Display string // отображаемое имя; по умолчанию — person_id
	Kind    string // person | service
	Team    string
	Note    string
}

// Alias — одно значение, принадлежавшее персоне в интервале времени.
type Alias struct {
	PersonID   string
	Kind       string     // один из Kinds
	Value      string     // нормализовано (Normalize)
	ValidFrom  time.Time  // UTC
	ValidTo    *time.Time // nil — действует
	Source     string     // yaml | api | event:<source события>
	Confidence float32    // 0 < c <= 1; 1 — точно
	Note       string
}

// Key — ключ строки в identity_aliases (ORDER BY таблицы): так сравниваются
// версии одного алиаса при синхронизации файла и отзыве событием.
func (a Alias) Key() string {
	return a.Kind + "\x00" + a.Value + "\x00" + a.ValidFrom.UTC().Format(time.RFC3339Nano) + "\x00" + a.PersonID
}

// ActiveAt — действует ли алиас в момент ts.
func (a Alias) ActiveAt(ts time.Time) bool {
	if ts.Before(a.ValidFrom) {
		return false
	}
	return a.ValidTo == nil || ts.Before(*a.ValidTo)
}

// Store — что пакету нужно от хранилища; реализует store.ClickHouse.
// Все чтения — «последняя версия» строки (argMax по updated_at, deleted = 0).
type Store interface {
	UpsertIdentities(ctx context.Context, persons []Person) error
	UpsertAliases(ctx context.Context, aliases []Alias) error
	// DeleteAliases — пометить строки deleted = 1 (та же строка-ключ).
	DeleteAliases(ctx context.Context, aliases []Alias) error
	// OpenAliases — действующие (valid_to IS NULL) алиасы с данным видом,
	// значением и персоной; пустая персона — любой.
	OpenAliases(ctx context.Context, kind, value, person string) ([]Alias, error)
	// AliasesBySource — все неудалённые алиасы источника (yaml, api, event:…).
	AliasesBySource(ctx context.Context, source string) ([]Alias, error)
	// KnownPersons — какие из идентификаторов уже заведены (и не удалены).
	KnownPersons(ctx context.Context, ids []string) (map[string]bool, error)
}

// ValidKind — вид алиаса известен.
func ValidKind(kind string) bool {
	for _, k := range Kinds {
		if k == kind {
			return true
		}
	}
	return false
}

// Normalize — нормальная форма значения алиаса: email/login/host — нижний
// регистр без пробелов по краям; ip — каноническая запись адреса (IPv6 —
// сжатая, без зоны); uid/sid/peer — как есть, без пробелов по краям.
// Ошибка — вид неизвестен, значение пустое или адрес не разбирается.
func Normalize(kind, value string) (string, error) {
	if !ValidKind(kind) {
		return "", fmt.Errorf("неизвестный вид алиаса %q (ожидается %s)", kind, strings.Join(Kinds, " | "))
	}
	v := strings.TrimSpace(value)
	if v == "" {
		return "", fmt.Errorf("пустое значение алиаса вида %s", kind)
	}
	if len(v) > 512 {
		return "", fmt.Errorf("значение алиаса вида %s длиннее 512 байт", kind)
	}
	switch kind {
	case KindEmail, KindLogin, KindHost:
		v = strings.ToLower(v)
		if strings.ContainsAny(v, " \t\r\n") {
			return "", fmt.Errorf("значение алиаса вида %s содержит пробелы: %q", kind, v)
		}
		if kind == KindEmail && !strings.Contains(v[1:], "@") {
			return "", fmt.Errorf("email без @: %q", v)
		}
	case KindIP:
		addr, err := netip.ParseAddr(v)
		if err != nil {
			return "", fmt.Errorf("ip %q не разбирается: %w", v, err)
		}
		v = addr.WithZone("").Unmap().String()
	}
	return v, nil
}

// timeLayouts — допустимые записи времени в attrs событий и в identities.yml.
var timeLayouts = []string{
	"2006-01-02 15:04:05.000", "2006-01-02 15:04:05", time.RFC3339Nano, time.RFC3339, "2006-01-02",
}

// ParseTime — время из строки: дата YYYY-MM-DD (полночь UTC), формат ts
// события или RFC3339. Результат в UTC.
func ParseTime(s string) (time.Time, error) {
	s = strings.TrimSpace(s)
	for _, layout := range timeLayouts {
		if t, err := time.Parse(layout, s); err == nil {
			return t.UTC(), nil
		}
	}
	return time.Time{}, fmt.Errorf("время %q: ожидается YYYY-MM-DD, YYYY-MM-DD HH:MM:SS или RFC3339", s)
}
