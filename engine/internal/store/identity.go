package store

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"strings"
	"sync"
	"time"

	"github.com/devitex-soft/argus/engine/internal/identity"
)

/* ===== паспорт субъекта: identities / identity_aliases =====
   Обе таблицы — ReplacingMergeTree(updated_at): запись — всегда полная
   строка с новым updated_at, удаление — та же строка с deleted = 1. Чтение
   «последней версии» — argMax(..., updated_at) по ключу ORDER BY с
   deleted = 0. valid_to читается через ifNull(toString(...), ''): argMax
   пропускает NULL в аргументе, и алиас, снова открытый после закрытия, иначе
   остался бы закрытым. */

const ts3 = "2006-01-02 15:04:05.000"

// stamps — монотонные updated_at: ReplacingMergeTree и argMax различают версии
// только по этому полю, и две строки одного ключа с равным временем — это
// «какая угодно из них». Одна метка на батч (дубли ключа внутри батча
// свёрнуты), следующий батч — не раньше предыдущего + 1 мс; при первом
// обращении нижняя граница берётся из max(updated_at) обеих таблиц, иначе
// после рестарта с отставшими часами новая версия проиграла бы старой.
// Шаг 1 мс от max(now, last) — в будущее не уезжаем дальше, чем нужно.
type stamps struct {
	mu     sync.Mutex
	last   time.Time
	seeded bool
}

// stamp — метка updated_at для очередного батча.
func (c *ClickHouse) stamp(ctx context.Context) string {
	c.idStamps.mu.Lock()
	defer c.idStamps.mu.Unlock()
	if !c.idStamps.seeded {
		if max, err := c.maxUpdatedAt(ctx); err != nil {
			slog.Warn("identity: max(updated_at) не прочитан, метки от текущего времени; повторю при следующей записи", "err", err)
		} else {
			if max.After(c.idStamps.last) {
				c.idStamps.last = max
			}
			c.idStamps.seeded = true
		}
	}
	t := time.Now().UTC().Truncate(time.Millisecond)
	if !t.After(c.idStamps.last) {
		t = c.idStamps.last.Add(time.Millisecond)
	}
	c.idStamps.last = t
	return t.Format(ts3)
}

// maxUpdatedAt — последняя метка версии в identities и identity_aliases
// (1970-01-01 на пустых таблицах).
func (c *ClickHouse) maxUpdatedAt(ctx context.Context) (time.Time, error) {
	out, err := c.do(ctx, `SELECT toString(max(updated_at)) AS m FROM
	(SELECT updated_at FROM identities UNION ALL SELECT updated_at FROM identity_aliases) FORMAT JSONEachRow`, nil, nil)
	if err != nil {
		return time.Time{}, err
	}
	var r struct {
		M string `json:"m"`
	}
	line := bytes.TrimSpace(out)
	if len(line) == 0 {
		return time.Time{}, nil
	}
	if err := json.Unmarshal(bytes.Split(line, []byte("\n"))[0], &r); err != nil {
		return time.Time{}, fmt.Errorf("max(updated_at): %w", err)
	}
	return identity.ParseTime(r.M)
}

// dedupeAliases — внутри батча по ключу строки остаётся последнее значение
// (порядок первого появления сохраняется): две версии с разным updated_at в
// одном INSERT не нужны, а одинаковым — неоднозначны.
func dedupeAliases(aliases []identity.Alias) []identity.Alias {
	idx := map[string]int{}
	out := make([]identity.Alias, 0, len(aliases))
	for _, a := range aliases {
		if i, ok := idx[a.Key()]; ok {
			out[i] = a
			continue
		}
		idx[a.Key()] = len(out)
		out = append(out, a)
	}
	return out
}

type identityRow struct {
	PersonID  string `json:"person_id"`
	Display   string `json:"display"`
	Kind      string `json:"kind"`
	Team      string `json:"team"`
	Note      string `json:"note"`
	UpdatedAt string `json:"updated_at"`
	Deleted   uint8  `json:"deleted"`
}

type aliasRow struct {
	PersonID   string  `json:"person_id"`
	AliasKind  string  `json:"alias_kind"`
	AliasValue string  `json:"alias_value"`
	ValidFrom  string  `json:"valid_from"`
	ValidTo    *string `json:"valid_to"`
	Source     string  `json:"source"`
	Confidence float32 `json:"confidence"`
	Note       string  `json:"note"`
	UpdatedAt  string  `json:"updated_at"`
	Deleted    uint8   `json:"deleted"`
}

func aliasRows(aliases []identity.Alias, deleted uint8, at string) []any {
	aliases = dedupeAliases(aliases)
	rows := make([]any, 0, len(aliases))
	for _, a := range aliases {
		r := aliasRow{PersonID: a.PersonID, AliasKind: a.Kind, AliasValue: a.Value, ValidFrom: a.ValidFrom.UTC().Format(ts3),
			Source: a.Source, Confidence: a.Confidence, Note: a.Note, UpdatedAt: at, Deleted: deleted}
		if a.ValidTo != nil {
			s := a.ValidTo.UTC().Format(ts3)
			r.ValidTo = &s
		}
		rows = append(rows, r)
	}
	return rows
}

// UpsertIdentities — персоны: новая версия строки (deleted = 0).
func (c *ClickHouse) UpsertIdentities(ctx context.Context, persons []identity.Person) error {
	idx := map[string]int{}
	uniq := make([]identity.Person, 0, len(persons))
	for _, p := range persons {
		if i, ok := idx[p.ID]; ok {
			uniq[i] = p
			continue
		}
		idx[p.ID] = len(uniq)
		uniq = append(uniq, p)
	}
	if len(uniq) == 0 {
		return nil
	}
	at := c.stamp(ctx)
	rows := make([]any, 0, len(uniq))
	for _, p := range uniq {
		kind := p.Kind
		if kind == "" {
			kind = identity.PersonKind
		}
		display := p.Display
		if display == "" {
			display = p.ID
		}
		rows = append(rows, identityRow{PersonID: p.ID, Display: display, Kind: kind, Team: p.Team, Note: p.Note, UpdatedAt: at})
	}
	return c.insert(ctx, "identities", rows)
}

// UpsertAliases — алиасы: новая версия строки (deleted = 0).
func (c *ClickHouse) UpsertAliases(ctx context.Context, aliases []identity.Alias) error {
	if len(aliases) == 0 {
		return nil
	}
	return c.insert(ctx, "identity_aliases", aliasRows(aliases, 0, c.stamp(ctx)))
}

// DeleteAliases — те же строки с deleted = 1.
func (c *ClickHouse) DeleteAliases(ctx context.Context, aliases []identity.Alias) error {
	if len(aliases) == 0 {
		return nil
	}
	return c.insert(ctx, "identity_aliases", aliasRows(aliases, 1, c.stamp(ctx)))
}

// aliasSelect — последняя версия алиасов по условию where (параметры — в params).
func (c *ClickHouse) aliasSelect(ctx context.Context, where string, params map[string]string) ([]identity.Alias, error) {
	out, err := c.do(ctx, `SELECT person_id, alias_kind, alias_value, toString(valid_from) AS valid_from,
	       argMax(ifNull(toString(valid_to), ''), updated_at) AS valid_to,
	       argMax(source, updated_at) AS source, argMax(confidence, updated_at) AS confidence,
	       argMax(note, updated_at) AS note, argMax(deleted, updated_at) AS deleted
	FROM identity_aliases WHERE `+where+`
	GROUP BY person_id, alias_kind, alias_value, valid_from
	HAVING deleted = 0
	ORDER BY alias_kind, alias_value, valid_from, person_id
	FORMAT JSONEachRow`, nil, params)
	if err != nil {
		return nil, err
	}
	var res []identity.Alias
	for _, line := range bytes.Split(out, []byte("\n")) {
		if len(bytes.TrimSpace(line)) == 0 {
			continue
		}
		var r struct {
			PersonID   string  `json:"person_id"`
			AliasKind  string  `json:"alias_kind"`
			AliasValue string  `json:"alias_value"`
			ValidFrom  string  `json:"valid_from"`
			ValidTo    string  `json:"valid_to"`
			Source     string  `json:"source"`
			Confidence float32 `json:"confidence"`
			Note       string  `json:"note"`
		}
		if err := json.Unmarshal(line, &r); err != nil {
			return nil, fmt.Errorf("identity_aliases: %w", err)
		}
		from, err := identity.ParseTime(r.ValidFrom)
		if err != nil {
			return nil, fmt.Errorf("identity_aliases valid_from: %w", err)
		}
		a := identity.Alias{PersonID: r.PersonID, Kind: r.AliasKind, Value: r.AliasValue, ValidFrom: from,
			Source: r.Source, Confidence: r.Confidence, Note: r.Note}
		if r.ValidTo != "" {
			to, err := identity.ParseTime(r.ValidTo)
			if err != nil {
				return nil, fmt.Errorf("identity_aliases valid_to: %w", err)
			}
			a.ValidTo = &to
		}
		res = append(res, a)
	}
	return res, nil
}

// OpenAliases — действующие алиасы (valid_to IS NULL) с данным видом и
// значением; person пустой — любой персоны.
func (c *ClickHouse) OpenAliases(ctx context.Context, kind, value, person string) ([]identity.Alias, error) {
	where := "alias_kind = {kind:String} AND alias_value = {value:String}"
	params := map[string]string{"kind": kind, "value": value}
	if person != "" {
		where += " AND person_id = {person:String}"
		params["person"] = person
	}
	all, err := c.aliasSelect(ctx, where, params)
	if err != nil {
		return nil, err
	}
	open := all[:0]
	for _, a := range all {
		if a.ValidTo == nil {
			open = append(open, a)
		}
	}
	return open, nil
}

// AliasesBySource — неудалённые алиасы источника (yaml | api | event:…).
// Источник в ключ ORDER BY не входит, поэтому фильтр — по последней версии.
func (c *ClickHouse) AliasesBySource(ctx context.Context, source string) ([]identity.Alias, error) {
	all, err := c.aliasSelect(ctx, "1", nil)
	if err != nil {
		return nil, err
	}
	res := all[:0]
	for _, a := range all {
		if a.Source == source {
			res = append(res, a)
		}
	}
	return res, nil
}

// AliasesByPerson — неудалённые алиасы персоны данного вида, открытые и
// закрытые (последние версии): состояние для политик алиасов.
func (c *ClickHouse) AliasesByPerson(ctx context.Context, person, kind string) ([]identity.Alias, error) {
	return c.aliasSelect(ctx, "person_id = {person:String} AND alias_kind = {kind:String}",
		map[string]string{"person": person, "kind": kind})
}

// KnownPersons — какие из идентификаторов заведены и не удалены.
func (c *ClickHouse) KnownPersons(ctx context.Context, ids []string) (map[string]bool, error) {
	res := map[string]bool{}
	if len(ids) == 0 {
		return res, nil
	}
	out, err := c.do(ctx, `SELECT person_id FROM identities WHERE person_id IN {ids:Array(String)}
	GROUP BY person_id HAVING argMax(deleted, updated_at) = 0 FORMAT JSONEachRow`, nil,
		map[string]string{"ids": chArray(ids)})
	if err != nil {
		return nil, err
	}
	for _, line := range bytes.Split(out, []byte("\n")) {
		if len(bytes.TrimSpace(line)) == 0 {
			continue
		}
		var r struct {
			PersonID string `json:"person_id"`
		}
		if err := json.Unmarshal(line, &r); err != nil {
			return nil, fmt.Errorf("identities: %w", err)
		}
		if strings.TrimSpace(r.PersonID) != "" {
			res[r.PersonID] = true
		}
	}
	return res, nil
}
