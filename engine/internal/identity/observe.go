package identity

import (
	"context"
	"fmt"
	"io"
	"log/slog"
	"sort"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/devitex-soft/argus/engine/internal/model"
)

// Источники алиасов (колонка source).
const (
	SourceYAML        = "yaml"
	SourceAPI         = "api"
	SourceEventPrefix = "event:"
)

// Действия событий, которые ведут алиасы. Само событие остаётся в журнале —
// это и есть запись «кто когда получил адрес».
const (
	ActionAlias  = "identity.alias"
	ActionRevoke = "identity.alias.revoke"
)

// Контракт события identity.alias (POST /ingest/events любого экспортера):
//
//	{"ts":"2026-10-24 10:00:00.000","source":"idp.example","source_class":"identity",
//	 "action":"identity.alias","actor_name":"i.petrov","outcome":"success",
//	 "attrs":{"alias_kind":"ip","alias_value":"10.77.0.11","valid_from":"2026-10-24 10:00:00","confidence":"1"}}
//
// actor_name — person_id; attrs.alias_kind и attrs.alias_value обязательны;
// valid_from по умолчанию ts события, valid_to необязателен, confidence по
// умолчанию 1, note необязателен. identity.alias.revoke закрывает действующий
// алиас той же персоны (valid_to = attrs.valid_to или ts). Персона без
// записи заводится с display = person_id.

// Stats — итог одного прохода Observe.
type Stats struct {
	OK      int // алиасов записано (включая отзывы)
	Invalid int // событий отклонено: нет attrs, плохое значение, отзыв несуществующего
	Errors  int // записей не удалось выполнить (ошибка хранилища)
	// Retry — события, которые не удалось применить из-за хранилища, в порядке
	// обработки: вызывающий отдаёт их в следующий Observe, чтобы сбой записи
	// не терял алиасы. Очередь живёт в памяти движка (теряется при рестарте)
	// и ограничена сверху; это терпимо — снимки алиасов экспортеры повторяют.
	Retry []*model.Event
}

// Observer читает события identity.alias / identity.alias.revoke из общего
// потока движка и ведёт identity_aliases. Безопасен для вызова из одного
// цикла; счётчики — для /metrics.
type Observer struct {
	store Store
	now   func() time.Time

	ok, invalid, errs atomic.Int64
	syncOK, syncErr   atomic.Int64

	knownMu sync.Mutex
	known   map[string]bool // person_id, про которые известно, что они заведены
}

// New — наблюдатель поверх хранилища; nil store — все вызовы no-op.
func New(store Store) *Observer {
	return &Observer{store: store, now: time.Now, known: map[string]bool{}}
}

// maxKnown — потолок кэша заведённых персон; сверх — кэш сбрасывается.
const maxKnown = 10000

// Observe — отбирает события алиасов из среза и применяет их в порядке
// времени события: выдача 08:00 → отзыв 09:00 → выдача 10:00 должна оставить
// второй интервал открытым, поэтому отзыв видит только то, что записано до
// него. Невалидные события считаются и пишутся в лог, но не останавливают
// проход; не записанные из-за хранилища возвращаются в Stats.Retry.
func (o *Observer) Observe(ctx context.Context, events []*model.Event) Stats {
	var st Stats
	if o == nil || o.store == nil {
		return st
	}
	type op struct {
		ev    *model.Event
		alias Alias
		ts    time.Time
	}
	var ops []op
	for _, ev := range events {
		if ev == nil || (ev.Action != ActionAlias && ev.Action != ActionRevoke) {
			continue
		}
		a, err := aliasFromEvent(ev)
		if err != nil {
			st.Invalid++
			o.invalid.Add(1)
			slog.Warn("identity: событие "+ev.Action+" отклонено", "source", ev.Source, "ts", ev.TS, "actor", ev.ActorName, "err", err)
			continue
		}
		ops = append(ops, op{ev: ev, alias: a, ts: ev.Time()})
	}
	if len(ops) == 0 {
		return st
	}
	sort.SliceStable(ops, func(i, j int) bool { return ops[i].ts.Before(ops[j].ts) })

	// Выдачи копятся и пишутся одним INSERT; перед отзывом и в конце — сброс.
	// Ошибка записи останавливает батч: остаток (невыполненные выдачи, этот
	// отзыв и всё после него) уходит в Retry в порядке обработки — иначе отзыв
	// не нашёл бы ещё не записанную выдачу и был бы отброшен, а повтор выдачи
	// оставил бы алиас открытым.
	var pending []op
	flush := func() error {
		if len(pending) == 0 {
			return nil
		}
		persons := map[string]bool{}
		aliases := make([]Alias, 0, len(pending))
		for _, p := range pending {
			persons[p.alias.PersonID] = true
			aliases = append(aliases, p.alias)
		}
		err := o.ensurePersons(ctx, persons)
		if err == nil {
			err = o.store.UpsertAliases(ctx, aliases)
		}
		if err != nil {
			st.Errors += len(pending)
			o.errs.Add(int64(len(pending)))
			return err
		}
		st.OK += len(pending)
		o.ok.Add(int64(len(pending)))
		pending = pending[:0]
		return nil
	}
	abort := func(from int, err error) Stats {
		for _, p := range pending {
			st.Retry = append(st.Retry, p.ev)
		}
		for _, p := range ops[from:] {
			st.Retry = append(st.Retry, p.ev)
		}
		slog.Warn("identity: хранилище недоступно, остаток батча повторю на следующем цикле", "retry", len(st.Retry), "err", err)
		return st
	}
	for i, p := range ops {
		if p.ev.Action == ActionAlias {
			pending = append(pending, p)
			continue
		}
		if err := flush(); err != nil {
			return abort(i, err)
		}
		n, err := o.revoke(ctx, p.ev)
		switch {
		case err != nil:
			st.Errors++
			o.errs.Add(1)
			return abort(i, err)
		case n == 0:
			st.Invalid++
			o.invalid.Add(1)
			slog.Warn("identity: отзыв без действующего алиаса — пропущен", "source", p.ev.Source, "ts", p.ev.TS, "actor", p.ev.ActorName,
				"kind", p.ev.Attrs["alias_kind"], "value", p.ev.Attrs["alias_value"])
		default:
			st.OK += n
			o.ok.Add(int64(n))
		}
	}
	if err := flush(); err != nil {
		return abort(len(ops), err)
	}
	return st
}

// ensurePersons заводит персоны, которых ещё нет: display = person_id.
func (o *Observer) ensurePersons(ctx context.Context, ids map[string]bool) error {
	var ask []string
	o.knownMu.Lock()
	for id := range ids {
		if !o.known[id] {
			ask = append(ask, id)
		}
	}
	o.knownMu.Unlock()
	if len(ask) == 0 {
		return nil
	}
	sort.Strings(ask)
	have, err := o.store.KnownPersons(ctx, ask)
	if err != nil {
		return err
	}
	var create []Person
	for _, id := range ask {
		if !have[id] {
			create = append(create, Person{ID: id, Display: id, Kind: PersonKind})
		}
	}
	if len(create) > 0 {
		if err := o.store.UpsertIdentities(ctx, create); err != nil {
			return err
		}
		slog.Info("identity: заведены персоны из событий", "n", len(create))
	}
	o.knownMu.Lock()
	if len(o.known)+len(ask) > maxKnown {
		o.known = map[string]bool{}
	}
	for _, id := range ask {
		o.known[id] = true
	}
	o.knownMu.Unlock()
	return nil
}

// revoke закрывает действующие алиасы (kind, value, person), открытые до
// момента отзыва: та же строка-ключ переписывается с valid_to. Интервалы,
// начатые позже отзыва (выдача после отзыва в том же батче), не трогаются.
// Возвращает число закрытых.
func (o *Observer) revoke(ctx context.Context, ev *model.Event) (int, error) {
	kind := strings.TrimSpace(ev.Attrs["alias_kind"])
	value, err := Normalize(kind, ev.Attrs["alias_value"])
	if err != nil {
		return 0, err
	}
	ts := ev.Time()
	if s := strings.TrimSpace(ev.Attrs["valid_to"]); s != "" {
		if ts, err = ParseTime(s); err != nil {
			return 0, err
		}
	}
	open, err := o.store.OpenAliases(ctx, kind, value, ev.ActorName)
	if err != nil {
		return 0, err
	}
	var closed []Alias
	for _, a := range open {
		if !a.ValidFrom.Before(ts) {
			continue
		}
		to := ts
		a.ValidTo = &to
		closed = append(closed, a)
	}
	if len(closed) == 0 {
		return 0, nil
	}
	if err := o.store.UpsertAliases(ctx, closed); err != nil {
		return 0, err
	}
	return len(closed), nil
}

// aliasFromEvent — алиас из события identity.alias(.revoke) после проверки.
// Для отзыва важны только kind/value/person — остальное проверяется так же,
// чтобы контракт был единым.
func aliasFromEvent(ev *model.Event) (Alias, error) {
	person := strings.TrimSpace(ev.ActorName)
	if !ValidPersonID(person) {
		return Alias{}, fmt.Errorf("actor_name %q не годится как person_id", ev.ActorName)
	}
	if ev.Attrs == nil {
		return Alias{}, fmt.Errorf("нет attrs.alias_kind и attrs.alias_value")
	}
	kind := strings.TrimSpace(ev.Attrs["alias_kind"])
	value, err := Normalize(kind, ev.Attrs["alias_value"])
	if err != nil {
		return Alias{}, err
	}
	ts := ev.Time()
	if ts.IsZero() {
		return Alias{}, fmt.Errorf("ts %q не разбирается", ev.TS)
	}
	from := ts
	if s := strings.TrimSpace(ev.Attrs["valid_from"]); s != "" {
		if from, err = ParseTime(s); err != nil {
			return Alias{}, fmt.Errorf("attrs.valid_from: %w", err)
		}
	}
	var to *time.Time
	if s := strings.TrimSpace(ev.Attrs["valid_to"]); s != "" {
		t, err := ParseTime(s)
		if err != nil {
			return Alias{}, fmt.Errorf("attrs.valid_to: %w", err)
		}
		if ev.Action == ActionAlias && !t.After(from) {
			return Alias{}, fmt.Errorf("attrs.valid_to %s не позже valid_from %s", t.Format(time.RFC3339), from.Format(time.RFC3339))
		}
		to = &t
	}
	conf := float32(1)
	if s := strings.TrimSpace(ev.Attrs["confidence"]); s != "" {
		f, err := strconv.ParseFloat(s, 32)
		if err != nil || f <= 0 || f > 1 {
			return Alias{}, fmt.Errorf("attrs.confidence %q: ожидается число в (0, 1]", s)
		}
		conf = float32(f)
	}
	source := SourceEventPrefix + strings.TrimSpace(ev.Source)
	if len(source) > 128 {
		source = source[:128]
	}
	return Alias{PersonID: person, Kind: kind, Value: value, ValidFrom: from, ValidTo: to, Source: source,
		Confidence: conf, Note: strings.TrimSpace(ev.Attrs["note"])}, nil
}

// WriteMetrics — счётчики в формате Prometheus.
func (o *Observer) WriteMetrics(w io.Writer) {
	if o == nil {
		return
	}
	for _, kv := range []struct {
		result string
		v      int64
	}{{"ok", o.ok.Load()}, {"invalid", o.invalid.Load()}, {"error", o.errs.Load()}} {
		fmt.Fprintf(w, "argus_engine_identity_alias_total{result=%q} %d\n", kv.result, kv.v)
	}
	fmt.Fprintf(w, "argus_engine_identity_file_syncs_total{result=\"ok\"} %d\n", o.syncOK.Load())
	fmt.Fprintf(w, "argus_engine_identity_file_syncs_total{result=\"error\"} %d\n", o.syncErr.Load())
}
