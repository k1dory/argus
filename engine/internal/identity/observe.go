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
	// Policy — нарушений политик алиасов (policy.go): flag и hold записаны и
	// учтены в OK, reject — не записаны и в OK не входят.
	Policy int
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

	// policies — действующие политики алиасов из identities.yml (SetPolicies);
	// nil — без ограничений. policyHits — счётчики нарушений по (rule, action).
	policies   atomic.Pointer[Policies]
	policyMu   sync.Mutex
	policyHits map[[2]string]int64
}

// New — наблюдатель поверх хранилища; nil store — все вызовы no-op.
func New(store Store) *Observer {
	return &Observer{store: store, now: time.Now, known: map[string]bool{}, policyHits: map[[2]string]int64{}}
}

// SetPolicies — заменить действующие политики алиасов (перечитывание
// identities.yml); пустые — снять ограничения.
func (o *Observer) SetPolicies(ps Policies) {
	if o == nil {
		return
	}
	if len(ps) == 0 {
		o.policies.Store(nil)
		return
	}
	cp := make(Policies, len(ps))
	for k, v := range ps {
		cp[k] = v
	}
	o.policies.Store(&cp)
}

// Policies — действующие политики (копия для чтения; nil — нет).
func (o *Observer) Policies() Policies {
	if o == nil {
		return nil
	}
	if p := o.policies.Load(); p != nil {
		return *p
	}
	return nil
}

// applyPolicy — проверка алиаса из события политикой его вида: состояние —
// алиасы персоны того же вида из хранилища плюс ожидающие записи в этом
// батче (без дублей по ключу). Возвращает алиас после решения (note,
// confidence), само решение и ошибку хранилища.
func (o *Observer) applyPolicy(ctx context.Context, a Alias, pending []Alias) (Alias, Decision, error) {
	ps := o.policies.Load()
	if ps == nil {
		return a, Decision{}, nil
	}
	if _, ok := (*ps)[a.Kind]; !ok || !strings.HasPrefix(a.Source, SourceEventPrefix) {
		return a, Decision{}, nil
	}
	stored, err := o.store.AliasesByPerson(ctx, a.PersonID, a.Kind)
	if err != nil {
		return a, Decision{}, fmt.Errorf("алиасы персоны для политики: %w", err)
	}
	seen := map[string]bool{}
	state := make([]Alias, 0, len(stored)+len(pending))
	for _, s := range stored {
		if !seen[s.Key()] {
			seen[s.Key()] = true
			state = append(state, s)
		}
	}
	for _, s := range pending {
		if s.PersonID == a.PersonID && s.Kind == a.Kind && !seen[s.Key()] {
			seen[s.Key()] = true
			state = append(state, s)
		}
	}
	dec := ps.Evaluate(a, state)
	out, _ := dec.Apply(a)
	return out, dec, nil
}

// countPolicy — счётчик нарушений для /metrics.
func (o *Observer) countPolicy(rule, action string) {
	o.policyMu.Lock()
	o.policyHits[[2]string{rule, action}]++
	o.policyMu.Unlock()
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
	// События нарушений политик пишутся в журнал после удачной записи
	// алиасов (и в конце прохода — ради reject без записи). Это телеметрия:
	// сбой их вставки только логируется, при abort не записанные пропадают
	// (нарушения по алиасам из Retry возникнут снова при повторе).
	var violations []*model.Event
	flushViolations := func() {
		if len(violations) == 0 {
			return
		}
		if err := o.store.InsertEvents(ctx, violations); err != nil {
			slog.Warn("identity: события нарушений политик не записаны", "n", len(violations), "err", err)
		}
		violations = violations[:0]
	}
	var pending []op
	flush := func() error {
		if len(pending) == 0 {
			flushViolations()
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
		flushViolations()
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
			// Политика вида (если задана): состояние — хранилище плюс
			// ожидающие записи того же человека и вида.
			state := make([]Alias, 0, len(pending))
			for _, q := range pending {
				state = append(state, q.alias)
			}
			a, dec, err := o.applyPolicy(ctx, p.alias, state)
			if err != nil {
				st.Errors++
				o.errs.Add(1)
				return abort(i, err)
			}
			if dec.Rule != "" {
				st.Policy++
				o.countPolicy(dec.Rule, dec.Action)
				violations = append(violations, dec.ViolationEvent(p.ev, p.alias))
				slog.Warn("identity: нарушение политики алиасов", "person", p.alias.PersonID, "kind", p.alias.Kind, "value", p.alias.Value,
					"rule", dec.Rule, "limit", dec.Limit, "window", dec.Window, "count", dec.Count, "source", p.ev.Source, "action", dec.Action)
				if dec.Action == ActionReject {
					continue
				}
			}
			p.alias = a
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
	o.policyMu.Lock()
	keys := make([][2]string, 0, len(o.policyHits))
	for k := range o.policyHits {
		keys = append(keys, k)
	}
	sort.Slice(keys, func(i, j int) bool {
		if keys[i][0] != keys[j][0] {
			return keys[i][0] < keys[j][0]
		}
		return keys[i][1] < keys[j][1]
	})
	for _, k := range keys {
		fmt.Fprintf(w, "argus_engine_identity_policy_total{rule=%q,action=%q} %d\n", k[0], k[1], o.policyHits[k])
	}
	o.policyMu.Unlock()
}
