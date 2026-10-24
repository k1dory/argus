// Package webhook — исходящие вебхуки движка: новый или эскалированный
// инцидент уровня не ниже порога уходит в настраиваемые цели (подписанный
// HTTP POST; другие виды целей реализуют интерфейс Target). Доставка с
// ретраями и backoff, повтор по тому же событию не доставляется дважды:
// отметки доставки лежат в ClickHouse и переживают перезапуск. URL, секреты
// и токены — только из окружения; в логах и метриках — имя цели, без адресов.
package webhook

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"log/slog"
	"math/rand/v2"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/devitex-soft/argus/engine/internal/incidents"
)

// Типы событий.
const (
	EventCreated   = "incident.created"
	EventEscalated = "incident.escalated"
)

// Payload — тело события. Снимок инцидента делается при постановке в очередь:
// следующий цикл движка меняет те же структуры.
type Payload struct {
	Event      string   `json:"event"`
	DeliveryID string   `json:"delivery_id"` // стабилен для цели и ключа дедупа: получатель может дедуплицировать сам
	SentAt     string   `json:"sent_at"`
	Incident   Incident `json:"incident"`
}

type Incident struct {
	ID         string   `json:"id"`
	Level      string   `json:"level"`
	Status     string   `json:"status"`
	RuleID     string   `json:"rule_id"`
	RuleTitle  string   `json:"rule_title"`
	Tags       []string `json:"tags,omitempty"`
	Actor      string   `json:"actor"`
	Node       string   `json:"node"`
	Sources    []string `json:"sources,omitempty"`
	EventCount uint32   `json:"event_count"`
	FirstTS    string   `json:"first_ts"`
	LastTS     string   `json:"last_ts"`
	CreatedAt  string   `json:"created_at"`
	PII        bool     `json:"pii"`
	Chain      []string `json:"chain,omitempty"` // только у целей с include_chain
	URL        string   `json:"url,omitempty"`   // карточка в консоли, если задан ARGUS_CONSOLE_URL
}

func snapshot(inc *incidents.Incident, consoleURL string) Incident {
	out := Incident{
		ID: inc.IncidentID, Level: strings.ToLower(inc.Level), Status: inc.Status, RuleID: inc.RuleID, RuleTitle: inc.RuleTitle,
		Tags: append([]string(nil), inc.Tags...), Actor: inc.ActorName, Node: inc.Node, Sources: append([]string(nil), inc.Sources...),
		EventCount: inc.EventCount, FirstTS: inc.FirstTS, LastTS: inc.LastTS, CreatedAt: inc.CreatedAt, PII: inc.PII == 1,
		Chain: append([]string(nil), inc.Chain...),
	}
	if consoleURL != "" {
		out.URL = strings.TrimRight(consoleURL, "/") + "/incidents/" + inc.IncidentID
	}
	return out
}

// levelRank — порядок уровней для порога min_level; неизвестный уровень — 0.
func levelRank(level string) int {
	switch strings.ToLower(strings.TrimSpace(level)) {
	case "critical":
		return 4
	case "high":
		return 3
	case "medium":
		return 2
	case "low":
		return 1
	}
	return 0
}

// Target — адаптер цели.
type Target interface {
	// Deliver доставляет событие. rec — прежнее состояние доставки по ключу
	// дедупа (Ref пуст, если ещё ничего не делали). checkpoint сохраняет
	// промежуточный шаг многошаговой цели (например, id созданного у неё
	// объекта), чтобы ретрай не повторял его.
	Deliver(ctx context.Context, p Payload, rec Record, checkpoint func(ref string) error) (ref string, err error)
	// DedupKey — ключ, по которому повтор считается тем же событием.
	DedupKey(p Payload) string
}

// PermanentError — повтор не поможет (4xx, кроме 408/429; неверный ответ).
type PermanentError struct{ Err error }

func (e *PermanentError) Error() string { return e.Err.Error() }
func (e *PermanentError) Unwrap() error { return e.Err }

func permanent(format string, a ...any) error {
	return &PermanentError{Err: fmt.Errorf(format, a...)}
}

// IsPermanent — ошибка не лечится повтором.
func IsPermanent(err error) bool {
	var p *PermanentError
	return errors.As(err, &p)
}

// Record — отметка доставки по ключу дедупа.
type Record struct {
	Target     string
	Key        string
	IncidentID string
	Event      string
	State      string // created — сделан промежуточный шаг; delivered — доставлено
	Ref        string // ссылка цели на доставку: код ответа HTTP или id объекта в цели
	UpdatedAt  time.Time
}

const (
	StateCreated   = "created"
	StateDelivered = "delivered"
)

// Store — где живут отметки доставки (ClickHouse в бою, память в тестах).
type Store interface {
	LookupWebhookDelivery(ctx context.Context, target, key string) (Record, bool, error)
	SaveWebhookDelivery(ctx context.Context, r Record) error
}

// Options — параметры доставки.
type Options struct {
	Workers     int           // по умолчанию 2
	QueueSize   int           // по умолчанию 1000; сверх — событие отбрасывается с метрикой dropped
	MaxAttempts int           // по умолчанию 8
	BaseBackoff time.Duration // по умолчанию 2s; дальше удвоение с джиттером
	MaxBackoff  time.Duration // по умолчанию 5m
	Timeout     time.Duration // на одну попытку, по умолчанию 15s
	ConsoleURL  string
}

func (o *Options) defaults() {
	if o.Workers <= 0 {
		o.Workers = 2
	}
	if o.QueueSize <= 0 {
		o.QueueSize = 1000
	}
	if o.MaxAttempts <= 0 {
		o.MaxAttempts = 8
	}
	if o.BaseBackoff <= 0 {
		o.BaseBackoff = 2 * time.Second
	}
	if o.MaxBackoff <= 0 {
		o.MaxBackoff = 5 * time.Minute
	}
	if o.Timeout <= 0 {
		o.Timeout = 15 * time.Second
	}
}

// Route — цель с фильтром событий.
type Route struct {
	Name         string
	MinLevel     string
	Events       []string // пусто — оба типа
	IncludeChain bool
	Target       Target
}

// wants — проходит ли событие фильтр цели. Эскалацию делает только человек
// (workflow консоли): он уже решил, что инцидент важный, поэтому min_level к
// ней не применяется — только список events.
func (r *Route) wants(event, level string) bool {
	if event != EventEscalated && levelRank(level) < max(levelRank(r.MinLevel), 1) {
		return false
	}
	if len(r.Events) == 0 {
		return true
	}
	for _, e := range r.Events {
		if e == event {
			return true
		}
	}
	return false
}

// TargetMetrics — счётчики одной цели.
type TargetMetrics struct {
	Delivered atomic.Int64
	Failed    atomic.Int64 // исчерпаны попытки или постоянная ошибка
	Deduped   atomic.Int64 // повтор по уже доставленному ключу
	Dropped   atomic.Int64 // очередь переполнена или движок останавливается
	Retries   atomic.Int64
}

type job struct {
	route   *Route
	payload Payload
	attempt int
}

// Dispatcher — очередь и воркеры доставки.
type Dispatcher struct {
	opts    Options
	routes  []*Route
	store   Store
	jobs    chan job
	metrics map[string]*TargetMetrics

	mu    sync.Mutex
	cache map[string]Record      // target|key → последняя известная отметка (дедуп без похода в базу)
	locks map[string]*keyedMutex // target|key → замок: created и escalated одного инцидента не идут параллельно

	ctx     context.Context
	wg      sync.WaitGroup
	retries sync.WaitGroup
	waiting atomic.Int64 // ретраи, ждущие своей паузы
	nowFn   func() time.Time
}

type keyedMutex struct {
	mu   sync.Mutex
	refs int
}

// New собирает диспетчер; nil, если целей нет.
func New(routes []*Route, store Store, opts Options) *Dispatcher {
	if len(routes) == 0 {
		return nil
	}
	opts.defaults()
	d := &Dispatcher{
		opts: opts, routes: routes, store: store, jobs: make(chan job, opts.QueueSize),
		metrics: map[string]*TargetMetrics{}, cache: map[string]Record{}, locks: map[string]*keyedMutex{},
		nowFn: time.Now,
	}
	for _, r := range routes {
		d.metrics[r.Name] = &TargetMetrics{}
	}
	return d
}

// Start запускает воркеры; они живут до отмены ctx.
func (d *Dispatcher) Start(ctx context.Context) {
	if d == nil {
		return
	}
	d.ctx = ctx
	for i := 0; i < d.opts.Workers; i++ {
		d.wg.Add(1)
		go func() {
			defer d.wg.Done()
			for {
				select {
				case j := <-d.jobs:
					d.process(ctx, j)
				case <-ctx.Done():
					return
				}
			}
		}()
	}
}

// Wait — дождаться остановки воркеров и отложенных ретраев (после отмены ctx).
func (d *Dispatcher) Wait() {
	if d == nil {
		return
	}
	d.wg.Wait()
	d.retries.Wait()
}

// Pending — сколько доставок не завершено: в очереди и в паузе перед
// повтором. После отмены ctx ни те, ни другие уже не выполнятся: очередь в
// памяти, отметки о них нет, поэтому после перезапуска они не повторятся.
func (d *Dispatcher) Pending() (queued, retries int) {
	if d == nil {
		return 0, 0
	}
	return len(d.jobs), int(d.waiting.Load())
}

// WaitTimeout — Wait, но не дольше d; false — не дождались. После отмены ctx
// ждать нечего, кроме выхода воркеров: текущая попытка доставки дорабатывает
// до своего таймаута, ретраи и очередь бросаются (см. Pending). Зависшая цель
// не должна держать остановку движка.
func (d *Dispatcher) WaitTimeout(timeout time.Duration) bool {
	if d == nil {
		return true
	}
	done := make(chan struct{})
	go func() {
		d.Wait()
		close(done)
	}()
	select {
	case <-done:
		return true
	case <-time.After(timeout):
		return false
	}
}

// Notify ставит событие по инциденту в очередь всех подходящих целей. Не
// блокирует цикл движка: при полной очереди событие отбрасывается.
func (d *Dispatcher) Notify(event string, inc *incidents.Incident) {
	if d == nil || inc == nil {
		return
	}
	snap := snapshot(inc, d.opts.ConsoleURL)
	for _, r := range d.routes {
		if !r.wants(event, snap.Level) {
			continue
		}
		p := Payload{Event: event, Incident: snap} // срезы снимка общие, но только для чтения
		if !r.IncludeChain {
			p.Incident.Chain = nil
		}
		p.DeliveryID = deliveryID(r.Name, r.Target.DedupKey(p))
		select {
		case d.jobs <- job{route: r, payload: p}:
		default:
			d.metrics[r.Name].Dropped.Add(1)
			slog.Warn("webhook: очередь переполнена, событие отброшено", "target", r.Name, "incident", inc.IncidentID, "event", event)
		}
	}
}

func deliveryID(target, key string) string {
	sum := sha256.Sum256([]byte(target + "|" + key))
	return hex.EncodeToString(sum[:16])
}

func (d *Dispatcher) lock(k string) func() {
	d.mu.Lock()
	m := d.locks[k]
	if m == nil {
		m = &keyedMutex{}
		d.locks[k] = m
	}
	m.refs++
	d.mu.Unlock()
	m.mu.Lock()
	return func() {
		m.mu.Unlock()
		d.mu.Lock()
		if m.refs--; m.refs == 0 {
			delete(d.locks, k)
		}
		d.mu.Unlock()
	}
}

func (d *Dispatcher) remember(r Record) {
	d.mu.Lock()
	defer d.mu.Unlock()
	if len(d.cache) > 10000 {
		d.cache = map[string]Record{} // база остаётся источником правды
	}
	d.cache[r.Target+"|"+r.Key] = r
}

func (d *Dispatcher) lookup(ctx context.Context, target, key string) (Record, bool, error) {
	d.mu.Lock()
	r, ok := d.cache[target+"|"+key]
	d.mu.Unlock()
	if ok || d.store == nil {
		return r, ok, nil
	}
	r, ok, err := d.store.LookupWebhookDelivery(ctx, target, key)
	if err == nil && ok {
		d.remember(r)
	}
	return r, ok, err
}

func (d *Dispatcher) save(ctx context.Context, r Record) error {
	// Память — первой: если база не приняла отметку, в этом процессе повтора
	// всё равно не будет; после перезапуска возможен один дубль (at least once).
	d.remember(r)
	if d.store == nil {
		return nil
	}
	return d.store.SaveWebhookDelivery(ctx, r)
}

func (d *Dispatcher) process(ctx context.Context, j job) {
	r, p := j.route, j.payload
	m := d.metrics[r.Name]
	key := r.Target.DedupKey(p)
	unlock := d.lock(r.Name + "|" + key)
	defer unlock()

	actx, cancel := context.WithTimeout(ctx, d.opts.Timeout)
	defer cancel()
	rec, found, err := d.lookup(actx, r.Name, key)
	if err != nil {
		// Без отметки не знаем, доставляли ли уже: лучше повторить позже, чем завести дубль.
		d.retry(j, fmt.Errorf("отметка доставки: %w", err))
		return
	}
	if found && rec.State == StateDelivered {
		m.Deduped.Add(1)
		slog.Debug("webhook: уже доставлено", "target", r.Name, "incident", p.Incident.ID, "event", p.Event)
		return
	}
	if !found {
		rec = Record{Target: r.Name, Key: key, IncidentID: p.Incident.ID, Event: p.Event}
	}
	p.SentAt = d.nowFn().UTC().Format(time.RFC3339)
	checkpoint := func(ref string) error {
		rec.State, rec.Ref, rec.UpdatedAt = StateCreated, ref, d.nowFn().UTC()
		return d.save(actx, rec)
	}
	ref, err := r.Target.Deliver(actx, p, rec, checkpoint)
	if err != nil {
		if IsPermanent(err) {
			m.Failed.Add(1)
			slog.Error("webhook: доставка отклонена целью", "target", r.Name, "incident", p.Incident.ID, "event", p.Event, "err", err)
			return
		}
		d.retry(j, err)
		return
	}
	rec.State, rec.Ref, rec.UpdatedAt = StateDelivered, ref, d.nowFn().UTC()
	if err := d.save(actx, rec); err != nil {
		slog.Warn("webhook: доставлено, но отметка не записана — после перезапуска возможен повтор", "target", r.Name, "incident", p.Incident.ID, "err", err)
	}
	m.Delivered.Add(1)
	slog.Info("webhook: доставлено", "target", r.Name, "incident", p.Incident.ID, "event", p.Event, "ref", ref, "attempt", j.attempt+1)
}

// backoff — base·2^attempt с джиттером ±20%, не больше max.
func (d *Dispatcher) backoff(attempt int) time.Duration {
	b := d.opts.BaseBackoff << min(attempt, 20)
	if b <= 0 || b > d.opts.MaxBackoff {
		b = d.opts.MaxBackoff
	}
	jitter := time.Duration(float64(b) * (rand.Float64()*0.4 - 0.2))
	return b + jitter
}

func (d *Dispatcher) retry(j job, cause error) {
	m := d.metrics[j.route.Name]
	if j.attempt+1 >= d.opts.MaxAttempts {
		m.Failed.Add(1)
		slog.Error("webhook: попытки исчерпаны", "target", j.route.Name, "incident", j.payload.Incident.ID, "event", j.payload.Event, "attempts", j.attempt+1, "err", cause)
		return
	}
	wait := d.backoff(j.attempt)
	m.Retries.Add(1)
	slog.Warn("webhook: ошибка доставки, повтор", "target", j.route.Name, "incident", j.payload.Incident.ID, "event", j.payload.Event, "attempt", j.attempt+1, "in", wait.Round(time.Millisecond), "err", cause)
	j.attempt++
	d.retries.Add(1)
	d.waiting.Add(1)
	go func() {
		defer d.retries.Done()
		defer d.waiting.Add(-1)
		t := time.NewTimer(wait)
		defer t.Stop()
		select {
		case <-t.C:
		case <-d.ctx.Done():
			m.Dropped.Add(1)
			return
		}
		select {
		case d.jobs <- j:
		case <-d.ctx.Done():
			m.Dropped.Add(1)
		}
	}()
}

// WriteMetrics — счётчики в формате Prometheus.
func (d *Dispatcher) WriteMetrics(w interface{ Write([]byte) (int, error) }) {
	if d == nil {
		return
	}
	names := make([]string, 0, len(d.metrics))
	for n := range d.metrics {
		names = append(names, n)
	}
	sort.Strings(names)
	for _, n := range names {
		m := d.metrics[n]
		for _, kv := range []struct {
			result string
			v      int64
		}{{"delivered", m.Delivered.Load()}, {"failed", m.Failed.Load()}, {"deduped", m.Deduped.Load()}, {"dropped", m.Dropped.Load()}} {
			fmt.Fprintf(w, "argus_engine_webhook_deliveries_total{target=%q,result=%q} %d\n", n, kv.result, kv.v)
		}
		fmt.Fprintf(w, "argus_engine_webhook_retries_total{target=%q} %d\n", n, m.Retries.Load())
	}
	fmt.Fprintf(w, "argus_engine_webhook_queue %d\n", len(d.jobs))
}

// Metrics — счётчики цели (для тестов и диагностики).
func (d *Dispatcher) Metrics(target string) *TargetMetrics {
	if d == nil {
		return nil
	}
	return d.metrics[target]
}
