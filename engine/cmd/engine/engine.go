package main

import (
	"context"
	"fmt"
	"log/slog"
	"os"
	"os/signal"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"time"

	"github.com/devitex-soft/argus/engine/internal/analyst"
	"github.com/devitex-soft/argus/engine/internal/enrich"
	"github.com/devitex-soft/argus/engine/internal/eval"
	"github.com/devitex-soft/argus/engine/internal/incidents"
	"github.com/devitex-soft/argus/engine/internal/model"
	"github.com/devitex-soft/argus/engine/internal/notify"
	"github.com/devitex-soft/argus/engine/internal/respond"
	"github.com/devitex-soft/argus/engine/internal/rules"
	"github.com/devitex-soft/argus/engine/internal/store"
	"github.com/devitex-soft/argus/engine/internal/webhook"
)

/* ===== run ===== */

type metrics struct {
	incidentsCreated atomic.Int64
	incidentsClosed  atomic.Int64
	incidentsDropped atomic.Int64 // не заведены сверх ARGUS_MAX_NEW_INCIDENTS за цикл
	stateWriteErrors atomic.Int64 // переход не попал в журнал после записи снимка или запроса оператора
	eventsPolled     atomic.Int64
	analystErrors    atomic.Int64
	analystRuns      atomic.Int64
	analystRejected  atomic.Int64 // cooldown / суточный лимит
	pollErrors       atomic.Int64
	reloads          atomic.Int64
	lastRun          atomic.Int64
	diskFreePermille atomic.Int64 // свободно на самом заполненном диске ClickHouse, ‰
	autoBlocks       atomic.Int64
	simulatedBlocks  atomic.Int64
	blockFailures    atomic.Int64
	untrustedSkips   atomic.Int64 // автоблокировка не выполнена: недоверенный источник события
	notifySuppressed atomic.Int64 // уведомления, ушедшие в сводку или отброшенные лимитом
}

type engine struct {
	rules      atomic.Pointer[[]*rules.Rule]
	rulesDir   string
	reloadMu   sync.Mutex // rulesSig и перечитывание: цикл и POST /reload
	workflowMu sync.Mutex // единственный писатель переходов и снимков инцидентов
	rulesSig   string
	ch         *store.ClickHouse
	an         *analyst.Analyst
	en         *enrich.Enricher
	tg         *notify.Telegram
	mail       *notify.Email
	agg        *notify.Aggregator
	hooks      *webhook.Dispatcher // nil — исходящие вебхуки не настроены
	resp       *respond.Responder
	acfg       analyst.Config
	reg        *incidents.Registry
	m          metrics
	sched      *scheduler
	ctx        context.Context // жизнь процесса: разборы и HTTP-ручки отменяются при остановке
	token      string          // ENGINE_TOKEN; пусто только при ARGUS_DEV=1
	mtoken     string          // METRICS_TOKEN (по умолчанию = ENGINE_TOKEN)

	sysMu  sync.Mutex
	storms map[string]*incidents.Incident // rule_id → открытый инцидент «шторм»

	respMu     sync.Mutex
	respState  map[string]respEntry // incident_id → что автоответ уже решил
	respCycles int                  // циклов с последней чистки respState по возрасту

	excWarnMu sync.Mutex
	excWarned map[string]bool
}

type respEntry struct {
	state string // waiting | done
	at    time.Time
}

func (e *engine) current() []*rules.Rule { return *e.rules.Load() }

func (e *engine) ruleFor(id string) *rules.Rule {
	for _, r := range e.current() {
		if r.ID == id {
			return r
		}
	}
	return nil
}

// signature — отпечаток каталога правил (с подкаталогами): имя, размер,
// mtime каждого файла.
func signature(dir string) string {
	paths, _ := rules.Files(dir)
	var b strings.Builder
	for _, p := range paths {
		if st, err := os.Stat(p); err == nil {
			fmt.Fprintf(&b, "%s|%d|%d;", p, st.Size(), st.ModTime().UnixNano())
		}
	}
	return b.String()
}

// maybeReload перечитывает правила, если каталог изменился; force — без проверки отпечатка.
func (e *engine) maybeReload(force bool) {
	e.reloadMu.Lock()
	defer e.reloadMu.Unlock()
	sig := signature(e.rulesDir)
	if !force && sig == e.rulesSig {
		return
	}
	rs, err := rules.Load(e.rulesDir)
	if err != nil {
		slog.Warn("rules reload: оставляю прежний набор", "err", err)
		e.rulesSig = sig
		return
	}
	e.rules.Store(&rs)
	e.rulesSig = sig
	e.m.reloads.Add(1)
	slog.Info("rules reloaded", "rules", len(rs))
}

func (e *engine) syncRespondMode(ctx context.Context) {
	v, err := e.ch.ConsoleSetting(ctx, "respond_mode")
	if err != nil {
		slog.Debug("respond mode", "err", err)
		return
	}
	if !e.resp.SetMode(v) { // "" — вернуться к конфигу
		slog.Warn("respond mode: неизвестное значение из консоли, игнорирую", "value", v)
	}
}

func newEngine(ctx context.Context, rulesDir string, rs []*rules.Rule, acfg analyst.Config, ch *store.ClickHouse, token, mtoken string) *engine {
	e := &engine{
		rulesDir: rulesDir, rulesSig: signature(rulesDir), ch: ch, acfg: acfg, ctx: ctx, token: token, mtoken: mtoken,
		an: analyst.New(acfg), en: enrich.New(ch, env("CMDB_FILE", "")),
		tg: notify.NewTelegram(os.Getenv("TELEGRAM_BOT_TOKEN"), acfg.Notify.Telegram.ChatID),
		mail: notify.NewEmail(acfg.Notify.Email.Host, acfg.Notify.Email.Port, acfg.Notify.Email.From,
			acfg.Notify.Email.User, acfg.Notify.Email.Password, acfg.Notify.Email.To, acfg.Notify.Email.StartTLS),
		agg:       notify.NewAggregator(time.Minute, 5),
		resp:      respond.New(acfg.Respond),
		storms:    map[string]*incidents.Incident{},
		respState: map[string]respEntry{},
		excWarned: map[string]bool{},
	}
	e.rules.Store(&rs)
	routes, problems := webhook.Build(acfg.Notify.Webhooks, os.Getenv)
	for _, p := range problems {
		slog.Error("webhook config: цель выключена", "problem", p)
	}
	var hookStore webhook.Store
	if ch != nil {
		hookStore = ch
	}
	e.hooks = webhook.New(routes, hookStore, webhook.Options{ConsoleURL: os.Getenv("ARGUS_CONSOLE_URL")})
	for _, r := range routes {
		slog.Info("webhook: цель включена", "target", r.Name, "min_level", r.MinLevel)
	}
	e.sched = newScheduler(envInt("ANALYST_CONCURRENCY", 4), envInt("ANALYST_DAILY_LIMIT", 500), 5*time.Minute)
	if e.tg != nil {
		e.tg.SetLimit(envInt("NOTIFY_TELEGRAM_PER_MINUTE", 20))
	}
	if e.mail != nil {
		e.mail.SetLimit(envInt("NOTIFY_EMAIL_PER_MINUTE", 20))
	}
	return e
}

func run(rulesDir string) {
	rs := mustLoad(rulesDir)
	acfg, err := analyst.LoadConfig(env("ANALYST_CONFIG", ""))
	if err != nil {
		slog.Error("analyst config", "err", err)
		os.Exit(1)
	}
	if msg := wazuhPlaceholderPassword(acfg.Respond.WazuhAR, os.Getenv("WAZUH_API_URL"), os.Getenv("WAZUH_API_PASSWORD")); msg != "" && os.Getenv("ARGUS_DEV") != "1" {
		slog.Error(msg)
		os.Exit(1)
	}
	token := strings.TrimSpace(os.Getenv("ENGINE_TOKEN"))
	if token == "" && os.Getenv("ARGUS_DEV") != "1" {
		slog.Error("ENGINE_TOKEN не задан: управляющий API движка (/reload, /rules, /respond/*, /incidents/*, /metrics) без токена открыт всем в сети compose. Задайте ENGINE_TOKEN в .env или ARGUS_DEV=1 для стенда")
		os.Exit(1)
	}
	if token == "" {
		slog.Warn("ARGUS_DEV=1: управляющий API без токена — только для стенда")
	}
	ch := store.New(env("CLICKHOUSE_URL", "http://localhost:8123"), env("CLICKHOUSE_DB", "argus"),
		env("CLICKHOUSE_USER", "default"), env("CLICKHOUSE_PASSWORD", ""))
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()
	e := newEngine(ctx, rulesDir, rs, acfg, ch, token, env("METRICS_TOKEN", token))
	for _, msg := range e.resp.ConfigErrors() {
		slog.Warn("respond config", "msg", msg)
	}
	poll, _ := time.ParseDuration(env("POLL_INTERVAL", "30s"))
	if poll <= 0 {
		poll = 30 * time.Second
	}
	e.startAnalystWorkers()
	e.hooks.Start(ctx)
	go e.serveHTTP(ctx, env("LISTEN_ADDR", ":8090"))
	if raw := env("RISK_REPORT_INTERVAL", ""); raw != "" {
		interval, err := time.ParseDuration(raw)
		if err != nil || interval < time.Hour {
			slog.Error("RISK_REPORT_INTERVAL: ожидается длительность не меньше 1h", "value", raw)
		} else if e.mail == nil || strings.TrimSpace(os.Getenv("SMTP_FROM")) == "" || strings.TrimSpace(os.Getenv("SMTP_TO")) == "" {
			slog.Error("risk report: SMTP_HOST, SMTP_FROM и SMTP_TO обязательны")
		} else {
			go e.runReports(ctx, interval)
		}
	}

	for {
		open, maxN, err := ch.OpenIncidents(ctx)
		if err == nil {
			reg := incidents.NewRegistry(maxN, open)
			reg.SetMaxNew(envInt("ARGUS_MAX_NEW_INCIDENTS", 200))
			// HTTP уже слушает (healthcheck), а /analyze через analystLimitIncident
			// читает e.reg под sysMu — присваиваем под тем же замком.
			e.sysMu.Lock()
			e.reg = reg
			e.sysMu.Unlock()
			restored := e.restoreRespState(open, time.Now())
			slog.Info("engine started", "rules", len(rs), "open_incidents", len(open), "respond_restored", restored, "next", maxN+1, "poll", poll)
			break
		}
		slog.Warn("clickhouse недоступен, жду", "err", err)
		select {
		case <-time.After(5 * time.Second):
		case <-ctx.Done():
			return
		}
	}
	e.loop(ctx, poll)
	// ctx уже отменён: недоставленное из очереди и отложенные повторы не
	// выполнятся (отметок о них нет — после перезапуска они не повторятся),
	// ждём только выхода воркеров с текущей попыткой.
	if queued, retries := e.hooks.Pending(); queued+retries > 0 {
		slog.Warn("webhook: остановка, недоставленные события бросаются", "queued", queued, "retries", retries)
	}
	if !e.hooks.WaitTimeout(10 * time.Second) {
		slog.Warn("webhook: воркеры не вышли за 10s (текущая попытка доставки не завершилась), выхожу без них")
	}
}

func (e *engine) maxWindow() time.Duration {
	w := 15 * time.Minute
	for _, r := range e.current() {
		if rw := r.Window(); rw > w {
			w = rw
		}
	}
	return w
}

func (e *engine) loop(ctx context.Context, poll time.Duration) {
	// Стартовый курсор — два окна назад: после рестарта окна восстанавливаются
	// из базы, а дубли гасит реестр открытых инцидентов.
	cursor := time.Now().Add(-2 * e.maxWindow())
	var buffer []*model.Event
	ticker := time.NewTicker(poll)
	defer ticker.Stop()
	for {
		e.maybeReload(false)
		e.syncRespondMode(ctx)
		rs := e.current()
		events, next, err := e.ch.EventsSince(ctx, cursor, 200000)
		if err != nil {
			slog.Warn("events", "err", err)
			e.m.pollErrors.Add(1)
		} else {
			cursor = next
			e.m.eventsPolled.Add(int64(len(events)))
			// В буфере живут только кандидаты: события, которые проходят
			// selection или close_on хотя бы одного правила. При тысячах EPS
			// это уменьшает буфер на порядки — оценка остаётся дешёвой.
			for _, ev := range events {
				if isCandidate(rs, ev) {
					buffer = append(buffer, ev)
				}
			}
			cut := time.Now().Add(-2 * e.maxWindow())
			kept := buffer[:0]
			for _, ev := range buffer {
				if ev.ReceivedAt.IsZero() || !ev.ReceivedAt.Before(cut) {
					kept = append(kept, ev)
				}
			}
			buffer = kept
			buffer = e.cycle(ctx, rs, buffer)
			e.m.lastRun.Store(time.Now().Unix())
		}
		e.checkDisks(ctx, time.Now())
		e.flushDigests(ctx)
		go e.expireBlocks(context.WithoutCancel(ctx), time.Now())
		select {
		case <-ticker.C:
		case <-ctx.Done():
			return
		}
	}
}

// cycle — один проход правил по буферу: сработки → инциденты → запись → реакции.
func (e *engine) cycle(ctx context.Context, rs []*rules.Rule, buffer []*model.Event) []*model.Event {
	exc, err := e.ch.Exceptions(ctx)
	if err != nil {
		slog.Warn("exceptions", "err", err)
	}
	exc = eval.SanitizeExceptions(exc, e.warnException)
	now := time.Now()
	dets, closers := eval.Evaluate(eval.Input{Rules: rs, Events: buffer, Now: now, Exceptions: exc})
	created, updated, dropped := e.reg.Apply(dets, now)
	var toWrite []*incidents.Incident
	engineClosed := map[string]bool{}
	toWrite = append(toWrite, updated...)
	for _, c := range closers {
		note := "закрыт автоматикой: событие " + c.Event.Action + " по " + c.Key
		var closed []*incidents.Incident
		if len(c.Rule.CloseMatch) > 0 {
			// Ротация/отзыв того же секрета в том же проекте позже последней
			// утечки; закрывает только отзыв доказанно того же токена, иначе —
			// эскалация с пометкой «нужна проверка».
			var review []*incidents.Incident
			closed, review = e.reg.CloseMatched(c.Rule.ID, c.Event, c.Rule, note+" ("+strings.Join(c.Rule.CloseMatch, ", ")+" совпали)", now)
			for _, inc := range review {
				engineClosed[inc.IncidentID] = true // статус движка: Reconcile не откатит escalated на new
				toWrite = append(toWrite, inc)
				slog.Warn("incident: ротация не подтверждена, нужна проверка", "id", inc.IncidentID, "by", c.Event.Action, "token_id", c.Event.Attrs["token_id"])
			}
		} else if inc := e.reg.Close(c.Rule.ID, c.Key, note, now); inc != nil {
			closed = append(closed, inc)
		}
		for _, inc := range closed {
			engineClosed[inc.IncidentID] = true
			toWrite = append(toWrite, inc)
			e.m.incidentsClosed.Add(1)
			slog.Info("incident auto-closed", "id", inc.IncidentID, "by", c.Event.Action)
		}
	}
	swept, escalated := e.reg.Sweep(func(id string) incidents.AutoClose {
		if r := e.ruleFor(id); r != nil {
			return incidents.AutoClose{After: r.AutoCloseAfter(), Escalate: r.AutoCloseEscalates()}
		}
		return incidents.AutoClose{}
	}, now)
	for _, inc := range swept {
		engineClosed[inc.IncidentID] = true
		toWrite = append(toWrite, inc)
		e.m.incidentsClosed.Add(1)
		slog.Info("incident auto-closed", "id", inc.IncidentID, "by", "auto_close")
	}
	for _, inc := range escalated {
		engineClosed[inc.IncidentID] = true // статус движка, как у закрытия: Reconcile не откатит его на new
		toWrite = append(toWrite, inc)
		slog.Warn("incident auto-escalated: тишина без отзыва секрета", "id", inc.IncidentID, "rule", inc.RuleID)
	}
	for _, inc := range created {
		r := e.ruleFor(inc.RuleID)
		if r != nil && len(r.Enrich) > 0 {
			inc.Enrichment = e.en.Run(ctx, inc, r.Enrich)
		}
		if sim, err := e.ch.SimilarIncidents(ctx, inc.RuleID, inc.ActorName, inc.Node, inc.IncidentID, 5); err == nil {
			inc.Similar = sim
		}
		toWrite = append(toWrite, inc)
	}
	toWrite = append(toWrite, e.stormIncidents(ctx, dropped, now)...)
	e.writeIncidents(ctx, toWrite, engineClosed, now)
	// Закрытые инциденты absence-правил остаются якорем дедупликации: их
	// «последнее событие» по определению старое, и без якоря молчание
	// заводило бы новый инцидент каждый цикл после чистки.
	e.reg.Prune(now, 24*time.Hour, func(ruleID string) bool {
		r := e.ruleFor(ruleID)
		return r != nil && r.IsAbsence()
	})
	if e.respCycles++; e.respCycles >= respPruneCycles {
		e.respCycles = 0
		e.pruneRespState(now, respStateTTL)
	}
	// Реагирование — вне главного цикла: исполнители ходят по сети, опрос
	// событий не ждёт. Горутина получает снимки: Apply следующего цикла
	// перезапишет Events/EventCount тех же инцидентов.
	go e.autoRespond(context.WithoutCancel(ctx), snapshotIncidents(append(append([]*incidents.Incident{}, created...), updated...)), now)
	for _, inc := range created {
		slog.Info("incident", "id", inc.IncidentID, "level", inc.Level, "rule", inc.RuleID, "actor", inc.ActorName, "events", inc.EventCount, "pii", inc.PII)
		e.m.incidentsCreated.Add(1)
		if ok, why := e.scheduleAnalyze(inc, e.ruleFor(inc.RuleID)); !ok {
			slog.Warn("analyst: разбор не запланирован", "incident", inc.IncidentID, "why", why)
		}
		e.notifyIncident(ctx, inc)
		e.hooks.Notify(webhook.EventCreated, inc)
	}
	return buffer
}

// writeIncidents сверяет снимки с текущим состоянием и пишет детекции.
// workflowMu исключает одновременный переход оператора на этом экземпляре engine.
func (e *engine) writeIncidents(ctx context.Context, toWrite []*incidents.Incident, engineClosed map[string]bool, now time.Time) {
	if len(toWrite) == 0 {
		return
	}
	e.workflowMu.Lock()
	defer e.workflowMu.Unlock()
	// Сверка с консолью: статус/владелец/заметка оператора важнее
	// копии в памяти движка (см. Registry.Reconcile).
	ids := make([]string, 0, len(toWrite))
	for _, inc := range toWrite {
		ids = append(ids, inc.IncidentID)
	}
	seen := map[string]incidents.Operator{}
	if ops, err := e.ch.OperatorStates(ctx, ids); err != nil {
		slog.Warn("operator states", "err", err)
	} else {
		for id, o := range ops {
			seen[id] = incidents.Operator{Status: o.Status, Owner: o.Owner, Note: o.Note, UpdatedAt: o.UpdatedAt}
		}
		toWrite = e.reg.Reconcile(toWrite, seen, engineClosed, now)
	}
	if len(toWrite) == 0 {
		return
	}
	if err := e.ch.InsertIncidents(ctx, toWrite); err != nil {
		slog.Warn("incidents insert", "err", err)
		return
	}
	for _, inc := range toWrite {
		if engineClosed[inc.IncidentID] && (inc.Status == incidents.StatusClosed || inc.Status == incidents.StatusFalsePositive) {
			if _, err := e.ch.AppendIncidentState(ctx, inc.IncidentID, "argus-engine", "auto_close", inc.Status, inc.Owner, "Закрыто автоматикой по правилу "+inc.RuleID); err != nil {
				e.m.stateWriteErrors.Add(1)
				slog.Error("incident auto-close state", "id", inc.IncidentID, "err", err)
			}
		}
		if engineClosed[inc.IncidentID] && inc.Status == incidents.StatusEscalated {
			reason := "Эскалировано автоматикой по правилу " + inc.RuleID + ": тишина без отзыва или ротации секрета"
			if inc.Review != "" {
				reason = "Эскалировано автоматикой по правилу " + inc.RuleID + ": " + inc.Review
			}
			if _, err := e.ch.AppendIncidentState(ctx, inc.IncidentID, "argus-engine", "auto_escalate", inc.Status, inc.Owner, reason); err != nil {
				e.m.stateWriteErrors.Add(1)
				slog.Error("incident auto-escalate state", "id", inc.IncidentID, "err", err)
				continue
			}
			e.hooks.Notify(webhook.EventEscalated, inc)
		}
	}
}

// warnException — исключение по полю вне whitelist: один раз в лог, дальше молча.
func (e *engine) warnException(ruleID, field, value string) {
	e.excWarnMu.Lock()
	defer e.excWarnMu.Unlock()
	key := ruleID + "|" + field + "|" + value
	if e.excWarned[key] {
		return
	}
	if len(e.excWarned) > 1000 {
		e.excWarned = map[string]bool{}
	}
	e.excWarned[key] = true
	slog.Warn("rule exception: поле вне whitelist — игнорирую", "rule", ruleID, "field", field, "value", value, "allowed", strings.Join(eval.ExceptionFields(), ", "))
}

// wazuhPlaceholderPassword — пароль API Wazuh остался заглушкой change-me* из
// argus init, а менеджер задан: движок не стартует (кроме стенда ARGUS_DEV=1),
// иначе исполнитель active-response молча получал бы 401 на каждую блокировку.
// Проверяются и переменные окружения, и то, что дошло до конфига исполнителя.
func wazuhPlaceholderPassword(w *respond.WazuhAR, envURL, envPass string) string {
	placeholder := func(p string) bool { return strings.HasPrefix(strings.TrimSpace(p), "change-me") }
	switch {
	case strings.TrimSpace(envURL) != "" && placeholder(envPass):
		return "WAZUH_API_PASSWORD — заглушка change-me при заданном WAZUH_API_URL: впишите пароль API менеджера Wazuh в .env (или ARGUS_DEV=1 для стенда)"
	case w != nil && strings.TrimSpace(w.APIURL) != "" && placeholder(w.Password):
		return "respond.wazuh_active_response.password — заглушка change-me при заданном api_url: впишите пароль API менеджера Wazuh (или ARGUS_DEV=1 для стенда)"
	}
	return ""
}

func isCandidate(rs []*rules.Rule, ev *model.Event) bool {
	for _, r := range rs {
		if r.Match(ev) || r.MatchClose(ev) {
			return true
		}
	}
	return false
}

func wantsNotify(levels []string, level string) bool {
	if len(levels) == 0 {
		levels = []string{"critical"}
	}
	for _, l := range levels {
		if strings.EqualFold(l, level) {
			return true
		}
	}
	return false
}

// notifyIncident — уведомление о новом инциденте через агрегатор: первые
// пять по правилу за минуту уходят отдельно, остальные — одной сводкой.
func (e *engine) notifyIncident(ctx context.Context, inc *incidents.Incident) {
	wantTG := e.tg != nil && wantsNotify(e.acfg.Notify.Telegram.Levels, inc.Level)
	wantMail := e.mail != nil && wantsNotify(e.acfg.Notify.Email.Levels, inc.Level)
	if !wantTG && !wantMail {
		return
	}
	if !e.agg.Add(inc.RuleID, inc.RuleTitle, inc.ActorName) {
		e.m.notifySuppressed.Add(1)
		return
	}
	if wantTG {
		e.sendTelegram(ctx, "⚠ "+inc.Summary())
	}
	if wantMail {
		e.sendMail(ctx, "[ARGUS] "+inc.IncidentID+" "+strings.ToUpper(inc.Level)+" · "+inc.RuleTitle, inc.Summary()+"\n\n"+strings.Join(inc.Chain, "\n"))
	}
}

// flushDigests — сводки закрывшихся окон агрегатора во все каналы.
func (e *engine) flushDigests(ctx context.Context) {
	for _, msg := range e.agg.Flush() {
		slog.Warn("notify: шторм инцидентов", "digest", msg)
		if e.tg != nil {
			e.sendTelegram(ctx, msg)
		}
		if e.mail != nil {
			e.sendMail(ctx, "[ARGUS] шторм инцидентов", msg)
		}
	}
}

func (e *engine) sendTelegram(ctx context.Context, text string) {
	go func() {
		if err := e.tg.Send(ctx, text); err != nil {
			if err == notify.ErrRateLimited {
				e.m.notifySuppressed.Add(1)
			}
			slog.Warn("telegram", "err", err)
		}
	}()
}

func (e *engine) sendMail(ctx context.Context, subject, body string) {
	go func() {
		if err := e.mail.Send(ctx, subject, body); err != nil {
			if err == notify.ErrRateLimited {
				e.m.notifySuppressed.Add(1)
			}
			slog.Warn("email", "err", err)
		}
	}()
}

// notifyAll — уведомления по инциденту во все настроенные каналы (без учёта уровней).
func (e *engine) notifyAll(ctx context.Context, inc *incidents.Incident) {
	e.hooks.Notify(webhook.EventCreated, inc) // у вебхуков свой порог уровня
	if e.tg != nil {
		e.sendTelegram(ctx, "⚠ "+inc.Summary())
	}
	if e.mail != nil {
		e.sendMail(ctx, "[ARGUS] "+inc.IncidentID+" "+strings.ToUpper(inc.Level)+" · "+inc.RuleTitle, inc.Summary()+"\n\n"+strings.Join(inc.Chain, "\n"))
	}
}
