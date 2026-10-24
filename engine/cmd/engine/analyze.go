package main

import (
	"context"
	"fmt"
	"log/slog"
	"sync"
	"time"

	"github.com/devitex-soft/argus/engine/internal/incidents"
	"github.com/devitex-soft/argus/engine/internal/model"
	"github.com/devitex-soft/argus/engine/internal/rules"
	"github.com/devitex-soft/argus/engine/internal/store"
)

/* ===== LLM-разборы: очередь с ограничениями =====
   Разбор — сетевой вызов на десятки секунд и, для облачного профиля, деньги.
   Ограничения: не больше ANALYST_CONCURRENCY одновременно (столько воркеров
   читают очередь), очередь ограничена concurrency×20 задачами — при
   переполнении отказ (лог, метрика analyst_rejected, HTTP 429), а не
   бесконечный рост горутин в шторм; один инцидент не чаще раза в cooldown
   (кнопка в консоли не должна давать DoS); облачных вызовов не больше
   ANALYST_DAILY_LIMIT в сутки — при достижении системный инцидент, дальше
   только локальные/mock профили. Автоанализ новых инцидентов и переразбор
   из консоли идут через одну и ту же очередь. */

const (
	analystLimitRuleID = "argus.system.analyst_limit"
	analystQueueFactor = 20 // ёмкость очереди = concurrency × analystQueueFactor
	errQueueFull       = "очередь разборов полна"
)

type analyzeJob struct {
	inc     *incidents.Incident
	profile string
	redact  []string
}

type scheduler struct {
	queue    chan analyzeJob
	workers  int
	cooldown time.Duration
	limit    int
	nowFn    func() time.Time

	mu       sync.Mutex
	last     map[string]time.Time
	day      string
	dayCount int
	notified bool // системный инцидент о лимите за этот день уже заведён
}

func newScheduler(concurrency, dailyLimit int, cooldown time.Duration) *scheduler {
	if concurrency <= 0 {
		concurrency = 4
	}
	return &scheduler{queue: make(chan analyzeJob, concurrency*analystQueueFactor), workers: concurrency,
		cooldown: cooldown, limit: dailyLimit, nowFn: time.Now, last: map[string]time.Time{}}
}

// startAnalystWorkers — воркеры очереди разборов (по одному на слот
// concurrency); живут до остановки процесса. Вызывать один раз после newEngine.
func (e *engine) startAnalystWorkers() {
	for i := 0; i < e.sched.workers; i++ {
		go func() {
			for {
				select {
				case <-e.ctx.Done():
					return
				case j := <-e.sched.queue:
					e.analyze(e.ctx, j.inc, j.profile, j.redact)
				}
			}
		}()
	}
}

// admit — можно ли запускать разбор; cloud — учитывать в суточном лимите.
// limitHit — суточный потолок только что достигнут (пора заводить инцидент).
func (s *scheduler) admit(incidentID string, cloud bool) (ok bool, why string, limitHit bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	now := s.nowFn()
	if t, seen := s.last[incidentID]; seen && now.Sub(t) < s.cooldown {
		return false, fmt.Sprintf("cooldown: разбор %s был %s назад, минимум %s", incidentID, now.Sub(t).Truncate(time.Second), s.cooldown), false
	}
	if day := now.UTC().Format("2006-01-02"); day != s.day {
		s.day, s.dayCount, s.notified = day, 0, false
	}
	if cloud && s.limit > 0 && s.dayCount >= s.limit {
		hit := !s.notified
		s.notified = true
		return false, fmt.Sprintf("суточный лимит облачных разборов %d исчерпан (%s)", s.limit, s.day), hit
	}
	if cloud {
		s.dayCount++
	}
	if len(s.last) > 10000 {
		for id, t := range s.last {
			if now.Sub(t) >= s.cooldown {
				delete(s.last, id)
			}
		}
	}
	s.last[incidentID] = now
	return true, "", false
}

// release — откат admit: задача не встала в очередь, cooldown и суточный
// счётчик не должны её учитывать.
func (s *scheduler) release(incidentID string, cloud bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	delete(s.last, incidentID)
	if cloud && s.dayCount > 0 {
		s.dayCount--
	}
}

// scheduleAnalyze ставит разбор в очередь (не блокирует вызывающего).
func (e *engine) scheduleAnalyze(inc *incidents.Incident, r *rules.Rule) (bool, string) {
	profile, redact := "", []string(nil)
	if r != nil {
		profile, redact = r.Analyst.Profile, r.Analyst.Redact
	}
	cloud := e.an.IsCloud(inc, profile)
	ok, why, limitHit := e.sched.admit(inc.IncidentID, cloud)
	if limitHit {
		e.analystLimitIncident(e.ctx, why)
	}
	if !ok {
		e.m.analystRejected.Add(1)
		return false, why
	}
	select {
	case e.sched.queue <- analyzeJob{inc: inc, profile: profile, redact: redact}:
		return true, ""
	default:
		e.sched.release(inc.IncidentID, cloud)
		e.m.analystRejected.Add(1)
		slog.Warn("analyst: "+errQueueFull, "incident", inc.IncidentID, "queued", len(e.sched.queue), "cap", cap(e.sched.queue))
		return false, errQueueFull
	}
}

func (e *engine) analyze(ctx context.Context, inc *incidents.Incident, profile string, redact []string) {
	e.m.analystRuns.Add(1)
	res := e.an.Analyze(ctx, inc, profile, redact)
	v := store.Verdict{
		Missing: res.Verdict.Missing, Actions: res.Verdict.Actions, ConfidenceKind: "self_reported",
		IncidentID: inc.IncidentID, EvaluatedAt: model.FormatTS(time.Now())[:19],
		Profile: res.Profile, Model: res.Model, SummaryRU: res.Verdict.SummaryRU,
		Evidence: res.Verdict.Evidence, FirstAction: res.Verdict.FirstAction,
		Confidence: res.Verdict.Confidence, Tokens: res.Tokens, LatencyMs: res.LatencyMs, ShownReason: res.ShownReason,
	}
	if v.Actions == nil {
		v.Actions = []string{}
	}
	if res.Model == "mock" {
		v.ConfidenceKind = "mock"
	}
	if res.Shown {
		v.Shown = 1
	}
	if res.Err != nil {
		v.Error = res.Err.Error()
		e.m.analystErrors.Add(1)
		slog.Warn("analyst", "incident", inc.IncidentID, "profile", res.Profile, "err", res.Err)
	}
	if err := e.ch.InsertVerdict(ctx, v); err != nil {
		slog.Warn("verdict insert", "err", err)
	}
}

// analystLimitIncident — системный инцидент «суточный лимит облачных разборов»:
// дежурный должен знать, что новые инциденты остаются без второго мнения.
func (e *engine) analystLimitIncident(ctx context.Context, why string) {
	e.sysMu.Lock()
	defer e.sysMu.Unlock()
	if e.reg == nil {
		return
	}
	ts := model.FormatTS(time.Now())[:19]
	id, _ := e.reg.NextID()
	inc := &incidents.Incident{
		IncidentID: id, UpdatedAt: ts, CreatedAt: ts, RuleID: analystLimitRuleID,
		RuleTitle: "Суточный лимит облачных LLM-разборов исчерпан", Level: "medium", Tags: []string{"argus.system", "ops.analyst"},
		Status: incidents.StatusNew, ActorName: "argus-engine", Node: "argus-engine", Sources: []string{"argus.system"},
		EventCount: 1, FirstTS: ts, LastTS: ts,
		Chain: []string{ts + " · " + why},
		Note:  "Системный инцидент движка. До конца суток (UTC) облачный профиль не вызывается; локальные и mock-профили работают. Поднять предел — ANALYST_DAILY_LIMIT.",
	}
	if err := e.ch.InsertIncidents(ctx, []*incidents.Incident{inc}); err != nil {
		slog.Warn("analyst limit incident insert", "err", err)
		return
	}
	e.reg.AddSystem(inc)
	e.m.incidentsCreated.Add(1)
	slog.Error("analyst daily limit", "id", id, "why", why)
	e.notifyAll(ctx, inc)
}
