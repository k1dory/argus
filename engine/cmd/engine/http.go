package main

import (
	"context"
	"crypto/subtle"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"regexp"
	"strings"
	"time"

	"github.com/devitex-soft/argus/engine/internal/eval"
	"github.com/devitex-soft/argus/engine/internal/model"
	"github.com/devitex-soft/argus/engine/internal/respond"
	"github.com/devitex-soft/argus/engine/internal/store"
)

/* ===== управляющий API =====
   Всё, кроме GET /healthz, — под токеном ENGINE_TOKEN (заголовок X-Argus-Token
   или Authorization: Bearer). /metrics принимает METRICS_TOKEN (по умолчанию тот
   же). Без токена процесс не стартует, кроме стенда с ARGUS_DEV=1. */

var incidentIDRe = regexp.MustCompile(`^INC-\d{1,9}$`)

func tokenOK(r *http.Request, want string) bool {
	if want == "" {
		return true // ARGUS_DEV=1
	}
	got := r.Header.Get("X-Argus-Token")
	if got == "" {
		got = strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer ")
	}
	return subtle.ConstantTimeCompare([]byte(got), []byte(want)) == 1
}

func requireToken(want string, next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if !tokenOK(r, want) {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusUnauthorized)
			_ = json.NewEncoder(w).Encode(map[string]string{"error": "нужен X-Argus-Token (ENGINE_TOKEN)"})
			return
		}
		next(w, r)
	}
}

func writeJSON(w http.ResponseWriter, code int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	_ = json.NewEncoder(w).Encode(v)
}

func (e *engine) handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /healthz", func(w http.ResponseWriter, _ *http.Request) {
		writeJSON(w, http.StatusOK, map[string]any{
			"status": "ok", "rules": len(e.current()), "incidents_created": e.m.incidentsCreated.Load(),
			"incidents_closed": e.m.incidentsClosed.Load(), "reloads": e.m.reloads.Load(),
			"last_run": time.Unix(e.m.lastRun.Load(), 0).UTC().Format(time.RFC3339), "errors": e.m.pollErrors.Load(),
			"buffer_events": e.m.bufferEvents.Load(), "buffer_evicted": e.m.bufferEvicted.Load(), "absence_groups": e.m.absenceGroups.Load(),
		})
	})
	mux.HandleFunc("GET /metrics", requireToken(e.mtoken, func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "text/plain; version=0.0.4")
		fmt.Fprintf(w, "argus_engine_rules %d\n", len(e.current()))
		fmt.Fprintf(w, "argus_engine_rules_reloads_total %d\n", e.m.reloads.Load())
		fmt.Fprintf(w, "argus_engine_events_polled_total %d\n", e.m.eventsPolled.Load())
		fmt.Fprintf(w, "argus_engine_incidents_created_total %d\n", e.m.incidentsCreated.Load())
		fmt.Fprintf(w, "argus_engine_incidents_autoclosed_total %d\n", e.m.incidentsClosed.Load())
		fmt.Fprintf(w, "argus_engine_incidents_dropped_total %d\n", e.m.incidentsDropped.Load())
		fmt.Fprintf(w, "argus_engine_incident_state_write_errors_total %d\n", e.m.stateWriteErrors.Load())
		fmt.Fprintf(w, "argus_clickhouse_disk_free_ratio %.3f\n", float64(e.m.diskFreePermille.Load())/1000)
		mode, _ := e.resp.Mode()
		fmt.Fprintf(w, "argus_engine_respond_mode{mode=%q} 1\n", mode)
		fmt.Fprintf(w, "argus_engine_auto_blocks_total %d\n", e.m.autoBlocks.Load())
		fmt.Fprintf(w, "argus_engine_simulated_blocks_total %d\n", e.m.simulatedBlocks.Load())
		fmt.Fprintf(w, "argus_engine_active_blocks %d\n", len(e.resp.Active()))
		fmt.Fprintf(w, "argus_engine_block_failures_total %d\n", e.m.blockFailures.Load())
		fmt.Fprintf(w, "argus_engine_untrusted_skips_total %d\n", e.m.untrustedSkips.Load())
		fmt.Fprintf(w, "argus_engine_pending_blocks %d\n", e.resp.Pending())
		fmt.Fprintf(w, "argus_engine_analyst_runs_total %d\n", e.m.analystRuns.Load())
		fmt.Fprintf(w, "argus_engine_analyst_errors_total %d\n", e.m.analystErrors.Load())
		fmt.Fprintf(w, "argus_engine_analyst_rejected_total %d\n", e.m.analystRejected.Load())
		fmt.Fprintf(w, "argus_engine_notify_suppressed_total %d\n", e.m.notifySuppressed.Load())
		e.hooks.WriteMetrics(w)
		e.identity.WriteMetrics(w)
		fmt.Fprintf(w, "argus_engine_poll_errors_total %d\n", e.m.pollErrors.Load())
		fmt.Fprintf(w, "argus_engine_last_run_timestamp %d\n", e.m.lastRun.Load())
		fmt.Fprintf(w, "argus_engine_buffer_events %d\n", e.m.bufferEvents.Load())
		fmt.Fprintf(w, "argus_engine_buffer_evicted_total %d\n", e.m.bufferEvicted.Load())
		fmt.Fprintf(w, "argus_engine_absence_groups %d\n", e.m.absenceGroups.Load())
	}))
	mux.HandleFunc("GET /rules", requireToken(e.token, func(w http.ResponseWriter, _ *http.Request) {
		type item struct {
			ID, Title, Level, File string
			Tags                   []string
			Threshold              bool
			Kind                   string
			Profile                string
			AutoClose              string
			Respond                bool
			MinEvents              int
		}
		out := []item{}
		for _, r := range e.current() {
			kind := ""
			if r.UsesThreshold() {
				kind = r.Detection.Threshold.KindResolved()
			}
			it := item{ID: r.ID, Title: r.Title, Level: r.Level, File: r.File, Tags: r.Tags, Threshold: r.UsesThreshold(), Kind: kind, Profile: r.Analyst.Profile, AutoClose: r.AutoClose}
			if r.Respond != nil {
				it.Respond, it.MinEvents = true, r.RespondMinEvents()
			}
			out = append(out, it)
		}
		writeJSON(w, http.StatusOK, out)
	}))
	// Единый источник правды для консоли: по каким полям можно заводить
	// исключения из правил (кнопка «ложное»). Консоль не должна дублировать список.
	mux.HandleFunc("GET /rules/exception_fields", requireToken(e.token, func(w http.ResponseWriter, _ *http.Request) {
		writeJSON(w, http.StatusOK, map[string]any{"exception_fields": eval.ExceptionFields()})
	}))
	mux.HandleFunc("POST /reload", requireToken(e.token, func(w http.ResponseWriter, r *http.Request) {
		e.maybeReload(true)
		e.maybeSyncIdentities(r.Context(), true) // identities.yml перечитывается вместе с правилами
		w.WriteHeader(http.StatusAccepted)
		fmt.Fprintf(w, "rules: %d\n", len(e.current()))
	}))
	mux.HandleFunc("POST /incidents/{id}/workflow", requireToken(e.token, func(w http.ResponseWriter, r *http.Request) {
		id := r.PathValue("id")
		if !incidentIDRe.MatchString(id) {
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": "некорректный идентификатор инцидента"})
			return
		}
		var in workflowRequest
		// 8 КиБ: причина до 2000 символов кириллицы (4 КиБ в UTF-8) плюс метка.
		dec := json.NewDecoder(io.LimitReader(r.Body, 8192))
		dec.DisallowUnknownFields()
		if err := dec.Decode(&in); err != nil {
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": "некорректная операция"})
			return
		}
		ctx, cancel := context.WithTimeout(context.WithoutCancel(e.ctx), 30*time.Second)
		defer cancel()
		event, err := e.transitionIncident(ctx, id, in)
		if err != nil {
			code := http.StatusConflict
			if err == errIncidentMissing {
				code = http.StatusNotFound
			}
			// Ошибка хранилища не должна возвращаться пользователю вместе с SQL.
			if code == http.StatusConflict && !isWorkflowUserError(err) {
				e.m.stateWriteErrors.Add(1)
				slog.Error("incident workflow", "id", id, "err", err)
				code = http.StatusBadGateway
			}
			message := err.Error()
			if code == http.StatusBadGateway {
				message = "хранилище недоступно"
			}
			writeJSON(w, code, map[string]string{"error": message})
			return
		}
		writeJSON(w, http.StatusOK, event)
	}))
	// Обратный канал: заблокировать адрес (active-response Wazuh / NGFW API).
	mux.HandleFunc("POST /incidents/{id}/respond", requireToken(e.token, func(w http.ResponseWriter, r *http.Request) {
		id := r.PathValue("id")
		if !incidentIDRe.MatchString(id) {
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": "некорректный идентификатор инцидента"})
			return
		}
		var in struct{ Action, IP, Reason, User string }
		if err := json.NewDecoder(io.LimitReader(r.Body, 4096)).Decode(&in); err != nil || in.Action != "block_ip" {
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": "ожидается {\"action\":\"block_ip\",\"ip\":...,\"reason\":...,\"user\":...}"})
			return
		}
		if strings.TrimSpace(in.Reason) == "" {
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": "нужна причина блокировки (reason)"})
			return
		}
		// Обрыв клиента не должен оборвать запрос к NGFW на середине и потерять запись в журнале.
		ctx, cancel := context.WithTimeout(context.WithoutCancel(e.ctx), 60*time.Second)
		defer cancel()
		actor := orDefault(strings.TrimSpace(in.User), "оператор")
		res, err := e.resp.BlockIP(ctx, in.IP, id, in.Reason)
		now := time.Now()
		ts := model.FormatTS(now)[:19]
		if err != nil {
			e.logResponses(ctx, []store.ResponseRow{respRow(ts, "manual", actor, respond.Result{Executor: "argus", IP: in.IP, Incident: id, Detail: err.Error()}, "", in.Reason)})
			writeJSON(w, http.StatusUnprocessableEntity, map[string]any{"error": err.Error()})
			return
		}
		rows := make([]store.ResponseRow, 0, len(res))
		for _, x := range res {
			rows = append(rows, respRow(ts, "manual", actor, x, "", in.Reason))
		}
		out := map[string]any{"results": res, "ttl": e.resp.ManualTTL().String()}
		blocked := false
		for _, x := range res {
			blocked = blocked || x.OK
		}
		if !blocked {
			// Ни один исполнитель не заблокировал: решения оператора нет, автоматика по
			// адресу работает как прежде (отказ — в results и журнале).
			e.logResponses(ctx, rows)
			writeJSON(w, http.StatusOK, out)
			return
		}
		// Ручной блок — решение оператора по ключам адреса, которые есть сейчас:
		// автоматика их больше не повторяет. Новые инциденты по адресу — как обычно
		// (блок уже стоит — noop). Блок поставлен, поэтому решение применяется и при
		// сбое журнала, но оператор видит предупреждение: после рестарта движок может
		// не знать о решении.
		var override []store.ResponseRow
		var keys []string
		if e.respReady(ctx, now) {
			// Ключи, решение по которым применено, но не записано прошлым вызовом, —
			// тоже: повтор после предупреждения дописывает потерянное решение.
			override, keys, _ = e.operatorKeys(in.IP, actor, in.Reason, now)
			e.applyKeys(keys, now, false)
		} else {
			// Ключи адреса из журнала ещё не прочитаны: блок стоит, их повторы дадут noop.
			out["warning"] = "блок поставлен, но журнал реагирования не прочитан: ожидающие автоблокировки адреса не отменены"
		}
		if err := e.ch.InsertResponses(ctx, append(rows, override...)); err != nil {
			slog.Error("response_log: ручной блок не записан", "ip", in.IP, "err", err)
			out["warning"] = "блок поставлен, но журнал реагирования недоступен: решение оператора не сохранится после рестарта движка — повторите, когда журнал вернётся"
		} else {
			e.markSaved(keys)
		}
		writeJSON(w, http.StatusOK, out)
	}))
	// Снятие блокировки из консоли: {ip, user, reason}. 422 — блок не найден или
	// снятие не настроено ни у одного исполнителя; отказ исполнителя — ok=false в results.
	mux.HandleFunc("POST /respond/unblock", requireToken(e.token, func(w http.ResponseWriter, r *http.Request) {
		var in struct{ IP, User, Reason string }
		if err := json.NewDecoder(io.LimitReader(r.Body, 4096)).Decode(&in); err != nil || strings.TrimSpace(in.IP) == "" {
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": "ожидается {\"ip\":...,\"user\":...,\"reason\":...}"})
			return
		}
		if strings.TrimSpace(in.Reason) == "" {
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": "нужна причина снятия (reason)"})
			return
		}
		ctx, cancel := context.WithTimeout(context.WithoutCancel(e.ctx), 60*time.Second)
		defer cancel()
		actor := orDefault(strings.TrimSpace(in.User), "оператор")
		now := time.Now()
		ts := model.FormatTS(now)[:19]
		ip := strings.TrimSpace(in.IP)
		// Снятие — решение оператора по ключам адреса, которые есть сейчас (и для
		// ожидающей автоблокировки): они конечные, повтор их больше не трогает. Новый
		// инцидент по адресу блокируется как обычно; не трогать адрес вообще —
		// /respond/exclude. Решение сначала пишется в журнал: не записалось — 503,
		// ничего не снято и не применено (иначе 200 обещал бы решение, которое
		// рестарт забудет).
		// Решение — по ключам адреса, поэтому они должны быть известны: при старте
		// журнал читается до решения, иначе повтор из журнала вернул бы снятый блок.
		if !e.respReady(ctx, now) {
			writeJSON(w, http.StatusServiceUnavailable, map[string]any{"error": "журнал реагирования не прочитан — снятие не выполнено, повторите позже"})
			return
		}
		override, keys, pending := e.operatorKeys(ip, actor, in.Reason, now)
		if len(keys) > 0 {
			if err := e.ch.InsertResponses(ctx, override); err != nil {
				slog.Error("response_log: решение оператора не записано — снятие не выполнено", "ip", ip, "err", err)
				writeJSON(w, http.StatusServiceUnavailable, map[string]any{"error": "журнал реагирования недоступен — снятие не выполнено, повторите позже"})
				return
			}
			e.applyKeys(keys, now, true)
		}
		// Ключи, которые поставили блок, пока писался журнал: этот вызов снимает и их
		// блок — тем же решением. Новые попытки, ещё не дошедшие до блока, не трогаются.
		blocked := e.doneKeys(ip)
		res, err := e.resp.Unblock(ctx, ip, in.Reason)
		out := map[string]any{}
		if late, lateKeys, _ := e.operatorKeysWhere(ip, actor, in.Reason, time.Now(), blocked); len(lateKeys) > 0 {
			e.applyKeys(lateKeys, time.Now(), false)
			if werr := e.ch.InsertResponses(ctx, late); werr != nil {
				slog.Error("response_log: решение оператора по новым ключам не записано", "ip", ip, "keys", len(lateKeys), "err", werr)
				out["warning"] = "блок снят, но журнал реагирования недоступен: решение по инцидентам, появившимся во время снятия, не сохранится после рестарта движка — повторите снятие, когда журнал вернётся"
			} else {
				e.markSaved(lateKeys)
			}
		}
		if errors.Is(err, respond.ErrNotBlocked) && pending > 0 {
			res, err = []respond.Result{{Executor: "argus", OK: true, IP: ip,
				Detail: fmt.Sprintf("блокировки ещё не было — ожидающая автоблокировка отменена (%d)", pending)}}, nil
		} else if errors.Is(err, respond.ErrNotBlocked) && len(keys) > 0 {
			// Повтор после предупреждения: блок уже снят, недописанное решение записано.
			res, err = []respond.Result{{Executor: "argus", OK: true, IP: ip,
				Detail: fmt.Sprintf("блок уже снят — решение оператора записано в журнал (%d)", len(keys))}}, nil
		}
		rows := make([]store.ResponseRow, 0, len(res)+len(override)+1)
		for _, x := range res {
			rows = append(rows, respRow(ts, "manual_unblock", actor, x, "", in.Reason))
		}
		if err != nil {
			rows = append(rows, respRow(ts, "manual_unblock", actor, respond.Result{Executor: "argus", IP: ip, Detail: err.Error()}, "", in.Reason))
			e.logResponses(ctx, rows)
			writeJSON(w, http.StatusUnprocessableEntity, map[string]any{"error": err.Error(), "results": res})
			return
		}
		e.logResponses(ctx, rows)
		slog.Warn("manual unblock", "ip", ip, "actor", actor, "reason", in.Reason)
		out["results"] = res
		writeJSON(w, http.StatusOK, out)
	}))
	// Исключение адреса из автоблокировки на срок: {ip, ttl, user, reason}. Явное
	// решение оператора — в отличие от снятия, действует на все инциденты адреса,
	// в том числе будущие, до срока или отзыва. Активный блок не снимает (это
	// /respond/unblock). Решение сначала пишется в журнал: не записалось — 503.
	mux.HandleFunc("POST /respond/exclude", requireToken(e.token, func(w http.ResponseWriter, r *http.Request) {
		var in struct{ IP, TTL, User, Reason string }
		if err := json.NewDecoder(io.LimitReader(r.Body, 4096)).Decode(&in); err != nil {
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": "ожидается {\"ip\":...,\"ttl\":\"24h\",\"user\":...,\"reason\":...}"})
			return
		}
		ip, ok := respond.CanonicalIP(strings.TrimSpace(in.IP))
		if !ok {
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": "некорректный адрес"})
			return
		}
		ttl, err := time.ParseDuration(strings.TrimSpace(in.TTL))
		if err != nil || ttl < time.Minute || ttl > excludeMaxTTL {
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": "ttl — срок исключения от 1m до " + excludeMaxTTL.String() + " (например 24h)"})
			return
		}
		if strings.TrimSpace(in.Reason) == "" {
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": "нужна причина исключения (reason)"})
			return
		}
		ctx, cancel := context.WithTimeout(context.WithoutCancel(e.ctx), 30*time.Second)
		defer cancel()
		actor := orDefault(strings.TrimSpace(in.User), "оператор")
		now := time.Now().UTC().Truncate(time.Second)
		x := exclusion{at: now, until: now.Add(ttl), actor: actor, reason: in.Reason}
		if err := e.ch.InsertResponses(ctx, []store.ResponseRow{excludeRow(ip, actor, in.Reason, now, x.until)}); err != nil {
			slog.Error("response_log: исключение адреса не записано", "ip", ip, "err", err)
			writeJSON(w, http.StatusServiceUnavailable, map[string]any{"error": "журнал реагирования недоступен — исключение не применено, повторите позже"})
			return
		}
		e.setExclusion(ip, x)
		slog.Warn("ips: адрес исключён из автоблокировки", "ip", ip, "until", x.until, "actor", actor, "reason", in.Reason)
		writeJSON(w, http.StatusOK, map[string]any{"ip": ip, "until": model.FormatTS(x.until)[:19]})
	}))
	// Отзыв исключения: {ip, user, reason}. 422 — адрес не исключён.
	mux.HandleFunc("POST /respond/exclude/revoke", requireToken(e.token, func(w http.ResponseWriter, r *http.Request) {
		var in struct{ IP, User, Reason string }
		if err := json.NewDecoder(io.LimitReader(r.Body, 4096)).Decode(&in); err != nil {
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": "ожидается {\"ip\":...,\"user\":...,\"reason\":...}"})
			return
		}
		ip, ok := respond.CanonicalIP(strings.TrimSpace(in.IP))
		if !ok {
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": "некорректный адрес"})
			return
		}
		if strings.TrimSpace(in.Reason) == "" {
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": "нужна причина отзыва (reason)"})
			return
		}
		now := time.Now().UTC().Truncate(time.Second)
		ctxRead, cancelRead := context.WithTimeout(context.WithoutCancel(e.ctx), 30*time.Second)
		defer cancelRead()
		// Исключения из журнала при старте ещё не прочитаны — 503, а не «не исключён».
		if !e.respReady(ctxRead, now) {
			writeJSON(w, http.StatusServiceUnavailable, map[string]any{"error": "журнал реагирования не прочитан — исключение не отозвано, повторите позже"})
			return
		}
		if _, excluded := e.excludedUntil(ip, now); !excluded {
			writeJSON(w, http.StatusUnprocessableEntity, map[string]string{"error": "адрес не исключён из автоблокировки"})
			return
		}
		ctx, cancel := context.WithTimeout(context.WithoutCancel(e.ctx), 30*time.Second)
		defer cancel()
		actor := orDefault(strings.TrimSpace(in.User), "оператор")
		if err := e.ch.InsertResponses(ctx, []store.ResponseRow{excludeRow(ip, actor, in.Reason, now, now)}); err != nil {
			slog.Error("response_log: отзыв исключения не записан", "ip", ip, "err", err)
			writeJSON(w, http.StatusServiceUnavailable, map[string]any{"error": "журнал реагирования недоступен — исключение не отозвано, повторите позже"})
			return
		}
		e.setExclusion(ip, exclusion{at: now, until: now})
		slog.Warn("ips: исключение адреса отозвано", "ip", ip, "actor", actor, "reason", in.Reason)
		writeJSON(w, http.StatusOK, map[string]any{"ip": ip})
	}))
	// Состояние реагирования для консоли: режим и его источник, списки, активные блокировки.
	mux.HandleFunc("GET /respond/status", requireToken(e.token, func(w http.ResponseWriter, r *http.Request) {
		e.syncRespondMode(r.Context()) // консоль видит режим сразу после переключения, не ждёт цикла
		mode, from := e.resp.Mode()
		writeJSON(w, http.StatusOK, map[string]any{
			"mode": mode, "mode_from": from, "enabled": e.resp.Enabled(), "ttl": e.resp.TTL().String(), "manual_ttl": e.resp.ManualTTL().String(),
			"allowlist": e.resp.Allowlist(), "never_block": e.resp.NeverBlock(), "trusted_sources": e.resp.TrustedSources(),
			"active": e.resp.Active(), "config_errors": e.resp.ConfigErrors(), "pending": e.resp.Pending(),
			"excluded": e.exclusions(time.Now()),
		})
	}))
	// Переразбор инцидента по запросу из консоли (кнопка в карточке): через
	// общую очередь с семафором, cooldown и суточным лимитом.
	mux.HandleFunc("POST /incidents/{id}/analyze", requireToken(e.token, func(w http.ResponseWriter, r *http.Request) {
		id := r.PathValue("id")
		if !incidentIDRe.MatchString(id) {
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": "некорректный идентификатор инцидента"})
			return
		}
		inc, err := e.ch.GetIncident(r.Context(), id)
		if err != nil {
			writeJSON(w, http.StatusBadGateway, map[string]string{"error": err.Error()})
			return
		}
		if inc == nil {
			writeJSON(w, http.StatusNotFound, map[string]string{"error": "инцидент не найден"})
			return
		}
		if ok, why := e.scheduleAnalyze(inc, e.ruleFor(inc.RuleID)); !ok {
			writeJSON(w, http.StatusTooManyRequests, map[string]string{"error": why})
			return
		}
		w.WriteHeader(http.StatusAccepted)
		fmt.Fprintf(w, "analyze scheduled: %s\n", id)
	}))
	return mux
}

// activeBlock — у адреса есть активная блокировка.
func (e *engine) activeBlock(ip string) bool {
	c, ok := respond.CanonicalIP(ip)
	for _, b := range e.resp.Active() {
		if b.IP == ip || (ok && b.IP == c) {
			return true
		}
	}
	return false
}

func (e *engine) logResponses(ctx context.Context, rows []store.ResponseRow) {
	if len(rows) == 0 {
		return
	}
	if err := e.ch.InsertResponses(ctx, rows); err != nil {
		slog.Warn("response_log insert", "err", err)
	}
}

func (e *engine) serveHTTP(ctx context.Context, addr string) {
	srv := &http.Server{Addr: addr, Handler: e.handler(), ReadHeaderTimeout: 5 * time.Second}
	go func() {
		<-ctx.Done()
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		_ = srv.Shutdown(shutdownCtx)
	}()
	slog.Info("http listening", "addr", addr)
	if err := srv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
		slog.Error("http", "err", err)
	}
}
