// policyd polls the Wazuh manager API, evaluates agents and their SCA results
// against OPA/Rego policies, and stores the verdicts in ClickHouse for the
// compliance panels of the ARGUS console.
package main

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/devitex-soft/argus/policyd/internal/policy"
	"github.com/devitex-soft/argus/policyd/internal/server"
	"github.com/devitex-soft/argus/policyd/internal/store"
	"github.com/devitex-soft/argus/policyd/internal/wazuh"
)

func envOr(key, def string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return def
}

func envBool(key string, def bool) bool {
	switch strings.ToLower(strings.TrimSpace(os.Getenv(key))) {
	case "":
		return def
	case "1", "true", "yes", "on":
		return true
	}
	return false
}

// Имя переменной бюджета раунда на агента и её устаревший синоним.
const (
	perAgentEnv       = "POLICY_ROUND_BUDGET_PER_AGENT"
	legacyPerAgentEnv = "PER_AGENT_TIMEOUT"
	defaultPerAgent   = "5s"
)

// perAgentBudgetEnv читает бюджет раунда на одного агента: новое имя
// POLICY_ROUND_BUDGET_PER_AGENT, при его отсутствии — старое PER_AGENT_TIMEOUT,
// иначе дефолт. Возвращает имя источника (для лога) и сырое значение.
func perAgentBudgetEnv(getenv func(string) string) (name, value string) {
	if v := getenv(perAgentEnv); v != "" {
		return perAgentEnv, v
	}
	if v := getenv(legacyPerAgentEnv); v != "" {
		return legacyPerAgentEnv, v
	}
	return perAgentEnv, defaultPerAgent
}

// roundTimeout — бюджет раунда: минимум max(POLL_INTERVAL, 2 мин), но не
// меньше perAgent × число агентов — иначе большой парк не успевает обойти.
func roundTimeout(pollInterval, perAgent time.Duration, agents int) time.Duration {
	base := max(pollInterval, 2*time.Minute)
	if agents <= 0 {
		return base
	}
	return max(base, perAgent*time.Duration(agents))
}

func main() {
	log := slog.New(slog.NewTextHandler(os.Stderr, nil))

	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	pollInterval, err := time.ParseDuration(envOr("POLL_INTERVAL", "5m"))
	if err != nil {
		log.Error("bad POLL_INTERVAL", "err", err)
		os.Exit(1)
	}
	perAgentName, perAgentRaw := perAgentBudgetEnv(os.Getenv)
	perAgent, err := time.ParseDuration(perAgentRaw)
	if err != nil {
		log.Error("bad "+perAgentName, "err", err)
		os.Exit(1)
	}
	if perAgentName == legacyPerAgentEnv {
		log.Warn("PER_AGENT_TIMEOUT is deprecated, rename it to POLICY_ROUND_BUDGET_PER_AGENT")
	}

	engine, err := policy.New(ctx, envOr("POLICY_DIR", "/policies"), []string{"agent", "sca"})
	if err != nil {
		log.Error("cannot load policies", "err", err)
		os.Exit(1)
	}

	tlsOpts := wazuh.TLSOptions{
		Insecure:   envBool("WAZUH_INSECURE_TLS", false),
		CAFile:     os.Getenv("WAZUH_CA_FILE"),
		CertSHA256: os.Getenv("WAZUH_CERT_SHA256"),
	}
	for _, w := range tlsOpts.Warnings() {
		log.Warn(w)
	}
	wz, err := wazuh.New(
		envOr("WAZUH_API_URL", "https://localhost:55000"),
		envOr("WAZUH_API_USER", "wazuh"),
		os.Getenv("WAZUH_API_PASSWORD"),
		tlsOpts,
	)
	if err != nil {
		log.Error("cannot configure Wazuh API client", "err", err)
		os.Exit(1)
	}
	ch := store.New(
		envOr("CLICKHOUSE_URL", "http://localhost:8123"),
		envOr("CLICKHOUSE_DB", "argus"),
		envOr("CLICKHOUSE_USER", "default"),
		os.Getenv("CLICKHOUSE_PASSWORD"),
	)
	// Поле status в INSERT идёт всегда (до миграции 0011 ClickHouse его
	// отбрасывает по skip_unknown_fields); DESCRIBE — только чтобы предупредить.
	{
		dctx, cancel := context.WithTimeout(ctx, 15*time.Second)
		has, err := ch.HasStatusColumn(dctx)
		cancel()
		switch {
		case err != nil:
			log.Warn("cannot describe policy_verdicts", "err", err)
		case !has:
			log.Warn("policy_verdicts has no status column (migration 0011 not applied): verdict status is not stored")
		}
	}

	snap := server.NewSnapshot(pollInterval)
	httpSrv := &http.Server{
		Addr:              envOr("LISTEN_ADDR", ":8080"),
		Handler:           server.Handler(snap, os.Getenv("POLICYD_TOKEN")),
		ReadHeaderTimeout: 10 * time.Second,
		ReadTimeout:       30 * time.Second,
		WriteTimeout:      30 * time.Second,
		IdleTimeout:       2 * time.Minute,
	}
	go func() {
		log.Info("http server listening", "addr", httpSrv.Addr)
		if err := httpSrv.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
			log.Error("http server", "err", err)
		}
	}()

	evaluate := func() {
		if err := runRound(ctx, log, wz, engine, ch, snap, pollInterval, perAgent); err != nil {
			log.Error("evaluation round failed", "err", err)
			snap.SetError(err)
		}
	}

	evaluate()
	ticker := time.NewTicker(pollInterval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			shutdownCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			_ = httpSrv.Shutdown(shutdownCtx)
			log.Info("shutting down")
			return
		case <-ticker.C:
			evaluate()
		}
	}
}

// runRound — один раунд: агенты → политика агента → SCA → политика SCA →
// ClickHouse. Ошибка по отдельному агенту/политике даёт вердикт unknown с
// причиной, а не молчаливый пропуск; ошибка всего раунда возвращается наверх.
func runRound(ctx context.Context, log *slog.Logger, wz *wazuh.Client, engine *policy.Engine,
	ch *store.ClickHouse, snap *server.Snapshot, pollInterval, perAgent time.Duration) error {
	listCtx, cancelList := context.WithTimeout(ctx, roundTimeout(pollInterval, perAgent, 0))
	agents, err := wz.Agents(listCtx)
	cancelList()
	if err != nil {
		return fmt.Errorf("fetch agents from Wazuh API: %w", err)
	}

	evalCtx, cancel := context.WithTimeout(ctx, roundTimeout(pollInterval, perAgent, len(agents)))
	defer cancel()

	now := time.Now().UTC()
	stamp := now.Format("2006-01-02 15:04:05")
	var rows []store.VerdictRow
	unknown := 0

	for _, a := range agents {
		if a.ID == "000" { // the manager itself, not a real agent
			continue
		}
		if err := evalCtx.Err(); err != nil {
			// Бюджет раунда исчерпан: оставшиеся агенты помечаем unknown,
			// чтобы в панелях они не выглядели «соответствующими».
			rows = append(rows, unknownRow(stamp, "agent", a.ID, a.Name, "wazuh/agent", "round timeout: "+err.Error()))
			unknown++
			continue
		}
		v, err := engine.Eval(evalCtx, "agent", map[string]any{
			"id":            a.ID,
			"name":          a.Name,
			"ip":            a.IP,
			"status":        a.Status,
			"version":       a.Version,
			"stale_seconds": a.StaleSeconds(now),
			"os_platform":   a.OS.Platform,
		})
		if err != nil {
			log.Error("agent policy eval failed", "agent", a.ID, "err", err)
			rows = append(rows, unknownRow(stamp, "agent", a.ID, a.Name, "wazuh/agent", "policy eval failed: "+err.Error()))
			unknown++
			continue
		}
		rows = append(rows, verdictRow(stamp, "agent", a.ID, a.Name, "wazuh/agent", v))

		if a.Status != "active" {
			continue // SCA data of a disconnected agent is stale by definition
		}
		scas, err := wz.SCA(evalCtx, a.ID)
		if err != nil {
			log.Error("cannot fetch SCA results", "agent", a.ID, "err", err)
			rows = append(rows, unknownRow(stamp, "sca", a.ID, a.Name, "wazuh/sca", "SCA fetch failed: "+err.Error()))
			unknown++
			continue
		}
		for _, p := range scas {
			v, err := engine.Eval(evalCtx, "sca", map[string]any{
				"agent_id":   a.ID,
				"agent_name": a.Name,
				"policy":     p.Name,
				"policy_id":  p.PolicyID,
				"score":      p.Score,
				"pass":       p.Pass,
				"fail":       p.Fail,
				"invalid":    p.Invalid,
			})
			id, name := a.ID+"/"+p.PolicyID, a.Name+" · "+p.Name
			if err != nil {
				log.Error("sca policy eval failed", "agent", a.ID, "policy", p.PolicyID, "err", err)
				rows = append(rows, unknownRow(stamp, "sca", id, name, "wazuh/sca", "policy eval failed: "+err.Error()))
				unknown++
				continue
			}
			rows = append(rows, verdictRow(stamp, "sca", id, name, "wazuh/sca", v))
		}
	}

	// Снимок для /verdicts обновляем до записи: он полезен и когда ClickHouse лёг.
	snap.Set(rows)
	// Отдельный контекст: даже если раунд опроса выел весь свой таймаут,
	// уже посчитанные вердикты должны доехать до ClickHouse.
	insertCtx, cancelInsert := context.WithTimeout(context.WithoutCancel(ctx), 30*time.Second)
	defer cancelInsert()
	if err := ch.InsertVerdicts(insertCtx, rows); err != nil {
		return fmt.Errorf("store verdicts: %w", err)
	}

	violations := 0
	for _, r := range rows {
		if r.Status == store.StatusFail {
			violations++
		}
	}
	log.Info("evaluation round done",
		"agents", len(agents), "verdicts", len(rows), "violations", violations, "unknown", unknown)
	return nil
}

func verdictRow(stamp, entityType, id, name, pol string, v policy.Verdict) store.VerdictRow {
	compliant := uint8(0)
	status := store.StatusFail
	if v.Compliant {
		compliant = 1
		status = store.StatusPass
	}
	violations := v.Violations
	if violations == nil {
		violations = []string{}
	}
	return store.VerdictRow{
		EvaluatedAt: stamp,
		EntityType:  entityType,
		EntityID:    id,
		EntityName:  name,
		Policy:      pol,
		Compliant:   compliant,
		Violations:  violations,
		Status:      status,
	}
}

// unknownRow — вердикт «не удалось проверить»: compliant=0, причина в
// violations, status=unknown. Панели отличают его от нарушения по status.
func unknownRow(stamp, entityType, id, name, pol, reason string) store.VerdictRow {
	return store.VerdictRow{
		EvaluatedAt: stamp,
		EntityType:  entityType,
		EntityID:    id,
		EntityName:  name,
		Policy:      pol,
		Violations:  []string{reason},
		Status:      store.StatusUnknown,
	}
}
