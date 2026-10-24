package main

import (
	"context"
	"fmt"
	"log/slog"
	"strings"
	"time"

	"github.com/devitex-soft/argus/engine/internal/store"
)

type riskReportStore interface {
	RiskReportLastSent(context.Context) (time.Time, error)
	RiskReport(context.Context) (store.RiskReport, error)
	RecordRiskReportDelivery(context.Context, time.Time) error
}

type riskReportSender interface {
	Send(context.Context, string, string) error
}

func (e *engine) runReports(ctx context.Context, interval time.Duration) {
	runRiskReports(ctx, e.ch, e.mail, interval, waitReport)
}

func runRiskReports(ctx context.Context, ch riskReportStore, mail riskReportSender, interval time.Duration, wait func(context.Context, time.Duration) bool) {
	const retryDelay = 5 * time.Minute
	for ctx.Err() == nil {
		last, err := ch.RiskReportLastSent(ctx)
		if err != nil {
			slog.Error("risk report schedule", "err", err)
			if !wait(ctx, retryDelay) {
				return
			}
			continue
		}
		if delay := nextRiskReportDelay(last, interval, time.Now()); delay > 0 {
			if !wait(ctx, delay) {
				return
			}
			continue
		}
		// При ошибке чтения отчёт не отправляем: неполная сводка опаснее
		// пропущенного письма. Повторяем через пять минут.
		report, err := ch.RiskReport(ctx)
		if err != nil {
			slog.Error("risk report query", "err", err)
			if !wait(ctx, retryDelay) {
				return
			}
			continue
		}
		body := formatRiskReport(report, time.Now().UTC())
		if err := mail.Send(ctx, "ARGUS: регулярный отчёт по рискам", body); err != nil {
			slog.Error("risk report delivery", "err", err)
			if !wait(ctx, retryDelay) {
				return
			}
			continue
		}
		sentAt := time.Now().UTC()
		for {
			if err := ch.RecordRiskReportDelivery(ctx, sentAt); err == nil {
				break
			} else {
				// SMTP уже принял письмо: повторяем только запись квитанции.
				// После аварийного рестарта до записи возможна повторная доставка.
				slog.Error("risk report delivery receipt", "err", err)
			}
			if !wait(ctx, retryDelay) {
				return
			}
		}
		slog.Info("risk report delivered", "open", report.Totals.Open, "overdue", report.Totals.Overdue)
	}
}

func nextRiskReportDelay(last time.Time, interval time.Duration, now time.Time) time.Duration {
	if last.IsZero() {
		return 0
	}
	delay := last.Add(interval).Sub(now)
	if delay < 0 {
		return 0
	}
	return delay
}

func waitReport(ctx context.Context, delay time.Duration) bool {
	t := time.NewTimer(delay)
	defer t.Stop()
	select {
	case <-ctx.Done():
		return false
	case <-t.C:
		return true
	}
}

func formatRiskReport(r store.RiskReport, now time.Time) string {
	var b strings.Builder
	fmt.Fprintf(&b, "ARGUS — риски на %s UTC\n", now.Format("2006-01-02 15:04"))
	b.WriteString("Срок первичной реакции 24/7 от создания: critical 15 мин, high 1 ч, medium 4 ч, low 24 ч. Просрочка — статус new после срока.\n\n")
	fmt.Fprintf(&b, "Открытых: %d; критичных: %d; без ответственного: %d; просрочена реакция: %d.\n\n", r.Totals.Open, r.Totals.Critical, r.Totals.Unassigned, r.Totals.Overdue)
	b.WriteString("Ответственные (первые 50 по просрочкам и нагрузке):\n")
	for _, owner := range r.Owners {
		name := owner.Owner
		if name == "" {
			name = "не назначен"
		}
		fmt.Fprintf(&b, "- %s: открытых %d, просрочено %d\n", name, owner.Open, owner.Overdue)
	}
	b.WriteString("\nПриоритетные инциденты (первые 30):\n")
	for _, inc := range r.Top {
		owner := inc.Owner
		if owner == "" {
			owner = "не назначен"
		}
		mark := ""
		if inc.Overdue == 1 {
			mark = " ПРОСРОЧЕНО"
		}
		fmt.Fprintf(&b, "- %s [%s] %s; %s; ответственный: %s; реакция до %s UTC%s\n", inc.ID, inc.Level, inc.Title, inc.Status, owner, inc.Deadline, mark)
	}
	return b.String()
}
