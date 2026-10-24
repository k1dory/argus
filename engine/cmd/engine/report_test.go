package main

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/devitex-soft/argus/engine/internal/store"
)

type reportStoreStub struct {
	last     time.Time
	receipts []time.Time
}

func (s *reportStoreStub) RiskReportLastSent(context.Context) (time.Time, error) { return s.last, nil }
func (s *reportStoreStub) RiskReport(context.Context) (store.RiskReport, error) {
	return store.RiskReport{}, nil
}
func (s *reportStoreStub) RecordRiskReportDelivery(_ context.Context, sent time.Time) error {
	s.receipts = append(s.receipts, sent)
	if len(s.receipts) == 1 {
		return errors.New("database temporarily unavailable")
	}
	s.last = sent
	return nil
}

type reportSenderStub struct{ calls int }

func (s *reportSenderStub) Send(context.Context, string, string) error { s.calls++; return nil }

func TestReportReceiptRetryDoesNotResendEmail(t *testing.T) {
	ch, mail := &reportStoreStub{}, &reportSenderStub{}
	waits := 0
	runRiskReports(context.Background(), ch, mail, 24*time.Hour, func(_ context.Context, delay time.Duration) bool {
		waits++
		if waits == 1 {
			if delay != 5*time.Minute {
				t.Fatalf("retry delay: %s", delay)
			}
			return true
		}
		if delay < 23*time.Hour {
			t.Fatalf("next report scheduled too soon: %s", delay)
		}
		return false
	})
	if mail.calls != 1 || len(ch.receipts) != 2 || ch.receipts[0] != ch.receipts[1] {
		t.Fatalf("mail calls=%d, receipts=%v", mail.calls, ch.receipts)
	}
}

func TestNextRiskReportDelaySurvivesRestart(t *testing.T) {
	now := time.Date(2026, 9, 25, 12, 0, 0, 0, time.UTC)
	interval := 24 * time.Hour
	if got := nextRiskReportDelay(time.Time{}, interval, now); got != 0 {
		t.Fatalf("первая отправка должна быть сразу, got %s", got)
	}
	if got := nextRiskReportDelay(now.Add(-23*time.Hour), interval, now); got != time.Hour {
		t.Fatalf("после перезапуска остался час, got %s", got)
	}
	if got := nextRiskReportDelay(now.Add(-25*time.Hour), interval, now); got != 0 {
		t.Fatalf("пропущенный срок должен быть отправлен сразу, got %s", got)
	}
}
