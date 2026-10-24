package store

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"time"
)

// Те же целевые сроки первичной реакции, что показаны в консоли:
// critical 15 мин, high 1 ч, medium 4 ч, low 24 ч.
const riskLatest = `WITH latest AS (
 SELECT incident_id, created_at, rule_title AS title, level, status, owner
 FROM incidents_current
)`

const riskOverdue = `status = 'new' AND dateDiff('second', created_at, now()) >
 multiIf(level = 'critical', 900, level = 'high', 3600, level = 'medium', 14400, 86400)`

type RiskTotals struct {
	Open       int `json:"open"`
	Unassigned int `json:"unassigned"`
	Overdue    int `json:"overdue"`
	Critical   int `json:"critical"`
}

type RiskOwner struct {
	Owner   string `json:"owner"`
	Open    int    `json:"open"`
	Overdue int    `json:"overdue"`
}

type RiskIncident struct {
	ID        string `json:"incident_id"`
	Title     string `json:"title"`
	Level     string `json:"level"`
	Status    string `json:"status"`
	Owner     string `json:"owner"`
	CreatedAt string `json:"created_at_str"`
	Deadline  string `json:"deadline"`
	Overdue   int    `json:"overdue"`
}

type RiskReport struct {
	Totals RiskTotals
	Owners []RiskOwner
	Top    []RiskIncident
}

func (c *ClickHouse) RiskReportLastSent(ctx context.Context) (time.Time, error) {
	out, err := c.do(ctx, `SELECT if(count() = 0, 0, toUnixTimestamp64Milli(max(sent_at))) AS last_ms
 FROM risk_report_deliveries FORMAT JSONEachRow`, nil, nil)
	if err != nil {
		return time.Time{}, err
	}
	var row struct {
		LastMS int64 `json:"last_ms"`
	}
	if err := json.Unmarshal([]byte(strings.TrimSpace(string(out))), &row); err != nil {
		return time.Time{}, err
	}
	if row.LastMS == 0 {
		return time.Time{}, nil
	}
	return time.UnixMilli(row.LastMS).UTC(), nil
}

func (c *ClickHouse) RecordRiskReportDelivery(ctx context.Context, sentAt time.Time) error {
	id, err := newEventID()
	if err != nil {
		return err
	}
	return c.insert(ctx, "risk_report_deliveries", []any{struct {
		ReportID string `json:"report_id"`
		SentAt   string `json:"sent_at"`
	}{ReportID: id, SentAt: sentAt.UTC().Format("2006-01-02 15:04:05.000")}})
}

func reportRows[T any](ctx context.Context, c *ClickHouse, query string) ([]T, error) {
	out, err := c.do(ctx, query+" FORMAT JSONEachRow", nil, nil)
	if err != nil {
		return nil, err
	}
	var rows []T
	for _, line := range strings.Split(strings.TrimSpace(string(out)), "\n") {
		if line == "" {
			continue
		}
		var row T
		if err := json.Unmarshal([]byte(line), &row); err != nil {
			return nil, fmt.Errorf("risk report: %w", err)
		}
		rows = append(rows, row)
	}
	return rows, nil
}

func (c *ClickHouse) RiskReport(ctx context.Context) (RiskReport, error) {
	open := `status NOT IN ('closed', 'false_positive')`
	totals, err := reportRows[RiskTotals](ctx, c, riskLatest+`
 SELECT count() AS open, countIf(owner = '') AS unassigned,
        countIf(`+riskOverdue+`) AS overdue, countIf(level = 'critical') AS critical
 FROM latest WHERE `+open)
	if err != nil {
		return RiskReport{}, err
	}
	owners, err := reportRows[RiskOwner](ctx, c, riskLatest+`
 SELECT owner, count() AS open,
        countIf(`+riskOverdue+`) AS overdue
 FROM latest WHERE `+open+` GROUP BY owner ORDER BY overdue DESC, open DESC LIMIT 50`)
	if err != nil {
		return RiskReport{}, err
	}
	top, err := reportRows[RiskIncident](ctx, c, riskLatest+`
 SELECT incident_id, title, level, status, owner, toString(created_at) AS created_at_str,
        toString(created_at + toIntervalSecond(multiIf(level = 'critical', 900, level = 'high', 3600, level = 'medium', 14400, 86400))) AS deadline,
        if(`+riskOverdue+`, 1, 0) AS overdue
 FROM latest WHERE `+open+`
 ORDER BY overdue DESC, multiIf(level = 'critical', 4, level = 'high', 3, level = 'medium', 2, 1) DESC, created_at ASC LIMIT 30`)
	if err != nil {
		return RiskReport{}, err
	}
	var total RiskTotals
	if len(totals) > 0 {
		total = totals[0]
	}
	return RiskReport{Totals: total, Owners: owners, Top: top}, nil
}
