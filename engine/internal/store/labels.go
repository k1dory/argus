package store

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"strconv"

	"github.com/devitex-soft/argus/engine/internal/incidents"
)

// LabeledIncident — инцидент в его текущем виде и ответ человека при
// последнем завершении. Имя аналитика не выдаётся: датасету оно не нужно,
// а это ПДн.
type LabeledIncident struct {
	Incident  incidents.Incident
	Label     ClosureLabel
	ChangedAt string
}

type labelRow struct {
	IncidentID string `json:"incident_id"`
	ChangedAt  string `json:"changed_at"`
	ClosureLabel
}

// LabeledIncidents — инциденты, последнее завершение которых сделал человек с
// меткой (labeled_by_human), с меткой не раньше since (ISO 8601, UTC), не
// больше limit, по времени метки. Последнее — по revision среди переходов в
// closed и false_positive: если инцидент переоткрыли и затем закрыли без
// метки, старая метка устарела и не выдаётся.
//
// Два запроса вместо JOIN: имена колонок c.* при соединении у ClickHouse
// зависят от версии и настроек (incident_id против c.incident_id).
func (c *ClickHouse) LabeledIncidents(ctx context.Context, since string, limit int) ([]LabeledIncident, error) {
	// toString(changed_at) — только во внешнем запросе: псевдоним с тем же
	// именем в ClickHouse подменяет колонку и в WHERE (String >= DateTime64).
	out, err := c.do(ctx, `SELECT incident_id, toString(ts) AS changed_at, disposition, escalate,
	       severity_correct, ops_cause, ops_action, blind, labeled_by_human
	FROM (
		SELECT incident_id, changed_at AS ts, disposition, escalate, severity_correct,
		       ops_cause, ops_action, blind, labeled_by_human
		FROM (
			SELECT * FROM incident_state_events
			WHERE status IN ('closed', 'false_positive')
			ORDER BY incident_id, revision DESC
			LIMIT 1 BY incident_id
		)
		WHERE labeled_by_human AND changed_at >= parseDateTime64BestEffort({since:String}, 3, 'UTC')
	)
	ORDER BY ts, incident_id
	LIMIT {limit:UInt32}
	FORMAT JSONEachRow`, nil, map[string]string{"since": since, "limit": strconv.Itoa(limit)})
	if err != nil {
		return nil, err
	}
	var labels []labelRow
	for i, line := range bytes.Split(out, []byte("\n")) {
		if len(bytes.TrimSpace(line)) == 0 {
			continue
		}
		var row labelRow
		if err := json.Unmarshal(line, &row); err != nil {
			return nil, fmt.Errorf("labeled incidents: строка %d: %w", i+1, err)
		}
		labels = append(labels, row)
	}
	if len(labels) == 0 {
		return nil, nil
	}
	ids := make([]string, len(labels))
	for i, l := range labels {
		ids[i] = l.IncidentID
	}
	idsJSON, _ := json.Marshal(ids)
	out, err = c.do(ctx, `SELECT * FROM incidents_current
	WHERE incident_id IN (SELECT arrayJoin(JSONExtract({ids:String}, 'Array(String)')))
	  AND status IN ('closed', 'false_positive')
	FORMAT JSONEachRow`, nil, map[string]string{"ids": string(idsJSON)})
	if err != nil {
		return nil, err
	}
	byID := map[string]incidents.Incident{}
	for _, line := range bytes.Split(out, []byte("\n")) {
		if len(bytes.TrimSpace(line)) == 0 {
			continue
		}
		var inc incidents.Incident
		if err := json.Unmarshal(line, &inc); err != nil {
			return nil, fmt.Errorf("labeled incidents: инцидент: %w", err)
		}
		byID[inc.IncidentID] = inc
	}
	res := make([]LabeledIncident, 0, len(labels))
	for _, l := range labels {
		inc, ok := byID[l.IncidentID]
		if !ok {
			continue // переоткрыт после метки — сейчас не завершён
		}
		res = append(res, LabeledIncident{Incident: inc, Label: l.ClosureLabel, ChangedAt: l.ChangedAt})
	}
	return res, nil
}
