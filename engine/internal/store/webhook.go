package store

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"github.com/devitex-soft/argus/engine/internal/webhook"
)

// LookupWebhookDelivery — последняя отметка доставки цели по ключу дедупа.
func (c *ClickHouse) LookupWebhookDelivery(ctx context.Context, target, key string) (webhook.Record, bool, error) {
	out, err := c.do(ctx, `SELECT incident_id, event, state, ref, toUnixTimestamp64Milli(updated_at) AS updated_ms
 FROM webhook_deliveries WHERE target = {target:String} AND dedup_key = {key:String}
 ORDER BY updated_at DESC, state = 'delivered' DESC, ref DESC, event DESC, incident_id DESC LIMIT 1 FORMAT JSONEachRow`, nil, map[string]string{"target": target, "key": key})
	if err != nil {
		return webhook.Record{}, false, err
	}
	line := strings.TrimSpace(string(out))
	if line == "" {
		return webhook.Record{}, false, nil
	}
	var row struct {
		IncidentID string `json:"incident_id"`
		Event      string `json:"event"`
		State      string `json:"state"`
		Ref        string `json:"ref"`
		UpdatedMS  int64  `json:"updated_ms"`
	}
	if err := json.Unmarshal([]byte(line), &row); err != nil {
		return webhook.Record{}, false, fmt.Errorf("webhook_deliveries: %w", err)
	}
	return webhook.Record{Target: target, Key: key, IncidentID: row.IncidentID, Event: row.Event,
		State: row.State, Ref: row.Ref, UpdatedAt: time.UnixMilli(row.UpdatedMS).UTC()}, true, nil
}

// SaveWebhookDelivery — новая версия отметки (ReplacingMergeTree по updated_at).
func (c *ClickHouse) SaveWebhookDelivery(ctx context.Context, r webhook.Record) error {
	at := r.UpdatedAt
	if at.IsZero() {
		at = time.Now()
	}
	return c.insert(ctx, "webhook_deliveries", []any{struct {
		Target     string `json:"target"`
		Key        string `json:"dedup_key"`
		IncidentID string `json:"incident_id"`
		Event      string `json:"event"`
		State      string `json:"state"`
		Ref        string `json:"ref"`
		UpdatedAt  string `json:"updated_at"`
	}{r.Target, r.Key, r.IncidentID, r.Event, r.State, r.Ref, at.UTC().Format("2006-01-02 15:04:05.000")}})
}
