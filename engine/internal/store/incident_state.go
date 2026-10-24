package store

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/json"
	"fmt"
	"strconv"
	"time"

	"github.com/devitex-soft/argus/engine/internal/incidents"
)

type IncidentStateEvent struct {
	EventID    string `json:"event_id"`
	IncidentID string `json:"incident_id"`
	Revision   uint64 `json:"revision"`
	ChangedAt  string `json:"changed_at"`
	Actor      string `json:"actor"`
	Kind       string `json:"kind"`
	Status     string `json:"status"`
	Owner      string `json:"owner"`
	Reason     string `json:"reason"`
}

func (c *ClickHouse) CurrentIncident(ctx context.Context, id string) (*incidents.Incident, error) {
	out, err := c.do(ctx, `SELECT * FROM incidents_current WHERE incident_id = {id:String} LIMIT 1 FORMAT JSONEachRow`, nil,
		map[string]string{"id": id})
	if err != nil {
		return nil, err
	}
	if len(bytes.TrimSpace(out)) == 0 {
		return nil, nil
	}
	var inc incidents.Incident
	if err := json.Unmarshal(bytes.TrimSpace(out), &inc); err != nil {
		return nil, err
	}
	return &inc, nil
}

func (c *ClickHouse) IncidentRevision(ctx context.Context, id string) (uint64, error) {
	out, err := c.do(ctx, `SELECT toString(max(revision)) AS revision FROM incident_state_events
		WHERE incident_id = {id:String} FORMAT JSONEachRow`, nil, map[string]string{"id": id})
	if err != nil {
		return 0, err
	}
	var row struct {
		Revision string `json:"revision"`
	}
	if err := json.Unmarshal(bytes.TrimSpace(out), &row); err != nil {
		return 0, err
	}
	return strconv.ParseUint(row.Revision, 10, 64)
}

func newEventID() (string, error) {
	var b [16]byte
	if _, err := rand.Read(b[:]); err != nil {
		return "", err
	}
	b[6] = (b[6] & 0x0f) | 0x40
	b[8] = (b[8] & 0x3f) | 0x80
	return fmt.Sprintf("%x-%x-%x-%x-%x", b[:4], b[4:6], b[6:8], b[8:10], b[10:]), nil
}

func (c *ClickHouse) AppendIncidentState(ctx context.Context, id, actor, kind, status, owner, reason string) (IncidentStateEvent, error) {
	rev, err := c.IncidentRevision(ctx, id)
	if err != nil {
		return IncidentStateEvent{}, err
	}
	eventID, err := newEventID()
	if err != nil {
		return IncidentStateEvent{}, err
	}
	e := IncidentStateEvent{
		EventID: eventID, IncidentID: id, Revision: rev + 1,
		ChangedAt: time.Now().UTC().Format("2006-01-02 15:04:05.000"),
		Actor:     actor, Kind: kind, Status: status, Owner: owner, Reason: reason,
	}
	if err := c.insert(ctx, "incident_state_events", []any{e}); err != nil {
		return IncidentStateEvent{}, err
	}
	return e, nil
}
