// Package store — чтение событий и запись инцидентов/вердиктов в ClickHouse
// по HTTP (JSONEachRow), только стандартная библиотека.
package store

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"regexp"
	"strings"
	"time"

	"github.com/devitex-soft/argus/engine/internal/eval"
	"github.com/devitex-soft/argus/engine/internal/incidents"
	"github.com/devitex-soft/argus/engine/internal/model"
)

type ClickHouse struct {
	base, db, user, pass string
	http                 *http.Client
}

// JSONEachRow escapes newlines inside values, so an exception on its own
// line cannot be confused with event text containing "DB::Exception".
var responseException = regexp.MustCompile(`(?m)^Code:\s*\d+\.\s*DB::Exception:`)

func New(base, db, user, pass string) *ClickHouse {
	return &ClickHouse{base: strings.TrimRight(base, "/"), db: db, user: user, pass: pass,
		http: &http.Client{Timeout: 60 * time.Second}}
}

// Host — имя узла ClickHouse из адреса подключения (без порта); «clickhouse»,
// если адрес не разбирается. Им подписываются события телеметрии движка о
// самом хранилище.
func (c *ClickHouse) Host() string {
	if u, err := url.Parse(c.base); err == nil && u.Hostname() != "" {
		return u.Hostname()
	}
	return "clickhouse"
}

// InsertEvents — события в argus.events (JSONEachRow). Так движок пишет
// собственную телеметрию, которую затем читает тем же путём, что и события
// коллекторов: правила ops видят её наравне с остальными источниками.
func (c *ClickHouse) InsertEvents(ctx context.Context, events []*model.Event) error {
	rows := make([]any, len(events))
	for i := range events {
		rows[i] = events[i]
	}
	return c.insert(ctx, "events", rows)
}

func (c *ClickHouse) do(ctx context.Context, query string, body io.Reader, params map[string]string) ([]byte, error) {
	q := url.Values{}
	q.Set("database", c.db)
	q.Set("date_time_input_format", "best_effort")
	q.Set("input_format_skip_unknown_fields", "1")
	// UInt64 иначе приходит строкой в кавычках и ломает разбор JSON
	q.Set("output_format_json_quote_64bit_integers", "0")
	for k, v := range params {
		q.Set("param_"+k, v)
	}
	var req *http.Request
	var err error
	if body != nil {
		q.Set("query", query)
		req, err = http.NewRequestWithContext(ctx, http.MethodPost, c.base+"/?"+q.Encode(), body)
	} else {
		req, err = http.NewRequestWithContext(ctx, http.MethodPost, c.base+"/?"+q.Encode(), strings.NewReader(query))
	}
	if err != nil {
		return nil, err
	}
	req.SetBasicAuth(c.user, c.pass)
	resp, err := c.http.Do(req)
	if err != nil {
		return nil, fmt.Errorf("clickhouse: %w", err)
	}
	defer resp.Body.Close()
	const maxResponseBytes = 256 << 20
	out, err := io.ReadAll(io.LimitReader(resp.Body, maxResponseBytes+1))
	if err != nil {
		return nil, fmt.Errorf("clickhouse response: %w", err)
	}
	if len(out) > maxResponseBytes {
		return nil, fmt.Errorf("clickhouse response exceeds %d bytes", maxResponseBytes)
	}
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("clickhouse %s: %s", resp.Status, strings.TrimSpace(string(out[:min(len(out), 400)])))
	}
	if code := resp.Header.Get("X-ClickHouse-Exception-Code"); code != "" && code != "0" {
		return nil, fmt.Errorf("clickhouse exception %s: %s", code, strings.TrimSpace(string(out[:min(len(out), 400)])))
	}
	if loc := responseException.FindIndex(out); loc != nil {
		return nil, fmt.Errorf("clickhouse: %s", strings.TrimSpace(string(out[loc[0]:min(len(out), loc[0]+400)])))
	}
	return out, nil
}

func (c *ClickHouse) insert(ctx context.Context, table string, rows []any) error {
	if len(rows) == 0 {
		return nil
	}
	var body bytes.Buffer
	enc := json.NewEncoder(&body)
	for _, r := range rows {
		if err := enc.Encode(r); err != nil {
			return err
		}
	}
	_, err := c.do(ctx, fmt.Sprintf("INSERT INTO %s FORMAT JSONEachRow", table), &body, nil)
	return err
}

// eventsSelectColumns — колонки события единой схемы в порядке model.Event;
// перечислены явно, чтобы SELECT * не тянул служебные колонки будущих миграций.
func eventsSelectColumns() string {
	return `ts, source, source_class, vendor, product, action, outcome, severity,
	       actor_name, actor_kind, object, node, session_id, src_ip, src_port, dst_ip, dst_port, proto,
	       bytes, packets, value, unit, pii, attrs, raw`
}

// EventsSince — события, принятые после курсора received_at (не ts: у
// источников свои часы, а курсор должен быть монотонным).
func (c *ClickHouse) EventsSince(ctx context.Context, cursor time.Time, limit int) ([]*model.Event, time.Time, error) {
	out, err := c.do(ctx, `SELECT `+eventsSelectColumns()+`, toString(received_at) AS received_str
	FROM events WHERE received_at > {cursor:DateTime} ORDER BY received_at LIMIT {limit:UInt32}
	FORMAT JSONEachRow`, nil, map[string]string{
		"cursor": cursor.UTC().Format("2006-01-02 15:04:05"), "limit": fmt.Sprint(limit)})
	if err != nil {
		return nil, cursor, err
	}
	var events []*model.Event
	last := cursor
	for _, line := range bytes.Split(out, []byte("\n")) {
		if len(bytes.TrimSpace(line)) == 0 {
			continue
		}
		var row struct {
			model.Event
			ReceivedAt string `json:"received_str"`
		}
		if err := json.Unmarshal(line, &row); err != nil {
			continue
		}
		e := row.Event
		if t, err := time.Parse("2006-01-02 15:04:05", row.ReceivedAt); err == nil {
			e.ReceivedAt = t
			if t.After(last) {
				last = t
			}
		}
		events = append(events, &e)
	}
	return events, last, nil
}

// OpenIncidents — незакрытые инциденты и максимальный номер.
func (c *ClickHouse) OpenIncidents(ctx context.Context) ([]incidents.Incident, int, error) {
	// Все колонки: инцидент из памяти потом записывается целиком, и пустой
	// first_ts/chain из усечённой выборки ронял весь батч INSERT (CANNOT_PARSE_DATETIME).
	out, err := c.do(ctx, `SELECT * FROM incidents_current FORMAT JSONEachRow`, nil, nil)
	if err != nil {
		return nil, 0, err
	}
	var open []incidents.Incident
	maxN := 0
	for _, line := range bytes.Split(out, []byte("\n")) {
		if len(bytes.TrimSpace(line)) == 0 {
			continue
		}
		var inc incidents.Incident
		if err := json.Unmarshal(line, &inc); err != nil {
			continue
		}
		var n int
		fmt.Sscanf(inc.IncidentID, "INC-%d", &n)
		if n > maxN {
			maxN = n
		}
		if inc.Status != incidents.StatusClosed && inc.Status != incidents.StatusFalsePositive {
			open = append(open, inc)
		}
	}
	return open, maxN, nil
}

// ResponseRow — запись журнала реагирования (response_log).
type ResponseRow struct {
	TS         string `json:"ts"`
	IncidentID string `json:"incident_id"`
	RuleID     string `json:"rule_id"`
	IP         string `json:"ip"`
	Mode       string `json:"mode"` // ids | simulate | ips | manual
	Executor   string `json:"executor"`
	DryRun     uint8  `json:"dry_run"`
	OK         uint8  `json:"ok"`
	Detail     string `json:"detail"`
	Reason     string `json:"reason"`
	Actor      string `json:"actor"` // argus-engine | оператор
}

func (c *ClickHouse) InsertResponses(ctx context.Context, rows []ResponseRow) error {
	anyRows := make([]any, len(rows))
	for i := range rows {
		anyRows[i] = rows[i]
	}
	return c.insert(ctx, "response_log", anyRows)
}

// ConsoleSetting — значение настройки, выставленной из консоли (console_settings), "" если нет.
func (c *ClickHouse) ConsoleSetting(ctx context.Context, key string) (string, error) {
	out, err := c.do(ctx, `SELECT argMax(value, updated_at) AS value FROM console_settings
	WHERE key = {key:String} GROUP BY key FORMAT JSONEachRow`, nil, map[string]string{"key": key})
	if err != nil {
		return "", err
	}
	var row struct {
		Value string `json:"value"`
	}
	if len(bytes.TrimSpace(out)) == 0 {
		return "", nil
	}
	if err := json.Unmarshal(bytes.TrimSpace(bytes.Split(out, []byte("\n"))[0]), &row); err != nil {
		return "", err
	}
	return row.Value, nil
}

// Disk — свободное место на дисках ClickHouse (system.disks): переполненный
// диск останавливает приём событий, и SIEM должна заметить это первой.
type Disk struct {
	Name  string `json:"name"`
	Path  string `json:"path"`
	Free  uint64 `json:"free_space"`
	Total uint64 `json:"total_space"`
}

func (c *ClickHouse) Disks(ctx context.Context) ([]Disk, error) {
	out, err := c.do(ctx, `SELECT name, path, free_space, total_space FROM system.disks
	WHERE total_space > 0 FORMAT JSONEachRow SETTINGS output_format_json_quote_64bit_integers=0`, nil, nil)
	if err != nil {
		return nil, err
	}
	var disks []Disk
	for _, line := range bytes.Split(out, []byte("\n")) {
		if len(bytes.TrimSpace(line)) == 0 {
			continue
		}
		var d Disk
		if err := json.Unmarshal(line, &d); err != nil {
			continue
		}
		disks = append(disks, d)
	}
	return disks, nil
}

// OperatorState — актуальные статус/владелец/заметка инцидентов, как их
// видит консоль. Движок держит инциденты в памяти и без этой сверки
// перезаписал бы своей старой копией то, что дежурный поменял в консоли.
type OperatorState struct {
	IncidentID string `json:"incident_id"`
	Status     string `json:"status"`
	Owner      string `json:"owner"`
	Note       string `json:"note"`
	UpdatedAt  string `json:"updated_max"`
}

// chArray — литерал Array(String) для параметра запроса {ids:Array(String)}.
func chArray(items []string) string {
	quoted := make([]string, len(items))
	for i, s := range items {
		quoted[i] = "'" + strings.NewReplacer(`\`, `\\`, `'`, `\'`).Replace(s) + "'"
	}
	return "[" + strings.Join(quoted, ",") + "]"
}

func (c *ClickHouse) OperatorStates(ctx context.Context, ids []string) (map[string]OperatorState, error) {
	res := map[string]OperatorState{}
	if len(ids) == 0 {
		return res, nil
	}
	out, err := c.do(ctx, `SELECT incident_id, status, owner, note, toString(updated_at) AS updated_max
	FROM incidents_current WHERE incident_id IN {ids:Array(String)} FORMAT JSONEachRow`, nil,
		map[string]string{"ids": chArray(ids)})
	if err != nil {
		return nil, err
	}
	for _, line := range bytes.Split(out, []byte("\n")) {
		if len(bytes.TrimSpace(line)) == 0 {
			continue
		}
		var st OperatorState
		if err := json.Unmarshal(line, &st); err != nil {
			continue
		}
		res[st.IncidentID] = st
	}
	return res, nil
}

func (c *ClickHouse) InsertIncidents(ctx context.Context, incs []*incidents.Incident) error {
	rows := make([]any, len(incs))
	for i := range incs {
		rows[i] = incs[i]
	}
	return c.insert(ctx, "incidents", rows)
}

type Verdict struct {
	Missing        string   `json:"missing"`
	Actions        []string `json:"actions"`
	ConfidenceKind string   `json:"confidence_kind"`
	IncidentID     string   `json:"incident_id"`
	EvaluatedAt    string   `json:"evaluated_at"`
	Profile        string   `json:"profile"`
	Model          string   `json:"model"`
	SummaryRU      string   `json:"summary_ru"`
	Evidence       []string `json:"evidence"`
	FirstAction    string   `json:"first_action"`
	Confidence     float32  `json:"confidence"`
	Shown          uint8    `json:"shown"`
	ShownReason    string   `json:"shown_reason"` // почему показан/скрыт; колонка появится миграцией, до неё поле пропускается (skip_unknown_fields)
	Tokens         uint32   `json:"tokens"`
	LatencyMs      uint32   `json:"latency_ms"`
	Error          string   `json:"error"`
}

func (c *ClickHouse) InsertVerdict(ctx context.Context, v Verdict) error {
	return c.insert(ctx, "incident_verdicts", []any{v})
}

// EventsAround — события класса вокруг инцидента: по узлу и/или субъекту/адресу.
func (c *ClickHouse) EventsAround(ctx context.Context, class, node, actor, ip string, from, to time.Time, limit int) ([]*model.Event, error) {
	where := "source_class = {class:String} AND ts BETWEEN {from:DateTime64(3)} AND {to:DateTime64(3)}"
	params := map[string]string{"class": class, "from": from.UTC().Format("2006-01-02 15:04:05.000"),
		"to": to.UTC().Format("2006-01-02 15:04:05.000"), "limit": fmt.Sprint(limit)}
	var by []string
	if node != "" {
		by = append(by, "node = {node:String}")
		params["node"] = node
	}
	if actor != "" {
		by = append(by, "actor_name = {actor:String}")
		params["actor"] = actor
	}
	if ip != "" {
		by = append(by, "src_ip = {ip:String}")
		params["ip"] = ip
	}
	if len(by) == 0 {
		return nil, nil
	}
	where += " AND (" + strings.Join(by, " OR ") + ")"
	out, err := c.do(ctx, `SELECT ts, source, source_class, action, outcome, severity, actor_name, actor_kind, object, node,
	       src_ip, src_port, dst_ip, dst_port, proto, bytes, packets, value, unit, pii, attrs
	FROM events WHERE `+where+` ORDER BY ts LIMIT {limit:UInt32} FORMAT JSONEachRow`, nil, params)
	if err != nil {
		return nil, err
	}
	var events []*model.Event
	for _, line := range bytes.Split(out, []byte("\n")) {
		if len(bytes.TrimSpace(line)) == 0 {
			continue
		}
		var e model.Event
		if json.Unmarshal(line, &e) == nil {
			events = append(events, &e)
		}
	}
	return events, nil
}

// SimilarIncidents — закрытые инциденты того же правила или субъекта/узла за 90 дней.
func (c *ClickHouse) SimilarIncidents(ctx context.Context, ruleID, actor, node, exceptID string, limit int) ([]string, error) {
	out, err := c.do(ctx, `SELECT incident_id, status, rule_title, note, created_at FROM incidents_current
	WHERE created_at >= now() - INTERVAL 90 DAY
	  AND status IN ('closed', 'false_positive') AND incident_id != {except:String}
	  AND (rule_id = {rule:String} OR (actor_name = {actor:String} AND actor_name != '') OR (node = {node:String} AND node != ''))
	ORDER BY created_at DESC LIMIT {limit:UInt32} FORMAT JSONEachRow`, nil,
		map[string]string{"rule": ruleID, "actor": actor, "node": node, "except": exceptID, "limit": fmt.Sprint(limit)})
	if err != nil {
		return nil, err
	}
	var lines []string
	for _, line := range bytes.Split(out, []byte("\n")) {
		if len(bytes.TrimSpace(line)) == 0 {
			continue
		}
		var r struct {
			IncidentID string `json:"incident_id"`
			Status     string `json:"status"`
			RuleTitle  string `json:"rule_title"`
			Note       string `json:"note"`
			CreatedAt  string `json:"created_at"`
		}
		if err := json.Unmarshal(line, &r); err != nil {
			return nil, fmt.Errorf("similar incident: %w", err)
		}
		note := strings.ReplaceAll(strings.TrimSpace(r.Note), "\n", " ")
		if chars := []rune(note); len(chars) > 120 {
			note = string(chars[:119]) + "…"
		}
		lines = append(lines, fmt.Sprintf("%s · %s · %s · %s · %s", r.IncidentID, r.CreatedAt[:min(10, len(r.CreatedAt))], r.Status, r.RuleTitle, note))
	}
	return lines, nil
}

// GetIncident — последняя версия инцидента по идентификатору.
func (c *ClickHouse) GetIncident(ctx context.Context, id string) (*incidents.Incident, error) {
	return c.CurrentIncident(ctx, id)
}

// Exceptions — активные исключения из правил (обратная связь «ложное»).
func (c *ClickHouse) Exceptions(ctx context.Context) (map[string][]eval.Exception, error) {
	out, err := c.do(ctx, `SELECT rule_id, field, value FROM rule_exceptions
	    GROUP BY rule_id, field, value HAVING argMax(active, created_at) = 1 FORMAT JSONEachRow`, nil, nil)
	if err != nil {
		return nil, err
	}
	res := map[string][]eval.Exception{}
	for _, line := range bytes.Split(out, []byte("\n")) {
		if len(bytes.TrimSpace(line)) == 0 {
			continue
		}
		var r struct{ RuleID, Field, Value string }
		var raw map[string]string
		if json.Unmarshal(line, &raw) == nil {
			r.RuleID, r.Field, r.Value = raw["rule_id"], raw["field"], raw["value"]
			res[r.RuleID] = append(res[r.RuleID], eval.Exception{Field: r.Field, Value: r.Value})
		}
	}
	return res, nil
}
