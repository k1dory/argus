// Package store writes policy verdicts to ClickHouse over the HTTP interface
// (JSONEachRow), keeping the dependency footprint to the standard library.
package store

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"regexp"
	"strconv"
	"strings"
	"time"
)

// Статусы вердикта. unknown — политику не удалось применить (ошибка API,
// таймаут, ошибка eval): это не «соответствует», но и не «нарушение».
const (
	StatusPass    = "pass"
	StatusFail    = "fail"
	StatusUnknown = "unknown"
)

type VerdictRow struct {
	EvaluatedAt string   `json:"evaluated_at"`
	EntityType  string   `json:"entity_type"`
	EntityID    string   `json:"entity_id"`
	EntityName  string   `json:"entity_name"`
	Policy      string   `json:"policy"`
	Compliant   uint8    `json:"compliant"`
	Violations  []string `json:"violations"`
	// Status шлётся всегда: на схеме до миграции 0011 (без колонки) ClickHouse
	// отбрасывает поле благодаря input_format_skip_unknown_fields=1.
	Status string `json:"status"`
}

type ClickHouse struct {
	base string
	user string
	pass string
	db   string
	http *http.Client
}

func New(base, db, user, pass string) *ClickHouse {
	return &ClickHouse{
		base: strings.TrimRight(base, "/"),
		user: user,
		pass: pass,
		db:   db,
		http: &http.Client{Timeout: 30 * time.Second},
	}
}

// HasStatusColumn спрашивает у ClickHouse схему policy_verdicts: есть ли
// колонка status (миграция 0011). На INSERT не влияет — только для
// предупреждения в лог, что статус вердикта не сохраняется.
func (c *ClickHouse) HasStatusColumn(ctx context.Context) (bool, error) {
	q := url.Values{}
	q.Set("query", fmt.Sprintf("DESCRIBE TABLE %s.policy_verdicts FORMAT TSV", c.db))
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, c.base+"/?"+q.Encode(), nil)
	if err != nil {
		return false, err
	}
	req.SetBasicAuth(c.user, c.pass)
	resp, err := c.http.Do(req)
	if err != nil {
		return false, fmt.Errorf("clickhouse describe: %w", err)
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(io.LimitReader(resp.Body, 64<<10))
	if err != nil {
		return false, err
	}
	if resp.StatusCode != http.StatusOK {
		return false, chError("describe", resp, body)
	}
	for _, line := range strings.Split(string(body), "\n") {
		name, _, _ := strings.Cut(line, "\t")
		if strings.TrimSpace(name) == "status" {
			return true, nil
		}
	}
	return false, nil
}

func (c *ClickHouse) InsertVerdicts(ctx context.Context, rows []VerdictRow) error {
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
	q := url.Values{}
	q.Set("query", fmt.Sprintf("INSERT INTO %s.policy_verdicts FORMAT JSONEachRow", c.db))
	q.Set("date_time_input_format", "best_effort")
	q.Set("input_format_skip_unknown_fields", "1")

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.base+"/?"+q.Encode(), &body)
	if err != nil {
		return err
	}
	req.SetBasicAuth(c.user, c.pass)
	resp, err := c.http.Do(req)
	if err != nil {
		return fmt.Errorf("clickhouse insert: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		msg, _ := io.ReadAll(io.LimitReader(resp.Body, 4<<10))
		return chError("insert", resp, msg)
	}
	return nil
}

var exceptionCode = regexp.MustCompile(`Code:\s*(\d+)`)

// chError — ошибка ClickHouse без текста исключения: он цитирует данные (сущность
// политики), а ошибка уходит в журнал и в открытый /healthz. Статус, код и query_id;
// полный текст — в system.query_log.
func chError(op string, resp *http.Response, body []byte) error {
	code := strings.TrimSpace(resp.Header.Get("X-ClickHouse-Exception-Code"))
	if _, err := strconv.Atoi(code); err != nil || code == "0" {
		code = ""
		if m := exceptionCode.FindSubmatch(body); m != nil {
			code = string(m[1])
		}
	}
	msg := fmt.Sprintf("clickhouse %s: HTTP %d", op, resp.StatusCode)
	if code != "" {
		msg += " code " + code
	}
	if id := resp.Header.Get("X-ClickHouse-Query-Id"); id != "" && len(id) <= 64 {
		msg += " query_id " + id
	}
	return errors.New(msg)
}
