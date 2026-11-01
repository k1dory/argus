// Package sink пишет события и heartbeat коллекторов в ClickHouse по HTTP
// (JSONEachRow) — тот же путь, что у shipper и policyd.
package sink

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

// Inserter — то, что нужно писателю от хранилища; ClickHouse реализует,
// тесты подменяют.
type Inserter interface {
	InsertEvents(ctx context.Context, rows []any) error
	InsertRejects(ctx context.Context, rows []Reject) error
}

// Reject — строка argus.ingest_rejects: событие, которое ClickHouse не принял
// (ядовитая строка после бисекции батча).
type Reject struct {
	TS     string `json:"ts"`
	Source string `json:"source"`
	Reason string `json:"reason"`
	Raw    string `json:"raw"`
}

// Error — ответ ClickHouse не 200: HTTP-статус и код исключения из тела
// («Code: 27. DB::Exception: Cannot parse input…»).
type Error struct {
	Table  string
	Status int
	Code   int
	Msg    string
}

// Error — без текста исключения: ClickHouse цитирует в нём данные строки (событие),
// а Error() попадает в журнал. Полный текст — Detail(), только для ingest_rejects.
func (e *Error) Error() string {
	return fmt.Sprintf("clickhouse %s: HTTP %d code %d", e.Table, e.Status, e.Code)
}

// Detail — ошибка вместе с текстом ClickHouse: для таблицы отказов (там же лежит
// исходная строка), не для журнала.
func (e *Error) Detail() string {
	return e.Error() + ": " + e.Msg
}

var codeRe = regexp.MustCompile(`Code:\s*(\d+)`)

// Коды ClickHouse, при которых повтор того же батча бессмыслен — виновата строка:
// 27 CANNOT_PARSE_INPUT_ASSERTION_FAILED, 6 CANNOT_PARSE_TEXT, 53 TYPE_MISMATCH,
// 117 INCORRECT_DATA. Плюс всё, где в тексте «Cannot parse».
var permanentCodes = map[int]bool{6: true, 27: true, 53: true, 117: true}

// IsPermanent — ошибка данных (батч надо делить), а не транспорта (батч надо повторить).
func IsPermanent(err error) bool {
	var ce *Error
	if !errors.As(err, &ce) {
		return false
	}
	return permanentCodes[ce.Code] || strings.Contains(ce.Msg, "Cannot parse")
}

// Коды, при которых батч «делимый»: повтор целиком бессмыслен, но и виновата
// не обязательно одна строка — половины могут пройти. 241 MEMORY_LIMIT_EXCEEDED,
// 131 TOO_LARGE_STRING_SIZE, 321 VALUE_IS_OUT_OF_RANGE_OF_DATA_TYPE,
// 349 CANNOT_CONVERT_TYPE, 69 ARGUMENT_OUT_OF_BOUND, 70 CANNOT_CONVERT_TYPE.
var divisibleCodes = map[int]bool{241: true, 131: true, 321: true, 349: true, 69: true, 70: true}

// IsDivisible — третья категория между транспортом и ядовитой строкой: батч
// делится пополам до размера 1, на размере 1 — dead-letter. Сюда же HTTP 4xx
// без кода исключения: сервер отверг запрос, повтор того же батча — livelock.
func IsDivisible(err error) bool {
	var ce *Error
	if !errors.As(err, &ce) {
		return false
	}
	if IsPermanent(err) {
		return false
	}
	return divisibleCodes[ce.Code] || (ce.Code == 0 && ce.Status >= 400 && ce.Status < 500)
}

// IsUnknownTable — таблицы нет (миграция не накатана): лог без повторов.
func IsUnknownTable(err error) bool {
	var ce *Error
	return errors.As(err, &ce) && (ce.Code == 60 || ce.Code == 81)
}

type ClickHouse struct {
	base, db, user, pass string
	http                 *http.Client
}

func New(base, db, user, pass string) *ClickHouse {
	return &ClickHouse{base: strings.TrimRight(base, "/"), db: db, user: user, pass: pass,
		http: &http.Client{Timeout: 30 * time.Second}}
}

func (c *ClickHouse) insert(ctx context.Context, table string, rows []any) error {
	if len(rows) == 0 {
		return nil
	}
	var body bytes.Buffer
	enc := json.NewEncoder(&body)
	for _, r := range rows {
		if err := enc.Encode(r); err != nil {
			// строка не сериализуется — это тоже «ядовитая» строка, а не транспорт
			return &Error{Table: table, Code: 117, Msg: "Cannot parse row for JSON: " + err.Error()}
		}
	}
	q := url.Values{}
	q.Set("query", fmt.Sprintf("INSERT INTO %s.%s FORMAT JSONEachRow", c.db, table))
	q.Set("date_time_input_format", "best_effort")
	q.Set("input_format_skip_unknown_fields", "1")
	// async_insert: сервер сам склеивает вставки в большие блоки — на порядок
	// меньше частей MergeTree при тысячах EPS; ждём записи в буфер, не merge.
	q.Set("async_insert", "1")
	q.Set("wait_for_async_insert", "1")
	// С async_insert+wait_for_async_insert ответ приходит после записи в буфер вставок;
	// wait_end_of_query дополнительно буферизует ответ, и ошибка — HTTP-статусом.
	q.Set("wait_end_of_query", "1")
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.base+"/?"+q.Encode(), &body)
	if err != nil {
		return err
	}
	req.SetBasicAuth(c.user, c.pass)
	resp, err := c.http.Do(req)
	if err != nil {
		return fmt.Errorf("clickhouse %s: %w", table, err)
	}
	defer resp.Body.Close()
	msg, readErr := io.ReadAll(io.LimitReader(resp.Body, (4<<10)+1))
	// Ошибка ClickHouse распознаётся до проверки размера: длинное исключение (27, 241)
	// иначе теряло код и уходило в транспортные повторы вместо деления батча/отказа.
	if code := resp.Header.Get("X-ClickHouse-Exception-Code"); resp.StatusCode != http.StatusOK || (code != "" && code != "0") || codeRe.Match(msg) {
		return parseError(table, resp.StatusCode, code, string(msg[:min(len(msg), 4<<10)]))
	}
	if readErr != nil {
		return fmt.Errorf("clickhouse %s response: %w", table, readErr)
	}
	if len(msg) > 4<<10 {
		return fmt.Errorf("clickhouse %s: oversized insert response", table)
	}
	return nil
}

func parseError(table string, status int, hdrCode, body string) *Error {
	e := &Error{Table: table, Status: status, Msg: strings.TrimSpace(body)}
	if n, err := strconv.Atoi(strings.TrimSpace(hdrCode)); err == nil {
		e.Code = n
	} else if m := codeRe.FindStringSubmatch(body); m != nil {
		e.Code, _ = strconv.Atoi(m[1])
	}
	return e
}

func (c *ClickHouse) InsertEvents(ctx context.Context, rows []any) error {
	return c.insert(ctx, "events", rows)
}

func (c *ClickHouse) InsertRejects(ctx context.Context, rows []Reject) error {
	anyRows := make([]any, len(rows))
	for i := range rows {
		anyRows[i] = rows[i]
	}
	return c.insert(ctx, "ingest_rejects", anyRows)
}

type HealthRow struct {
	Source   string `json:"source"`
	Listener string `json:"listener"`
	SeenAt   string `json:"seen_at"`
	Events1m uint32 `json:"events_1m"`
}

func (c *ClickHouse) InsertHealth(ctx context.Context, rows []HealthRow) error {
	anyRows := make([]any, len(rows))
	for i := range rows {
		anyRows[i] = rows[i]
	}
	return c.insert(ctx, "collector_health", anyRows)
}
