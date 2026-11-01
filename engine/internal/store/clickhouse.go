// Package store — чтение событий и запись инцидентов/вердиктов в ClickHouse
// по HTTP (JSONEachRow), только стандартная библиотека.
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

	"github.com/devitex-soft/argus/engine/internal/eval"
	"github.com/devitex-soft/argus/engine/internal/incidents"
	"github.com/devitex-soft/argus/engine/internal/model"
)

type ClickHouse struct {
	base, db, user, pass string
	http                 *http.Client
	idStamps             stamps // метки updated_at паспорта (identity.go)
}

// Исключение после HTTP 200 (страховка: с wait_end_of_query=1 ClickHouse 24.8 отвечает
// на ошибку HTTP-статусом и X-ClickHouse-Exception-Code). Формы сервера: отдельная
// строка «Code: N. DB::Exception», «Poco::Exception. Code: N,», «std::exception. Code:
// N,» и хвост JSONEachRow {"exception": "Code: …"}. JSONEachRow экранирует переводы
// строк в значениях, а колонок с именем exception в запросах движка нет.
var responseException = regexp.MustCompile(`(?m)^(?:\{"exception":\s*"|Poco::Exception\. |std::exception\. )?Code:\s*\d+[.,]`)

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
	// Ответ буферизуется на сервере до конца запроса: ошибка посреди выдачи приходит
	// HTTP-ошибкой, а не хвостом тела со статусом 200 (неполная страница EventsSince
	// сдвинула бы курсор и потеряла события).
	q.Set("wait_end_of_query", "1")
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
		return nil, chError(resp, out)
	}
	if code := resp.Header.Get("X-ClickHouse-Exception-Code"); code != "" && code != "0" {
		return nil, chError(resp, out)
	}
	if loc := responseException.FindIndex(out); loc != nil {
		return nil, chError(resp, out[loc[0]:])
	}
	return out, nil
}

var exceptionCode = regexp.MustCompile(`Code:\s*(\d+)`)

// chError — ошибка ClickHouse без текста исключения: он цитирует данные запроса
// (вердикт, строку события), а ошибка уходит в журнал движка. Статус, код (из
// заголовка или тела) и query_id; полный текст — в system.query_log.
func chError(resp *http.Response, body []byte) error {
	code := strings.TrimSpace(resp.Header.Get("X-ClickHouse-Exception-Code"))
	if _, err := strconv.Atoi(code); err != nil || code == "0" {
		code = ""
		if m := exceptionCode.FindSubmatch(body); m != nil {
			code = string(m[1])
		}
	}
	msg := "clickhouse HTTP " + strconv.Itoa(resp.StatusCode)
	if code != "" {
		msg += " code " + code
	}
	if id := resp.Header.Get("X-ClickHouse-Query-Id"); id != "" && len(id) <= 64 {
		msg += " query_id " + id
	}
	return errors.New(msg)
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
// raw в движке не используется (правила смотрят на поля и attrs), а это самая
// тяжёлая колонка: при шторме NetFlow именно она раздувала память опроса. Её
// нет в выборке совсем — не `” AS raw`: алиас в SELECT ClickHouse подставляет
// во все выражения запроса с этим именем, и хеш строки по raw переставал
// различать события с разным исходным логом (см. миграцию 0029).
func eventsSelectColumns() string {
	return `ts, source, source_class, vendor, product, action, outcome, severity,
	       actor_name, actor_kind, object, node, session_id, src_ip, src_port, dst_ip, dst_port, proto,
	       bytes, packets, value, unit, pii, attrs`
}

/* ===== курсор чтения событий =====
   received_at — секундный DateTime, который ставит база при INSERT. Читать
   «строго после последней секунды» нельзя: вставка той же секунды, пришедшая
   после опроса, терялась бы, как и остаток секунды за LIMIT. Поэтому курсор —
   секунда, читаемая включительно, плюс множество ключей (event_id) уже
   обработанных строк этой секунды (дедупликация). Если LIMIT сработал внутри
   одной секунды, страницы дочитываются по ключу сразу (More), а на следующем
   опросе секунда перечитывается целиком с дедупликацией по Seen — поздняя
   вставка с меньшим ключом не теряется. Строки моложе cursorSettle не берутся:
   вставка получает received_at в начале INSERT, а видна по его завершении —
   секунда должна «устояться», иначе её хвост остался бы за курсором.

   Догон читается срезами received_at ∈ [At, At+Step): запрос с открытым верхом
   после рестарта сортировал весь хвост ради одной страницы (6,8 млн строк и
   общий лимит памяти ClickHouse на стенде). Срез подстраивается под плотность
   потока: упёрся в LIMIT — вдвое уже, вернул меньше четверти — вдвое шире. */

// Cursor — позиция чтения argus.events.
type Cursor struct {
	At   time.Time           // секунда received_at, читается включительно
	Hash uint64              // продолжение внутри секунды At в пределах одного опроса (event_id); 0 — с начала секунды
	Seen map[uint64]struct{} // event_id строк секунды At, уже отданных вызывающему
	More bool                // страница упёрлась в LIMIT или срез догона не последний: дочитать сразу
	Step time.Duration       // ширина среза received_at для следующего запроса; 0 — sliceDefault
}

// StartCursor — курсор с начала секунды at.
func StartCursor(at time.Time) Cursor {
	return Cursor{At: at.UTC().Truncate(time.Second), Seen: map[uint64]struct{}{}, Step: sliceDefault}
}

// cursorSettle — сколько секунда должна «устояться», прежде чем курсор её
// пройдёт: строки с received_at моложе этого откладываются до следующего опроса.
const cursorSettle = 3 * time.Second

// Ширина среза received_at одного запроса: начальная и пределы подстройки.
const (
	sliceDefault = 5 * time.Minute
	sliceMin     = time.Second
	sliceMax     = time.Hour
)

// rowHashExpr — устойчивый ключ строки события по всем колонкам единой схемы
// (своего id у events нет); attrs — по отсортированным ключам, чтобы ключ не
// зависел от порядка в Map. С миграции 0029 это выражение колонки event_id
// (MATERIALIZED): движок читает её, а не считает хеш в запросе. Внутренний ключ
// курсора движка, не идентификатор для внешних систем.
const rowHashExpr = "cityHash64(received_at, ts, source, source_class, action, outcome, severity, actor_name, actor_kind, object, node, session_id, " +
	"src_ip, src_port, dst_ip, dst_port, proto, bytes, packets, value, unit, pii, " +
	"arrayStringConcat(arrayMap(k -> concat(k, '=', attrs[k]), arraySort(mapKeys(attrs))), ';'), raw)"

// eventRow — строка выборки EventsSince до разбора курсора.
type eventRow struct {
	Event      *model.Event
	ReceivedAt time.Time
	Hash       uint64
}

// sliceEnd — верхняя граница среза (не включительно): At+Step, но не дальше
// последней устоявшейся секунды; ok=false — читать пока нечего.
func sliceEnd(cur Cursor, now time.Time) (time.Time, bool) {
	step := cur.Step
	if step <= 0 {
		step = sliceDefault
	}
	upto := cur.At.Add(step)
	if limit := now.UTC().Add(-cursorSettle).Truncate(time.Second).Add(time.Second); upto.After(limit) {
		upto = limit
	}
	return upto, upto.After(cur.At)
}

// EventsSince — события от курсора (по received_at, не ts: у источников свои
// часы, а курсор должен быть монотонным) в пределах одного среза. Возвращает ещё
// не отданные события и следующий курсор; см. advanceCursor и finishSlice.
func (c *ClickHouse) EventsSince(ctx context.Context, cur Cursor, limit int) ([]*model.Event, Cursor, error) {
	now := time.Now()
	upto, ok := sliceEnd(cur, now)
	if !ok {
		cur.More = false
		return nil, cur, nil
	}
	out, err := c.do(ctx, `SELECT `+eventsSelectColumns()+`, toString(received_at) AS received_str, event_id
	FROM events
	WHERE received_at >= {cursor:DateTime} AND received_at < {upto:DateTime}
	  AND (received_at > {cursor:DateTime} OR event_id >= {hash:UInt64})
	ORDER BY received_at, event_id LIMIT {limit:UInt32}
	FORMAT JSONEachRow`, nil, map[string]string{
		"cursor": cur.At.UTC().Format("2006-01-02 15:04:05"), "upto": upto.UTC().Format("2006-01-02 15:04:05"),
		"hash": fmt.Sprint(cur.Hash), "limit": fmt.Sprint(limit)})
	if err != nil {
		return nil, cur, err
	}
	var rows []eventRow
	for _, line := range bytes.Split(out, []byte("\n")) {
		if len(bytes.TrimSpace(line)) == 0 {
			continue
		}
		var row struct {
			model.Event
			ReceivedAt string `json:"received_str"`
			Hash       uint64 `json:"event_id"`
		}
		if err := json.Unmarshal(line, &row); err != nil {
			continue
		}
		e := row.Event
		t, err := time.Parse("2006-01-02 15:04:05", row.ReceivedAt)
		if err != nil {
			// Без received_at строку не разместить на оси курсора: отдаём как
			// есть, в дедупликации она не участвует.
			e.ReceivedAt = time.Time{}
		} else {
			e.ReceivedAt = t
		}
		rows = append(rows, eventRow{Event: &e, ReceivedAt: t, Hash: row.Hash})
	}
	events, next := advanceCursor(cur, rows, limit, now)
	return events, finishSlice(cur, next, len(rows), limit, upto, now), nil
}

// finishSlice — куда встать после среза [cur.At, upto) и какой ширины брать
// следующий. Страница упёрлась в LIMIT — курсор уже внутри среза (advanceCursor),
// срез сужается. Иначе срез прочитан целиком:
//   - срез в прошлом (upto раньше устоявшейся границы): курсор переходит на upto
//     с пустым Seen — иначе пустой срез в прошлом не сдвинул бы курсор никогда;
//   - срез у live-края (upto — устоявшаяся граница), и в нём были строки: курсор
//     остаётся на последней прочитанной секунде с её Seen и Hash = 0. Следующий
//     опрос перечитает эту секунду целиком, дедупликация отдаст только новое —
//     INSERT той же секунды, завершившийся после чтения, с меньшим event_id не
//     теряется. Переход на upto здесь сбрасывал Seen и отменял это перечитывание.
//     Диапазон чтения остаётся ограниченным: [At, min(At+Step, граница));
//   - пустой срез у края — как в прошлом: курсор на upto (перечитывать нечего).
//
// More — когда до устоявшейся границы ещё есть срезы.
func finishSlice(cur, next Cursor, nrows, limit int, upto, now time.Time) Cursor {
	step := cur.Step
	if step <= 0 {
		step = sliceDefault
	}
	if limit > 0 && nrows >= limit {
		next.Step = max(step/2, sliceMin)
		return next
	}
	if limit > 0 && nrows < limit/4 {
		step = min(step*2, sliceMax)
	}
	settledEnd := now.UTC().Add(-cursorSettle).Truncate(time.Second).Add(time.Second)
	atEdge := !upto.Before(settledEnd)
	switch {
	case atEdge && len(next.Seen) > 0:
		next.Hash = 0 // перечитать последнюю секунду с начала; Seen отсеет отданное
	case upto.After(next.At):
		next = Cursor{At: upto, Seen: map[uint64]struct{}{}}
	}
	next.Step = step
	next.More = !atEdge
	return next
}

// advanceCursor — какие строки выборки отдать и куда сдвинуть курсор.
//   - строки моложе now − cursorSettle откладываются (секунда ещё не устоялась);
//   - строки секунды cur.At с хешем из cur.Seen уже отданы — пропускаются;
//   - выборка упёрлась в LIMIT и последняя секунда моложе cur.At: она могла
//     быть прочитана не целиком — её строки откладываются, курсор встаёт на её
//     начало, More — дочитать сразу;
//   - выборка упёрлась в LIMIT внутри одной секунды (> limit строк за секунду):
//     всё отдаётся, продолжение с максимального хеша страницы, включая уже
//     отданные из Seen (More); когда страница не
//     полная, Hash сбрасывается — следующий опрос перечитает секунду с начала,
//     дедупликация по Seen отдаст только новое;
//   - иначе курсор — последняя секунда выборки, Seen — её строки.
func advanceCursor(cur Cursor, rows []eventRow, limit int, now time.Time) ([]*model.Event, Cursor) {
	settled := now.UTC().Add(-cursorSettle).Truncate(time.Second)
	truncated := limit > 0 && len(rows) >= limit
	k := 0
	for k < len(rows) && !rows[k].ReceivedAt.After(settled) {
		k++
	}
	if k < len(rows) {
		rows, truncated = rows[:k], false // отрезанный хвост — только неустоявшиеся секунды
	}
	if len(rows) == 0 {
		cur.More = false
		return nil, cur
	}
	last := cur.At
	for _, r := range rows {
		if r.ReceivedAt.After(last) {
			last = r.ReceivedAt
		}
	}
	deferLast := truncated && last.After(cur.At)
	next := Cursor{At: last, Seen: map[uint64]struct{}{}, More: truncated}
	if last.Equal(cur.At) {
		for h := range cur.Seen {
			next.Seen[h] = struct{}{}
		}
	}
	var out []*model.Event
	for _, r := range rows {
		if deferLast && r.ReceivedAt.Equal(last) {
			continue
		}
		// Продолжение двигается и по уже отданным строкам: страница целиком из
		// Seen иначе оставляла бы Hash на месте, и тот же LIMIT перечитывал бы
		// её бесконечно, не доходя до следующих секунд.
		if r.ReceivedAt.Equal(next.At) && truncated && !deferLast && r.Hash > next.Hash {
			next.Hash = r.Hash
		}
		if r.ReceivedAt.Equal(cur.At) {
			if _, ok := cur.Seen[r.Hash]; ok {
				continue
			}
		}
		out = append(out, r.Event)
		if r.ReceivedAt.Equal(next.At) {
			next.Seen[r.Hash] = struct{}{}
		}
	}
	return out, next
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
	if err := c.restoreGroupKeys(ctx, open); err != nil {
		return nil, 0, err
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
	// Step — шаг автомата автоблокировки (миграция 0037): reserve | blocked | noop |
	// simulated | failed | exhausted | capped | refused | ids | manual; пусто — служебная
	// строка или ручное действие. По нему движок восстанавливает решения после рестарта.
	Step string `json:"step"`
	// Until — срок исключения адреса из автоблокировки (step=exclude, миграция 0038);
	// у остальных строк пусто, в колонке — значение по умолчанию.
	Until string `json:"until,omitempty"`
}

// ResponsesSince — строки response_log с адресом и шагом автомата не старше since,
// по времени. Ошибка ClickHouse, в том числе внутри ответа 200, возвращается без
// текста строки (в нём может быть цитата данных).
func (c *ClickHouse) ResponsesSince(ctx context.Context, since, excludeSince time.Time) ([]ResponseRow, error) {
	// ts без toString: псевдоним с именем колонки перекрыл бы её в WHERE, а DateTime
	// в JSONEachRow и так строка «2006-01-02 15:04:05».
	// Исключения адресов (step=exclude) — за excludeSince: исключение живёт дольше окна
	// решений, а его отзыв всегда позже самого исключения.
	out, err := c.do(ctx, `SELECT ts, incident_id, rule_id, ip, mode, executor, dry_run, ok, detail, reason, actor, step, until
		FROM response_log WHERE ip != '' AND step != '' AND (ts >= {since:DateTime} OR (step = 'exclude' AND ts >= {exclude_since:DateTime}))
		ORDER BY ts FORMAT JSONEachRow`, nil,
		map[string]string{"since": since.UTC().Format("2006-01-02 15:04:05"), "exclude_since": excludeSince.UTC().Format("2006-01-02 15:04:05")})
	if err != nil {
		return nil, fmt.Errorf("response_log: %w", err)
	}
	var rows []ResponseRow
	for _, line := range bytes.Split(out, []byte("\n")) {
		if len(bytes.TrimSpace(line)) == 0 {
			continue
		}
		var row struct {
			ResponseRow
			Exception string `json:"exception"`
		}
		// incident_id пустой — только у исключения адреса (step=exclude).
		if err := json.Unmarshal(line, &row); err != nil || row.Exception != "" || (row.IncidentID == "" && row.Step != "exclude") {
			return nil, errors.New("response_log: неожиданная строка ответа ClickHouse")
		}
		rows = append(rows, row.ResponseRow)
	}
	return rows, nil
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

// restoreGroupKeys — group_key открытых инцидентов (колонка incidents из
// миграции 0034, в incidents_current её нет). Ошибка ClickHouse, в том числе
// пришедшая внутри ответа 200 (строкой {"exception":…} у JSONEachRow), возвращается:
// с пустыми ключами разные группы одного узла слились бы в реестре под
// «правило|субъект|узел», а старт движка повторяет попытку. ID уходят пачками:
// параметры запроса идут в URL, а у ClickHouse он не длиннее 1 МиБ.
func (c *ClickHouse) restoreGroupKeys(ctx context.Context, open []incidents.Incident) error {
	const batch = 5000
	keys := map[string]string{}
	for lo := 0; lo < len(open); lo += batch {
		hi := min(lo+batch, len(open))
		ids := make([]string, 0, hi-lo)
		for i := lo; i < hi; i++ {
			ids = append(ids, open[i].IncidentID)
		}
		out, err := c.do(ctx, `SELECT incident_id, argMax(group_key, (updated_at, event_count, last_ts)) AS group_key
		FROM incidents WHERE incident_id IN {ids:Array(String)} GROUP BY incident_id FORMAT JSONEachRow`, nil,
			map[string]string{"ids": chArray(ids)})
		if err != nil {
			return fmt.Errorf("restore group_key: %w", err)
		}
		for _, line := range bytes.Split(out, []byte("\n")) {
			if len(bytes.TrimSpace(line)) == 0 {
				continue
			}
			var row struct {
				IncidentID string `json:"incident_id"`
				GroupKey   string `json:"group_key"`
				Exception  string `json:"exception"`
			}
			if err := json.Unmarshal(line, &row); err != nil || row.Exception != "" || row.IncidentID == "" {
				// Без текста строки: это может быть исключение с цитатой данных.
				return errors.New("restore group_key: неожиданная строка ответа ClickHouse")
			}
			keys[row.IncidentID] = row.GroupKey
		}
	}
	for i := range open {
		open[i].GroupKey = keys[open[i].IncidentID]
	}
	return nil
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
