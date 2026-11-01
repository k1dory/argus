package store

// Живой ClickHouse: каждый запрос хранилища выполняется на настоящей базе со
// схемой из clickhouse/migrations. Сервер задаётся ARGUS_TEST_CLICKHOUSE_URL
// (+ _USER, _PASSWORD); без него тесты пропускаются. Миграции применяются по
// одному оператору, как migrate.sh --multiquery, и дважды — так проверяется и
// идемпотентность. Базу не чистим (её могут делить тесты консоли), поэтому
// фикстуры помечены случайным суффиксом и проверки не зависят от чужих строк.

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"testing"
	"time"

	"github.com/devitex-soft/argus/engine/internal/identity"
	"github.com/devitex-soft/argus/engine/internal/incidents"
	"github.com/devitex-soft/argus/engine/internal/model"
	"github.com/devitex-soft/argus/engine/internal/webhook"
)

func liveStore(t *testing.T) *ClickHouse {
	t.Helper()
	url := os.Getenv("ARGUS_TEST_CLICKHOUSE_URL")
	if url == "" {
		t.Skip("нет ARGUS_TEST_CLICKHOUSE_URL — тест живого ClickHouse пропущен")
	}
	user := os.Getenv("ARGUS_TEST_CLICKHOUSE_USER")
	if user == "" {
		user = "default"
	}
	return New(url, "argus", user, os.Getenv("ARGUS_TEST_CLICKHOUSE_PASSWORD"))
}

var commentLine = regexp.MustCompile(`(?m)^--.*$`)
var stmtSep = regexp.MustCompile(`;\s*\n`)

// migrationStatements — операторы файла миграции без комментариев, по порядку.
func migrationStatements(t *testing.T, path string) []string {
	t.Helper()
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	var out []string
	for _, s := range stmtSep.Split(commentLine.ReplaceAllString(string(raw), ""), -1) {
		if s = strings.TrimSpace(s); s != "" {
			out = append(out, s)
		}
	}
	return out
}

// applyMigrations — все clickhouse/migrations/*.sql по именам, как migrate.sh
// на свежей установке. CREATE DATABASE идёт от базы default: параметра
// database=argus до её создания нет.
func applyMigrations(t *testing.T, c *ClickHouse) []string {
	t.Helper()
	ctx := context.Background()
	dir := filepath.Join("..", "..", "..", "clickhouse", "migrations")
	files, err := filepath.Glob(filepath.Join(dir, "*.sql"))
	if err != nil || len(files) == 0 {
		t.Fatalf("миграции не найдены в %s: %v", dir, err)
	}
	sort.Strings(files)
	sys := New(c.base, "default", c.user, c.pass)
	for _, f := range files {
		for _, stmt := range migrationStatements(t, f) {
			cl := c
			if strings.HasPrefix(strings.ToUpper(stmt), "CREATE DATABASE") {
				cl = sys
			}
			if _, err := cl.do(ctx, stmt, nil, nil); err != nil {
				t.Fatalf("%s: %v\n%s", filepath.Base(f), err, stmt)
			}
		}
	}
	return files
}

func suffix(t *testing.T) string {
	t.Helper()
	var b [4]byte
	if _, err := rand.Read(b[:]); err != nil {
		t.Fatal(err)
	}
	return hex.EncodeToString(b[:])
}

func exec(t *testing.T, c *ClickHouse, q string) {
	t.Helper()
	if _, err := c.do(context.Background(), q, nil, nil); err != nil {
		t.Fatalf("%v\n%s", err, q)
	}
}

func countRows(t *testing.T, c *ClickHouse, q string) string {
	t.Helper()
	out, err := c.do(context.Background(), q, nil, nil)
	if err != nil {
		t.Fatalf("%v\n%s", err, q)
	}
	return strings.TrimSpace(string(out))
}

func TestLiveMigrationsFromScratchAndRerun(t *testing.T) {
	c := liveStore(t)
	files := applyMigrations(t, c)
	if len(files) < 28 {
		t.Fatalf("ожидалось ≥ 28 миграций, найдено %d", len(files))
	}
	applyMigrations(t, c) // повторный прогон — идемпотентность каждого оператора
	if got := countRows(t, c, "SELECT count() FROM system.tables WHERE database = 'argus' AND name IN ('events','incidents','incidents_current','identity_aliases') FORMAT TSV"); got != "4" {
		t.Fatalf("таблицы схемы: %s", got)
	}
}

func TestLiveEventsInsertSinceAround(t *testing.T) {
	c := liveStore(t)
	applyMigrations(t, c)
	ctx := context.Background()
	sfx := suffix(t)
	src, node, actor, ip := "store.live."+sfx, "node-"+sfx, "user-"+sfx, "203.0.113.7"
	now := time.Now().UTC().Truncate(time.Second)
	ts := func(d time.Duration) string { return model.FormatTS(now.Add(d)) }

	// Приём как у движка: received_at ставит база (now), ts — часы источника.
	evs := []*model.Event{
		{TS: ts(-2 * time.Minute), Source: src, SourceClass: "syslog", Action: "auth.login", Outcome: "failure", Severity: 5,
			ActorName: actor, ActorKind: "user", Node: node, SrcIP: ip, SrcPort: 51000, DstIP: "10.0.0.1", DstPort: 22, Proto: "tcp",
			Bytes: 10, Packets: 1, Attrs: map[string]string{"k": "v", "ю": "я"}, Raw: "raw line"},
		{TS: ts(-1 * time.Minute), Source: src, SourceClass: "syslog", Action: "auth.login", Outcome: "success", Severity: 1,
			ActorName: actor, Node: "other-" + sfx, SrcIP: "10.9.9.9", Attrs: map[string]string{}},
	}
	if err := c.InsertEvents(ctx, evs); err != nil {
		t.Fatal(err)
	}
	if err := c.InsertEvents(ctx, nil); err != nil {
		t.Fatalf("пустой батч — не ошибка: %v", err)
	}

	// EventsAround: по узлу, по субъекту, по адресу, без фильтра.
	from, to := now.Add(-time.Hour), now.Add(time.Hour)
	got, err := c.EventsAround(ctx, "syslog", node, "", "", from, to, 100)
	if err != nil || len(got) != 1 || got[0].Node != node || got[0].Attrs["ю"] != "я" || got[0].SrcPort != 51000 {
		t.Fatalf("по узлу: %v %+v", err, got)
	}
	got, err = c.EventsAround(ctx, "syslog", "", actor, "", from, to, 100)
	if err != nil || len(got) != 2 || got[0].TS > got[1].TS {
		t.Fatalf("по субъекту, по ts: %v %d", err, len(got))
	}
	got, err = c.EventsAround(ctx, "syslog", "", "", ip, from, to, 1000)
	if err != nil {
		t.Fatal(err)
	}
	byIP := 0
	for _, e := range got { // адрес не уникален между прогонами — считаем только свой источник
		if e.Source == src {
			byIP++
			if e.Outcome != "failure" {
				t.Fatalf("по адресу: %+v", e)
			}
		}
	}
	if byIP != 1 {
		t.Fatalf("по адресу: %d своих событий", byIP)
	}
	got, err = c.EventsAround(ctx, "syslog", "", actor, "", from, to, 1)
	if err != nil || len(got) != 1 {
		t.Fatalf("limit: %v %d", err, len(got))
	}
	if got, err = c.EventsAround(ctx, "syslog", "", "", "", from, to, 100); err != nil || got != nil {
		t.Fatalf("без фильтра — nil: %v %v", err, got)
	}
	if got, err = c.EventsAround(ctx, "ngfw", node, "", "", from, to, 100); err != nil || len(got) != 0 {
		t.Fatalf("другой класс: %v %v", err, got)
	}

	// EventsSince читает по received_at: строки «устоявшейся» секунды в прошлом.
	recv := now.Add(-30 * time.Second).Format("2006-01-02 15:04:05")
	exec(t, c, fmt.Sprintf(`INSERT INTO events (ts, received_at, source, source_class, action, outcome, actor_name, node, attrs, raw)
		VALUES ('%s', '%s', '%s', 'syslog', 'cursor.a', 'success', '%s', '%s', {'n':'1'}, ''),
		       ('%s', '%s', '%s', 'syslog', 'cursor.b', 'success', '%s', '%s', {'n':'2'}, '')`,
		ts(-3*time.Minute), recv, src, actor, node, ts(-3*time.Minute), recv, src, actor, node))
	cur := StartCursor(now.Add(-40 * time.Second))
	if cur.At.Nanosecond() != 0 || cur.Seen == nil {
		t.Fatalf("StartCursor: %+v", cur)
	}
	var mine []*model.Event
	var next Cursor
	for i := 0; i < 50; i++ { // другие тесты могли оставить строки — листаем до конца
		var page []*model.Event
		page, next, err = c.EventsSince(ctx, cur, 1000)
		if err != nil {
			t.Fatal(err)
		}
		for _, e := range page {
			if e.Source == src {
				mine = append(mine, e)
			}
		}
		if !next.More || len(page) == 0 {
			break
		}
		cur = next
	}
	if len(mine) != 2 || mine[0].Raw != "" || mine[0].ReceivedAt.IsZero() {
		t.Fatalf("EventsSince: %d событий, %+v", len(mine), mine)
	}
	if !next.At.After(StartCursor(now.Add(-40 * time.Second)).At) {
		t.Fatalf("курсор не сдвинулся: %+v", next)
	}
	// Повторный опрос с полученным курсором не отдаёт те же строки.
	page, _, err := c.EventsSince(ctx, next, 1000)
	if err != nil {
		t.Fatal(err)
	}
	for _, e := range page {
		if e.Source == src {
			t.Fatalf("дубль после курсора: %+v", e)
		}
	}
	if h := c.Host(); h == "" || h == "clickhouse" {
		t.Fatalf("Host из адреса подключения: %q", h)
	}
}

func inc(id, rule, status, level, actor, node string, created time.Time) *incidents.Incident {
	ts := created.UTC().Format("2006-01-02 15:04:05")
	return &incidents.Incident{IncidentID: id, UpdatedAt: ts, CreatedAt: ts, RuleID: rule, RuleTitle: "Правило " + rule,
		Level: level, Tags: []string{"test"}, Status: status, Owner: "", Note: "заметка\nвторая строка", ActorName: actor, Node: node,
		Sources: []string{"store.live"}, EventCount: 3, FirstTS: ts + ".000", LastTS: ts + ".000", Chain: []string{ts[11:] + "  src  node  act  detail"}}
}

func TestLiveIncidentsStateAndOperatorViews(t *testing.T) {
	c := liveStore(t)
	applyMigrations(t, c)
	ctx := context.Background()
	sfx := suffix(t)
	n := 900000000 + int(time.Now().UnixNano()%90000000)
	openID, closedID, quoteID := fmt.Sprintf("INC-%d", n), fmt.Sprintf("INC-%d", n-1), fmt.Sprintf("INC-%d'x", n-2)
	rule := "rule." + sfx
	now := time.Now().UTC()
	if err := c.InsertIncidents(ctx, []*incidents.Incident{
		inc(openID, rule, incidents.StatusNew, "critical", "actor-"+sfx, "node-"+sfx, now.Add(-time.Hour)),
		inc(closedID, rule, incidents.StatusClosed, "high", "actor-"+sfx, "node-"+sfx, now.Add(-2*time.Hour)),
		inc(quoteID, rule, incidents.StatusFalsePositive, "low", "", "", now.Add(-3*time.Hour)),
	}); err != nil {
		t.Fatal(err)
	}
	if err := c.InsertIncidents(ctx, nil); err != nil {
		t.Fatal(err)
	}

	open, maxN, err := c.OpenIncidents(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if maxN < n {
		t.Fatalf("максимальный номер %d < %d", maxN, n)
	}
	var seenOpen, seenClosed bool
	for _, i := range open {
		seenOpen = seenOpen || i.IncidentID == openID
		seenClosed = seenClosed || i.IncidentID == closedID || i.IncidentID == quoteID
	}
	if !seenOpen || seenClosed {
		t.Fatalf("открытые: open=%v closed=%v", seenOpen, seenClosed)
	}

	got, err := c.GetIncident(ctx, openID)
	if err != nil || got == nil || got.RuleID != rule || got.Note != "заметка\nвторая строка" || got.EventCount != 3 || len(got.Chain) != 1 {
		t.Fatalf("GetIncident: %v %+v", err, got)
	}
	if got, err = c.CurrentIncident(ctx, "INC-nope-"+sfx); err != nil || got != nil {
		t.Fatalf("неизвестный инцидент — nil: %v %+v", err, got)
	}

	// Журнал переходов: ревизии растут, consоль видит статус и владельца из него.
	if rev, err := c.IncidentRevision(ctx, openID); err != nil || rev != 0 {
		t.Fatalf("ревизия до переходов: %d %v", rev, err)
	}
	e1, err := c.AppendIncidentState(ctx, openID, "ivan", "take", incidents.StatusInProgress, "ivan", "", ClosureLabel{})
	if err != nil || e1.Revision != 1 || len(e1.EventID) != 36 {
		t.Fatalf("переход 1: %v %+v", err, e1)
	}
	e2, err := c.AppendIncidentState(ctx, openID, "ivan", "status", "observing", "ivan", "смотрим", ClosureLabel{})
	if err != nil || e2.Revision != 2 || e2.EventID == e1.EventID {
		t.Fatalf("переход 2: %v %+v", err, e2)
	}
	if rev, err := c.IncidentRevision(ctx, openID); err != nil || rev != 2 {
		t.Fatalf("ревизия: %d %v", rev, err)
	}
	cur, err := c.CurrentIncident(ctx, openID)
	if err != nil || cur == nil || cur.Status != "observing" || cur.Owner != "ivan" {
		t.Fatalf("incidents_current после переходов: %v %+v", err, cur)
	}
	// Закрытый детектором инцидент переходами не оживает.
	if _, err := c.AppendIncidentState(ctx, closedID, "ivan", "take", incidents.StatusInProgress, "ivan", "", ClosureLabel{}); err != nil {
		t.Fatal(err)
	}
	// Метка ответа (миграции 0033, 0036) пишется и читается теми же колонками; null
	// у эскалации отличим от false.
	no, level := false, uint8(2)
	if _, err := c.AppendIncidentState(ctx, closedID, "ivan", "status", incidents.StatusClosed, "ivan", "проверено, угрозы нет",
		ClosureLabel{Disposition: "benign_authorized", SeverityLevel: &level, SeverityCorrect: &no, AttackTactic: "discovery",
			AttackTechnique: "T1046", AttackVersion: "20.0", Blind: true, LabeledByHuman: true}); err != nil {
		t.Fatal(err)
	}
	labelRow, err := c.do(ctx, `SELECT disposition, escalate, severity_level, severity_correct, attack_tactic, attack_technique, attack_version,
		ops_act_now, ops_urgency, blind, labeled_by_human FROM incident_state_events
		WHERE incident_id = {id:String} AND kind = 'status' FORMAT JSONEachRow`, nil, map[string]string{"id": closedID})
	if err != nil {
		t.Fatal(err)
	}
	if got := strings.TrimSpace(string(labelRow)); got != `{"disposition":"benign_authorized","escalate":null,"severity_level":2,"severity_correct":false,"attack_tactic":"discovery","attack_technique":"T1046","attack_version":"20.0","ops_act_now":null,"ops_urgency":null,"blind":true,"labeled_by_human":true}` {
		t.Fatalf("метка ответа: %s", got)
	}
	if cur, err = c.CurrentIncident(ctx, closedID); err != nil || cur.Status != incidents.StatusClosed {
		t.Fatalf("закрытый остаётся закрытым: %v %+v", err, cur)
	}

	states, err := c.OperatorStates(ctx, []string{openID, quoteID, "INC-absent-" + sfx})
	if err != nil {
		t.Fatal(err)
	}
	if len(states) != 2 || states[openID].Status != "observing" || states[openID].Owner != "ivan" || states[quoteID].Status != incidents.StatusFalsePositive {
		t.Fatalf("OperatorStates: %+v", states)
	}
	if states[openID].UpdatedAt == "" || states[openID].Note == "" {
		t.Fatalf("updated_max/note пусты: %+v", states[openID])
	}
	if empty, err := c.OperatorStates(ctx, nil); err != nil || len(empty) != 0 {
		t.Fatalf("без id — пустая карта: %v %v", err, empty)
	}

	similar, err := c.SimilarIncidents(ctx, rule, "", "", openID, 10)
	if err != nil {
		t.Fatal(err)
	}
	if len(similar) != 2 || !strings.HasPrefix(similar[0], closedID+" · "+now.Add(-2*time.Hour).Format("2006-01-02")+" · closed · Правило "+rule+" · заметка вторая строка") {
		t.Fatalf("похожие: %q", similar)
	}
	similar, err = c.SimilarIncidents(ctx, "none", "actor-"+sfx, "", "INC-0", 1)
	if err != nil || len(similar) != 1 {
		t.Fatalf("похожие по субъекту с limit 1: %v %q", err, similar)
	}
}

func TestLiveResponsesSettingsDisksVerdictsExceptions(t *testing.T) {
	c := liveStore(t)
	applyMigrations(t, c)
	ctx := context.Background()
	sfx := suffix(t)
	ts := time.Now().UTC().Format("2006-01-02 15:04:05")

	id := "INC-resp-" + sfx
	if err := c.InsertResponses(ctx, []ResponseRow{
		{TS: ts, IncidentID: id, RuleID: "r", IP: "203.0.113.9", Mode: "ips", Executor: "wazuh.active-response", OK: 1, Detail: "ok", Reason: "TTL истёк", Actor: "argus-engine"},
		{TS: ts, IncidentID: id, RuleID: "r", IP: "203.0.113.10", Mode: "simulate", Executor: "argus", DryRun: 1, Detail: "", Reason: "", Actor: "argus-engine"},
	}); err != nil {
		t.Fatal(err)
	}
	if err := c.InsertResponses(ctx, nil); err != nil {
		t.Fatal(err)
	}
	if got := countRows(t, c, "SELECT count(), sum(dry_run), sum(ok) FROM response_log WHERE incident_id = '"+id+"' FORMAT TSV"); got != "2\t1\t1" {
		t.Fatalf("response_log: %q", got)
	}

	key := "respond_mode_" + sfx
	if v, err := c.ConsoleSetting(ctx, key); err != nil || v != "" {
		t.Fatalf("неизвестный ключ: %q %v", v, err)
	}
	exec(t, c, "INSERT INTO console_settings (key, value, updated_at, updated_by) VALUES ('"+key+"', 'ids', now() - INTERVAL 10 SECOND, 'admin')")
	exec(t, c, "INSERT INTO console_settings (key, value, updated_at, updated_by) VALUES ('"+key+"', 'ips', now(), 'admin')")
	if v, err := c.ConsoleSetting(ctx, key); err != nil || v != "ips" {
		t.Fatalf("последнее значение: %q %v", v, err)
	}

	disks, err := c.Disks(ctx)
	if err != nil || len(disks) == 0 || disks[0].Total == 0 || disks[0].Name == "" || disks[0].Path == "" {
		t.Fatalf("Disks: %v %+v", err, disks)
	}

	vid := "INC-verdict-" + sfx
	if err := c.InsertVerdict(ctx, Verdict{IncidentID: vid, EvaluatedAt: ts, Profile: "mock", Model: "m", SummaryRU: "сводка",
		Evidence: []string{"a", "б"}, FirstAction: "проверить", Confidence: 0.75, Shown: 1, ShownReason: "порог", Tokens: 10, LatencyMs: 20,
		Missing: "", Actions: []string{"x"}, ConfidenceKind: "high"}); err != nil {
		t.Fatal(err)
	}
	if got := countRows(t, c, "SELECT summary_ru, length(evidence), shown FROM incident_verdicts WHERE incident_id = '"+vid+"' FORMAT TSV"); got != "сводка\t2\t1" {
		t.Fatalf("incident_verdicts: %q", got)
	}

	rule := "rule.exc." + sfx
	exec(t, c, fmt.Sprintf(`INSERT INTO rule_exceptions (rule_id, field, value, reason, incident_id, created_by, created_at, active) VALUES
		('%[1]s', 'actor.name', 'svc-backup', 'ложное', 'INC-1', 'admin', now() - INTERVAL 20 SECOND, 1),
		('%[1]s', 'src.ip', '10.0.0.5', 'ложное', 'INC-1', 'admin', now() - INTERVAL 20 SECOND, 1),
		('%[1]s', 'src.ip', '10.0.0.5', 'снято', 'INC-1', 'admin', now() - INTERVAL 10 SECOND, 0),
		('%[1]s', 'node', 'host-1', 'ложное', 'INC-1', 'admin', now() - INTERVAL 20 SECOND, 0),
		('%[1]s', 'node', 'host-1', 'вернули', 'INC-1', 'admin', now() - INTERVAL 10 SECOND, 1)`, rule))
	exc, err := c.Exceptions(ctx)
	if err != nil {
		t.Fatal(err)
	}
	got := exc[rule]
	sort.Slice(got, func(i, j int) bool { return got[i].Field < got[j].Field })
	if len(got) != 2 || got[0].Field != "actor.name" || got[0].Value != "svc-backup" || got[1].Field != "node" || got[1].Value != "host-1" {
		t.Fatalf("активные исключения: %+v", got)
	}
}

func TestLiveRiskReport(t *testing.T) {
	c := liveStore(t)
	applyMigrations(t, c)
	ctx := context.Background()
	sfx := suffix(t)
	now := time.Now().UTC()

	if countRows(t, c, "SELECT count() FROM risk_report_deliveries FORMAT TSV") == "0" {
		if last, err := c.RiskReportLastSent(ctx); err != nil || !last.IsZero() {
			t.Fatalf("без доставок — нулевое время: %v %v", last, err)
		}
	}
	sent := now.Truncate(time.Millisecond)
	if err := c.RecordRiskReportDelivery(ctx, sent); err != nil {
		t.Fatal(err)
	}
	last, err := c.RiskReportLastSent(ctx)
	if err != nil || last.Before(sent) || last.After(sent.Add(time.Minute)) {
		t.Fatalf("последняя доставка: %v (отправлено %v) %v", last, sent, err)
	}

	n := 800000000 + int(now.UnixNano()%90000000)
	overdue := fmt.Sprintf("INC-%d", n)
	fresh := fmt.Sprintf("INC-%d", n+1)
	rule := "rule.risk." + sfx
	if err := c.InsertIncidents(ctx, []*incidents.Incident{
		inc(overdue, rule, incidents.StatusNew, "critical", "a", "n", now.Add(-time.Hour)), // 15 мин на реакцию — просрочен
		inc(fresh, rule, incidents.StatusNew, "low", "a", "n", now.Add(-time.Minute)),      // сутки — нет
	}); err != nil {
		t.Fatal(err)
	}
	if _, err := c.AppendIncidentState(ctx, fresh, "petr", "take", incidents.StatusInProgress, "petr", "", ClosureLabel{}); err != nil {
		t.Fatal(err)
	}
	r, err := c.RiskReport(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if r.Totals.Open < 2 || r.Totals.Overdue < 1 || r.Totals.Critical < 1 || r.Totals.Unassigned < 1 {
		t.Fatalf("итоги: %+v", r.Totals)
	}
	var seenOverdue, seenFresh bool
	for _, i := range r.Top {
		if i.ID == overdue {
			seenOverdue = true
			if i.Overdue != 1 || i.Level != "critical" || i.Owner != "" || i.Deadline == "" || i.CreatedAt == "" {
				t.Fatalf("просроченный: %+v", i)
			}
		}
		if i.ID == fresh {
			seenFresh = true
			if i.Overdue != 0 || i.Owner != "petr" || i.Status != incidents.StatusInProgress {
				t.Fatalf("свежий: %+v", i)
			}
		}
	}
	if !seenOverdue {
		t.Fatalf("просроченный критичный не в топе: %+v", r.Top)
	}
	var owners []string
	for _, o := range r.Owners {
		owners = append(owners, o.Owner)
	}
	if !seenFresh && len(r.Top) < 30 {
		t.Fatalf("свежий не в топе: %+v", r.Top)
	}
	if !contains(owners, "") || (!contains(owners, "petr") && len(owners) < 50) {
		t.Fatalf("ответственные: %q", owners)
	}
}

func contains(xs []string, s string) bool {
	for _, x := range xs {
		if x == s {
			return true
		}
	}
	return false
}

func TestLiveIdentities(t *testing.T) {
	c := liveStore(t)
	applyMigrations(t, c)
	ctx := context.Background()
	sfx := suffix(t)
	p1, p2 := "i.petrov."+sfx, "svc-backup."+sfx
	login := "petrov-" + sfx
	from := time.Date(2026, 1, 10, 0, 0, 0, 0, time.UTC)

	if err := c.UpsertIdentities(ctx, nil); err != nil {
		t.Fatal(err)
	}
	if err := c.UpsertIdentities(ctx, []identity.Person{
		{ID: p1, Display: "Иван", Kind: identity.PersonKind, Team: "platform"},
		{ID: p1, Display: "Иван Петров", Kind: identity.PersonKind, Team: "platform"}, // дубль в батче — последний
		{ID: p2}, // display и kind по умолчанию
	}); err != nil {
		t.Fatal(err)
	}
	known, err := c.KnownPersons(ctx, []string{p1, p2, "nobody-" + sfx})
	if err != nil || len(known) != 2 || !known[p1] || !known[p2] {
		t.Fatalf("KnownPersons: %v %v", known, err)
	}
	if got := countRows(t, c, "SELECT argMax(display, updated_at), argMax(kind, updated_at) FROM identities WHERE person_id = '"+p1+"' FORMAT TSV"); got != "Иван Петров\tperson" {
		t.Fatalf("последняя версия персоны: %q", got)
	}
	if got := countRows(t, c, "SELECT argMax(display, updated_at), argMax(kind, updated_at) FROM identities WHERE person_id = '"+p2+"' FORMAT TSV"); got != p2+"\tperson" {
		t.Fatalf("умолчания персоны: %q", got)
	}
	if k, err := c.KnownPersons(ctx, nil); err != nil || len(k) != 0 {
		t.Fatalf("без id: %v %v", k, err)
	}

	a1 := identity.Alias{PersonID: p1, Kind: "login", Value: login, ValidFrom: from, Source: "yaml", Confidence: 1, Note: "из файла"}
	a2 := identity.Alias{PersonID: p1, Kind: "email", Value: login + "@example.org", ValidFrom: from, Source: "api", Confidence: 0.5}
	if err := c.UpsertAliases(ctx, nil); err != nil {
		t.Fatal(err)
	}
	if err := c.UpsertAliases(ctx, []identity.Alias{a1, a1, a2}); err != nil {
		t.Fatal(err)
	}
	open, err := c.OpenAliases(ctx, "login", login, "")
	if err != nil || len(open) != 1 || open[0].PersonID != p1 || open[0].Note != "из файла" || !open[0].ValidFrom.Equal(from) || open[0].ValidTo != nil {
		t.Fatalf("OpenAliases: %v %+v", err, open)
	}
	if open, err = c.OpenAliases(ctx, "login", login, p2); err != nil || len(open) != 0 {
		t.Fatalf("чужая персона: %v %+v", err, open)
	}
	bySrc, err := c.AliasesBySource(ctx, "api")
	if err != nil {
		t.Fatal(err)
	}
	var seenAPI bool
	for _, a := range bySrc {
		if a.Source != "api" {
			t.Fatalf("чужой источник: %+v", a)
		}
		seenAPI = seenAPI || (a.Value == a2.Value && a.Confidence == 0.5)
	}
	if !seenAPI {
		t.Fatalf("AliasesBySource не нашёл %q: %+v", a2.Value, bySrc)
	}

	// Закрытие алиаса — новая версия той же строки с valid_to; открытых больше нет.
	to := from.Add(48 * time.Hour)
	closed := a1
	closed.ValidTo = &to
	if err := c.UpsertAliases(ctx, []identity.Alias{closed}); err != nil {
		t.Fatal(err)
	}
	if open, err = c.OpenAliases(ctx, "login", login, ""); err != nil || len(open) != 0 {
		t.Fatalf("закрытый алиас не открыт: %v %+v", err, open)
	}
	byPerson, err := c.AliasesByPerson(ctx, p1, "login")
	if err != nil || len(byPerson) != 1 || byPerson[0].ValidTo == nil || !byPerson[0].ValidTo.Equal(to) {
		t.Fatalf("AliasesByPerson: %v %+v", err, byPerson)
	}
	// Повторное открытие: valid_to снова NULL (argMax по ifNull — не застревает).
	if err := c.UpsertAliases(ctx, []identity.Alias{a1}); err != nil {
		t.Fatal(err)
	}
	if byPerson, err = c.AliasesByPerson(ctx, p1, "login"); err != nil || len(byPerson) != 1 || byPerson[0].ValidTo != nil {
		t.Fatalf("снова открыт: %v %+v", err, byPerson)
	}

	if err := c.DeleteAliases(ctx, nil); err != nil {
		t.Fatal(err)
	}
	if err := c.DeleteAliases(ctx, []identity.Alias{a1, a2}); err != nil {
		t.Fatal(err)
	}
	if byPerson, err = c.AliasesByPerson(ctx, p1, "login"); err != nil || len(byPerson) != 0 {
		t.Fatalf("удалённый алиас: %v %+v", err, byPerson)
	}
	if byPerson, err = c.AliasesByPerson(ctx, p1, "email"); err != nil || len(byPerson) != 0 {
		t.Fatalf("удалённый email: %v %+v", err, byPerson)
	}

	// Метки версий монотонны даже в одном миллисекундном окне.
	s1, s2 := c.stamp(ctx), c.stamp(ctx)
	if s2 <= s1 {
		t.Fatalf("метки не растут: %s %s", s1, s2)
	}
	if _, err := c.maxUpdatedAt(ctx); err != nil {
		t.Fatal(err)
	}
}

func TestLiveWebhookDeliveries(t *testing.T) {
	c := liveStore(t)
	applyMigrations(t, c)
	ctx := context.Background()
	sfx := suffix(t)
	target, key := "taskview-"+sfx, "INC-1|created"

	if _, ok, err := c.LookupWebhookDelivery(ctx, target, key); err != nil || ok {
		t.Fatalf("до записи: ok=%v %v", ok, err)
	}
	at := time.Now().UTC().Truncate(time.Millisecond)
	if err := c.SaveWebhookDelivery(ctx, webhook.Record{Target: target, Key: key, IncidentID: "INC-1", Event: webhook.EventCreated,
		State: webhook.StateCreated, Ref: "", UpdatedAt: at}); err != nil {
		t.Fatal(err)
	}
	rec, ok, err := c.LookupWebhookDelivery(ctx, target, key)
	if err != nil || !ok || rec.State != webhook.StateCreated || !rec.UpdatedAt.Equal(at) || rec.Target != target || rec.Key != key {
		t.Fatalf("после записи: %+v %v %v", rec, ok, err)
	}
	// Новая версия без UpdatedAt — «сейчас», и она побеждает.
	if err := c.SaveWebhookDelivery(ctx, webhook.Record{Target: target, Key: key, IncidentID: "INC-1", Event: webhook.EventCreated,
		State: webhook.StateDelivered, Ref: "42"}); err != nil {
		t.Fatal(err)
	}
	rec, ok, err = c.LookupWebhookDelivery(ctx, target, key)
	if err != nil || !ok || rec.State != webhook.StateDelivered || rec.Ref != "42" || !rec.UpdatedAt.After(at.Add(-time.Second)) {
		t.Fatalf("последняя версия: %+v %v %v", rec, ok, err)
	}
	if _, ok, err = c.LookupWebhookDelivery(ctx, target, "other"); err != nil || ok {
		t.Fatalf("другой ключ: ok=%v %v", ok, err)
	}
}

// Выгрузка меток для датасета: только последнее завершение, и только если
// его сделал человек с меткой; переоткрытые и закрытые автоматикой — нет.
func TestLiveLabeledIncidents(t *testing.T) {
	c := liveStore(t)
	applyMigrations(t, c)
	ctx := context.Background()
	sfx := suffix(t)
	n := 800000000 + int(time.Now().UnixNano()%90000000)
	labeledID, autoID, reopenedID, relabeledID := fmt.Sprintf("INC-%d", n), fmt.Sprintf("INC-%d", n-1), fmt.Sprintf("INC-%d", n-2), fmt.Sprintf("INC-%d", n-3)
	rule := "rule." + sfx
	now := time.Now().UTC()
	var incs []*incidents.Incident
	for _, id := range []string{labeledID, autoID, reopenedID, relabeledID} {
		incs = append(incs, inc(id, rule, incidents.StatusNew, "high", "actor-"+sfx, "node-"+sfx, now.Add(-time.Hour)))
	}
	if err := c.InsertIncidents(ctx, incs); err != nil {
		t.Fatal(err)
	}
	yes, no := true, false
	sev, urg := uint8(4), uint8(2)
	human := ClosureLabel{Disposition: "malicious", Escalate: &yes, SeverityLevel: &sev, SeverityCorrect: &no,
		AttackTactic: "credential-access", AttackTechnique: "T1110.001", AttackVersion: "20.0",
		OpsActNow: &no, OpsUrgency: &urg, Blind: true, LabeledByHuman: true}
	step := func(id, kind, status string, l ClosureLabel) {
		t.Helper()
		if _, err := c.AppendIncidentState(ctx, id, "ivan", kind, status, "ivan", "причина завершения", l); err != nil {
			t.Fatal(err)
		}
	}
	step(labeledID, "status", incidents.StatusClosed, human)
	step(autoID, "auto_close", incidents.StatusClosed, ClosureLabel{})
	step(reopenedID, "status", incidents.StatusClosed, human)
	step(reopenedID, "status", incidents.StatusInProgress, ClosureLabel{})
	step(relabeledID, "status", incidents.StatusClosed, human)
	step(relabeledID, "status", incidents.StatusInProgress, ClosureLabel{})
	fp := ClosureLabel{Disposition: "false_positive", Escalate: &no, SeverityCorrect: &no, LabeledByHuman: true}
	step(relabeledID, "status", incidents.StatusFalsePositive, fp)

	got, err := c.LabeledIncidents(ctx, now.Add(-time.Minute).Format(time.RFC3339), 50000)
	if err != nil {
		t.Fatal(err)
	}
	mine := map[string]LabeledIncident{}
	for _, l := range got {
		if l.Incident.RuleID == rule {
			mine[l.Incident.IncidentID] = l
		}
	}
	if len(mine) != 2 {
		t.Fatalf("ждали 2 размеченных (%s, %s), получили %v", labeledID, relabeledID, mine)
	}
	l := mine[labeledID]
	if l.Label.Disposition != "malicious" || l.Label.Escalate == nil || !*l.Label.Escalate || l.Label.SeverityCorrect == nil || *l.Label.SeverityCorrect ||
		!l.Label.Blind || !l.Label.LabeledByHuman || l.ChangedAt == "" || l.Incident.Status != incidents.StatusClosed || len(l.Incident.Chain) != 1 {
		t.Fatalf("метка и инцидент: %+v", l)
	}
	if l.Label.SeverityLevel == nil || *l.Label.SeverityLevel != 4 || l.Label.AttackTactic != "credential-access" ||
		l.Label.AttackTechnique != "T1110.001" || l.Label.AttackVersion != "20.0" ||
		l.Label.OpsActNow == nil || *l.Label.OpsActNow || l.Label.OpsUrgency == nil || *l.Label.OpsUrgency != 2 {
		t.Fatalf("поля плана разметки (0036): %+v", l.Label)
	}
	if r := mine[relabeledID]; r.Label.Disposition != "false_positive" || r.Incident.Status != incidents.StatusFalsePositive {
		t.Fatalf("берётся последняя метка: %+v", r)
	}
	if got, err := c.LabeledIncidents(ctx, now.Add(time.Hour).Format(time.RFC3339), 10); err != nil || len(got) != 0 {
		t.Fatalf("since в будущем: %v %d", err, len(got))
	}
}
