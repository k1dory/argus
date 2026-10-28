// SQL консоли на живом ClickHouse. Юнит-тесты подменяют chQuery и не ловят ошибку в
// самом запросе (нет столбца, не та функция, неверный тип параметра) — её ловил только
// e2e или прод. Здесь: все миграции применяются с нуля по порядку, таблицы заполняются
// небольшой фикстурой, и каждый запрос консоли выполняется настоящим сервером.
// Пустая таблица тоже проверяет запрос: ClickHouse разбирает его и привязывает столбцы
// до чтения данных. Нужен ARGUS_TEST_CLICKHOUSE_URL (в CI — сервис clickhouse у job web).
import { test } from "node:test";
import assert from "node:assert/strict";
import { randomUUID } from "node:crypto";
import { applyAllMigrations, ch, liveSkip as skip } from "./_ch-live";
import { parseJournalParams, parseTailCursor } from "../src/lib/shared/journal";
import { SILENCE_MIN_SEC } from "../src/lib/shared/source-health";
import { ACTOR_RANGES } from "../src/lib/shared/actors";

/* eslint-disable @typescript-eslint/no-require-imports -- модули читают env при загрузке */
const q = () => require("../src/lib/argus-queries") as typeof import("../src/lib/argus-queries");
const journal = () => require("../src/lib/journal") as typeof import("../src/lib/journal");
const search = () => require("../src/lib/search") as typeof import("../src/lib/search");
const wazuh = () => require("../src/lib/queries") as typeof import("../src/lib/queries");
const actors = () => require("../src/lib/actors") as typeof import("../src/lib/actors");
/* eslint-enable @typescript-eslint/no-require-imports */

const RUN = `q${Date.now().toString(36)}`;
const LIVE = `netflow.${RUN}`, RARE = `ci.${RUN}`, STALE = `sshd.${RUN}`, ONCE = `once.${RUN}`;

/** Фикстура: непрерывный источник за час, редкий (раз в 2 ч) и замолчавший 3 суток назад. */
async function seed(): Promise<void> {
  const c = ch();
  const ev = (src: string, cls: string, expr: string, n: number, pii = 0) =>
    c.chCommand(`INSERT INTO events (ts, received_at, source, source_class, action, outcome, severity, actor_name, node, src_ip, dst_ip, pii)
      SELECT ${expr}, ${expr}, {s:String}, {c:String}, 'flow', 'allow', 3, 'actor-${RUN}', 'node-${RUN}', '10.1.2.3', '203.0.113.9', ${pii} FROM numbers(${n})`, { s: src, c: cls });
  await ev(LIVE, "netflow", "now() - number", 1800);
  await ev(RARE, "cicd", "now() - INTERVAL 7200 * number SECOND", 30);
  await ev(STALE, "syslog", "now() - INTERVAL 3 DAY - 7 * number", 20, 1);
  const hb = (src: string, listener: string, expr: string, n: number, perMin: string) =>
    c.chCommand(`INSERT INTO collector_health (source, listener, seen_at, events_1m) SELECT {s:String}, {l:String}, toStartOfMinute(${expr}), ${perMin} FROM numbers(${n})`, { s: src, l: listener });
  await hb(LIVE, "netflow", "now() - 60 * number", 30, "60");
  await hb(RARE, "http", "now() - INTERVAL 7200 * number SECOND", 30, "1");
  await hb(STALE, "syslog", "now() - INTERVAL 3 DAY - 60 * number", 3, "7");
  await hb(ONCE, "http", "now() - INTERVAL 2 HOUR", 1, "5");
}

test("миграции применяются с нуля по порядку, фикстура вставляется", { skip }, async () => {
  const files = await applyAllMigrations();
  assert.ok(files.length >= 28, `миграций ${files.length}`);
  await seed();
});

test("sourcesHealth: живой — alive, редкий — порог по ритму, замолчавший 3 суток — в списке с классом из events", { skip }, async () => {
  const rows = await q().sourcesHealth();
  const by = new Map(rows.map((r) => [r.source, r]));
  const live = by.get(LIVE), rare = by.get(RARE), stale = by.get(STALE);
  assert.ok(live && rare && stale, `все три источника в списке: ${rows.map((r) => r.source).join(", ")}`);
  assert.equal(live.alive, 1); assert.equal(live.source_class, "netflow"); assert.ok(live.events_1h >= 1800);
  assert.equal(live.silence_threshold_sec, SILENCE_MIN_SEC, "непрерывный — минимальный порог");
  assert.equal(rare.rhythm_sec, 7200, "ритм редкого — разрыв между активными минутами (2 ч)");
  assert.equal(rare.silence_threshold_sec, 3 * 7200, "порог — три ритма");
  assert.equal(rare.alive, 1, "последнее событие сейчас — жив");
  assert.equal(stale.alive, 0); assert.equal(stale.source_class, "syslog", "класс замолчавшего — точечным запросом к events");
  assert.equal(stale.rhythm_sec, 60, "три активные минуты подряд → разрывы по минуте");
  assert.equal(stale.silence_threshold_sec, SILENCE_MIN_SEC);
  assert.ok(stale.silent_for_sec > 2.9 * 86400 && stale.events_1h === 0);
  assert.equal(stale.pii_share, 0, "доля ПДн — за час, а не за окно");
  const once = by.get(ONCE);
  assert.ok(once, "источник с одной активной минутой heartbeat и без строк в events — в списке");
  assert.equal(once.rhythm_sec, null, "разрывов нет — ритм неизвестен"); assert.equal(once.silence_threshold_sec, SILENCE_MIN_SEC); assert.equal(once.alive, 0);
  assert.equal(once.source_class, "", "класса нет — в events строк не было"); assert.ok(once.last_ts, "время — из heartbeat");
  for (const r of rows) assert.ok(r.last_ts && Number.isFinite(r.silent_for_sec) && Number.isFinite(r.events_window), r.source);
});

test("чтение: запросы инцидентов, журнала, статистики и лицензии выполняются сервером", { skip }, async () => {
  const a = q();
  const list = await a.incidentsList({});
  assert.deepEqual(Object.keys(list).sort(), ["page", "pageSize", "rows", "total"]);
  for (const queue of ["open", "mine", "unassigned", "overdue"] as const) await a.incidentsList({ queue, user: "admin", status: "new", level: "high", q: RUN, page: 2, pageSize: 10 });
  assert.equal(await a.incidentGet("INC-0"), null);
  assert.deepEqual(await a.incidentComments("INC-0"), []);
  assert.deepEqual(await a.incidentStateHistory("INC-0"), []);
  await a.incidentClosuresFor(["INC-0", "INC-1"]);
  assert.equal(await a.incidentFirstResponse("INC-0"), null);
  assert.equal(await a.verdictGet("INC-0"), null);
  await a.verdictsFor(["INC-0"]);
  const stats = await a.incidentStats();
  assert.ok(Number.isFinite(stats.total) && Number.isFinite(stats.open));
  const recent = await a.eventsRecent(LIVE, 5);
  assert.equal(recent.length, 5); assert.equal(recent[0].source, LIVE);
  assert.ok((await a.eventsRecent()).length > 0);
  const classes = await a.eventsByClass(24);
  assert.ok(classes.some((c) => c.source_class === "netflow"));
  await a.listExceptions(); await a.auditTail(10); await a.rulesFalsePositives();
  const lic = await a.licenseStats();
  assert.ok(lic.peak_eps_30d >= 1, `пик EPS по heartbeat: ${lic.peak_eps_30d}`);
  assert.ok(lic.sources >= 3);
  await a.triageRevocations(); await a.triageVerdictClaim("INC-0"); await a.triageVerdictWinner("INC-0"); await a.triageVerdictEpoch("INC-0");
  await a.agentVerdictsFor("INC-0"); await a.agentVerdictBySession("INC-0", "s");
});

test("запись: аудит, исключения, комментарии, отзыв сессии — вставка и обратное чтение", { skip }, async () => {
  const a = q();
  await a.audit(`user-${RUN}`, "test.audit", "target", "живой ClickHouse", { strict: true });
  assert.ok((await a.auditTail(50)).some((r) => r.user === `user-${RUN}`), "аудит читается обратно");
  await a.addException({ rule_id: `r-${RUN}`, field: "src_ip", value: "10.0.0.1", reason: "тест", incident_id: `INC-${RUN}`, created_by: "admin" });
  assert.ok((await a.listExceptions()).some((x) => x.rule_id === `r-${RUN}`));
  await a.deactivateException(`r-${RUN}`, "src_ip", "10.0.0.1", "admin");
  const commentId = randomUUID();
  await a.addIncidentComment(`INC-${RUN}`, "admin", "комментарий", { commentId });
  assert.equal(await a.incidentCommentExists(`INC-${RUN}`, commentId), true);
  assert.equal((await a.incidentComments(`INC-${RUN}`)).length, 1);
  await a.saveTriageRevocation(`s-${RUN}`, `INC-${RUN}`, new Date(Date.now() + 600_000).toISOString().slice(0, 19).replace("T", " "));
  assert.ok((await a.triageRevocations()).has(`s-${RUN}`));
});

test("журнал и поиск: лента, live-tail с курсором, поиск по индексам", { skip }, async () => {
  const f = parseJournalParams(new URLSearchParams(`source=${LIVE}&range=1h`));
  const page = await journal().journalSearch(f);
  assert.equal(page.error, null, page.error ?? "");
  assert.ok(page.total >= 1800 && page.rows.length > 0 && page.series.length > 0);
  const cursor = parseTailCursor("2000-01-01 00:00:00|0");
  assert.ok(cursor);
  const tail = await journal().journalTail({ ...f, range: "24h" }, cursor);
  assert.equal(tail.error, null, tail.error ?? "");
  assert.ok(tail.rows.length > 0 && tail.cursor.includes("|"));
  const s = search();
  for (const index of s.availableIndexes()) {
    const r = await s.search({ index, q: RUN, range: "24h", page: 1, facets: true });
    assert.equal(r.error, null, `${index}: ${r.error}`);
  }
  const bound = await s.search({ index: "events", q: "", range: "24h", page: 1, facets: false, bind: { actors: [`actor-${RUN}`], nodes: [] } });
  assert.equal(bound.error, null); assert.ok(bound.total >= 1800, `строки субъекта за сутки: ${bound.total}`);
  const exp = await s.searchExport({ index: "events", q: RUN, range: "24h", page: 1 }, 10, false);
  assert.equal(exp.error, null); assert.equal(exp.rows.length, 10);
});

test("модуль Wazuh: запросы по wazuh_alerts и вердиктам политик на пустых таблицах", { skip }, async () => {
  const w = wazuh();
  for (const range of ["1h", "24h", "7d", "30d"] as const) {
    await w.overviewStats(range); await w.alertsSeries(range); await w.topRules(range); await w.topTactics(range); await w.agentNames(range); await w.agentsSummary(range);
  }
  await w.alertsList({ range: "24h", page: 1 } as Parameters<typeof w.alertsList>[0]);
  await w.latestVerdictsSummary(); await w.latestVerdicts(); await w.mutedRuleIds(); await w.mutedRulesList(); await w.vulnList();
  await w.setRuleMuted(100002, true);
  assert.ok((await w.mutedRuleIds()).includes(100002));
  await w.setRuleMuted(100002, false);
});

test("паспорт субъекта: идентичности, резолв алиаса, несвязанные субъекты, отчёт", { skip }, async () => {
  const ac = actors();
  const pid = `p-${RUN}`;
  await ac.upsertIdentities([{ person_id: pid, display: "Тест", kind: "person", team: "", note: "", aliases: [{ kind: "login", value: `login-${RUN}`, valid_from: null, valid_to: null, confidence: 1, note: "" }] }], "test");
  const person = await ac.getPerson(pid);
  assert.ok(person, "персона записана");
  const res = await ac.resolveAlias(`login-${RUN}`);
  assert.equal(res.status, "resolved");
  for (const range of ACTOR_RANGES) { await ac.listPersons(range); await ac.unboundSubjects(range, 5); }
  const report = await ac.actorReport(person, await ac.personAliases(pid), "7d", 20);
  assert.ok(report);
  assert.equal(await ac.confirmAlias(pid, "login", `login-${RUN}`), 0, "подтверждённый алиас (confidence 1) подтверждать нечего — SQL выполняется, строк 0");
  assert.equal(await ac.closeAlias(pid, "login", `login-${RUN}`), 1);
  await ac.allAliases();
});
