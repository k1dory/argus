// GET /api/v1/log: разбор параметров, карта уровней, параметризованный SQL,
// область сессии разбора (как у /api/search).
import { test } from "node:test";
import assert from "node:assert/strict";
import { installNextMocks, loadAuth } from "./_next-mock";
import { buildLogSql, LEVEL_MIN, levelOf, logScopeQuery, parseDuration, parseLogParams, toLogItem } from "../src/lib/shared/log-query";

loadAuth();
const mocks = installNextMocks();
const API = "a".repeat(40);
const ISSUER = "i".repeat(40);
process.env.ARGUS_API_TOKEN = API;
process.env.ARGUS_TRIAGE_ISSUER_TOKEN = ISSUER;

/* eslint-disable @typescript-eslint/no-require-imports -- маршруты грузятся после моков */
type Route = { GET?: (req: Request) => Promise<Response>; POST?: (req: Request) => Promise<Response> };
const logRoute = require("../src/app/api/v1/log/route") as Route;
const sessionsRoute = require("../src/app/api/triage/sessions/route") as Route;
/* eslint-enable @typescript-eslint/no-require-imports */

const NOW = Date.parse("2026-10-24T12:00:00Z");
const parse = (qs: string) => parseLogParams(new URLSearchParams(qs), NOW);

test("уровни: границы severity и обратная карта", () => {
  assert.deepEqual(LEVEL_MIN, { info: 0, low: 3, medium: 5, high: 7, critical: 9 });
  const expected: [number, string][] = [[0, "info"], [2, "info"], [3, "low"], [4, "low"], [5, "medium"], [6, "medium"], [7, "high"], [8, "high"], [9, "critical"], [10, "critical"]];
  for (const [sev, lvl] of expected) assert.equal(levelOf(sev), lvl, String(sev));
});

test("параметры: значения по умолчанию, since/until/limit/format, отказ на мусор", () => {
  const def = parse("");
  assert.ok(def.ok);
  assert.deepEqual(def.params, { fromMs: NOW - 24 * 3600_000, limit: 200, format: "json" });
  assert.equal(parseDuration("15m"), 900_000);
  assert.equal(parseDuration("7d"), 7 * 86_400_000);
  assert.equal(parseDuration("1w"), null);
  const full = parse("log=ci&level=high&actor=bot&node=n1&src_ip=10.0.0.1&action=deploy&since=2h&until=2026-10-24T11:30:00Z&q=token&limit=5&format=ndjson");
  assert.ok(full.ok);
  assert.deepEqual(full.params, {
    log: "ci", level: "high", actor: "bot", node: "n1", src_ip: "10.0.0.1", action: "deploy", q: "token",
    fromMs: NOW - 2 * 3600_000, toMs: Date.parse("2026-10-24T11:30:00Z"), limit: 5, format: "ndjson",
  });
  for (const bad of ["level=urgent", "since=abc", "since=31d", "since=0h", "until=yesterday", "until=2026-10-24", "until=2026-10-20T00:00:00Z&since=1h", "limit=0", "limit=1001", "limit=x", "format=xml", `actor=${"a".repeat(300)}`, "node=a%00b", `q=${"q".repeat(600)}`]) {
    const r = parse(bad);
    assert.equal(r.ok, false, bad);
  }
  const future = parse("until=2030-01-01T00:00:00Z");
  assert.ok(future.ok && future.params.toMs === NOW, "until в будущем режется до «сейчас»");
});

test("SQL: только параметры, фильтры и привязка сессии", () => {
  const p = parse("log=k8s&level=medium&actor=bot&q=secret&limit=10");
  assert.ok(p.ok);
  const { sql, params } = buildLogSql(p.params, { fromMs: NOW - 3600_000, toMs: NOW });
  assert.ok(sql.includes("(source = {log:String} OR source_class = {log:String})"));
  assert.ok(sql.includes("severity >= {sev:UInt8}") && params.sev === 5);
  assert.ok(sql.includes("actor_name = {actor:String}") && params.actor === "bot");
  assert.ok(sql.includes("positionCaseInsensitiveUTF8(concat(object, ' ', raw), {q:String}) > 0"));
  assert.ok(sql.includes("ORDER BY ts DESC LIMIT {limit:UInt32}") && params.limit === 10);
  assert.ok(!sql.includes("bot") && !sql.includes("secret") && !sql.includes("k8s"), "значения не в тексте SQL");
  assert.equal(params.from, "2026-10-24 11:00:00.000");
  const info = parse("level=info");
  assert.ok(info.ok && !buildLogSql(info.params, { fromMs: NOW }).sql.includes("severity >="), "info — без фильтра по severity");
  const bound = buildLogSql(p.params, { fromMs: NOW }, { actors: ["bot"], nodes: ["n1", "n2"] });
  assert.match(bound.sql, /\(actor_name IN \(\{ba0:String\}\) OR node IN \(\{bn0:String\}, \{bn1:String\}\)\)/);
  assert.ok(buildLogSql(p.params, { fromMs: NOW }, { actors: [], nodes: [] }).sql.endsWith(" AND 0 ORDER BY ts DESC LIMIT {limit:UInt32}"), "нечем привязать — ни одной строки");
  assert.equal(logScopeQuery({ ...p.params, node: "n 1", src_ip: "10.0.0.1" }), 'actor:bot node:"n 1" src:10.0.0.1 source:k8s', "кавычки — только где нужны");
});

test("toLogItem: level из severity, attrs — объект, value/unit — числа и строки", () => {
  const item = toLogItem({ ts: "2026-10-24 11:59:00.000", source: "ci.gitlab", source_class: "cicd", action: "job.failed", outcome: "failure", severity: "7", actor_name: "bot", actor_kind: "service", object: "build#1", node: "r1", session_id: "", src_ip: "", dst_ip: "", value: "12.5", unit: "s", attrs: { job: "test" } });
  assert.equal(item.level, "high");
  assert.equal(item.severity, 7);
  assert.equal(item.value, 12.5);
  assert.deepEqual(item.attrs, { job: "test" });
  assert.deepEqual(toLogItem({}).attrs, {});
});

/* ===== Маршрут ===== */

const INC7 = {
  incident_id: "INC-7", rule_id: "a41c-cicd-007", rule_title: "CI job echoed a secret", level: "high", status: "new",
  owner: "", note: "", actor_name: "project_7_bot", node: "runner-07", sources: ["gitlab.ci"], event_count: 1,
  first_ts: "2026-10-12 04:01:38.000", last_ts: "2026-10-12 04:01:38.000", created_at: "2026-10-12 04:02:00", pii: 0,
  chain: [], tags: [], enrichment: [], similar: [],
};
const sqlLog: { sql: string; params: Record<string, string | number> }[] = [];
mocks.queries.incidentGet = async (id) => (id === "INC-7" ? { ...INC7 } : null);
mocks.queries.chQuery = async (sql, params = {}) => {
  sqlLog.push({ sql, params });
  if (sql.includes("FROM events WHERE ts >= parseDateTime64BestEffort({from:String}") && sql.includes("ORDER BY ts DESC")) {
    return [{ ts: "2026-10-24 11:00:00.000", source: "gitlab.ci", source_class: "cicd", action: "job.failed", outcome: "failure", severity: 7, actor_name: "project_7_bot", actor_kind: "service", object: "b", node: "runner-07", session_id: "", src_ip: "", dst_ip: "", value: 0, unit: "", attrs: {} }];
  }
  if (sql.includes("FROM events")) return [{ k: "ip", v: "10.20.4.31" }];
  return [];
};

const req = (qs: string, token: string) => new Request(`http://x/api/v1/log${qs}`, { headers: { authorization: `Bearer ${token}` } });

test("маршрут: токен API — полный доступ, плохие параметры — 400, ndjson", async () => {
  assert.equal((await logRoute.GET!(new Request("http://x/api/v1/log"))).status, 401);
  const r = await logRoute.GET!(req("?log=ci&level=high&since=2h", API));
  assert.equal(r.status, 200);
  const body = await r.json();
  assert.equal(body.count, 1);
  assert.equal(body.items[0].level, "high");
  assert.ok(!("raw" in body.items[0]), "raw не отдаётся");
  const last = sqlLog.at(-1)!;
  assert.equal(last.params.log, "ci");
  assert.equal(last.params.sev, 7);
  for (const bad of ["?level=urgent", "?since=40d", "?limit=5000", "?format=csv", "?until=soon"]) {
    const b = await logRoute.GET!(req(bad, API));
    assert.equal(b.status, 400, bad);
    assert.equal((await b.json()).error, "invalid_value", bad);
  }
  const nd = await logRoute.GET!(req("?format=ndjson", API));
  assert.equal(nd.status, 200);
  assert.ok(nd.headers.get("content-type")?.startsWith("application/x-ndjson"));
  const lines = (await nd.text()).trim().split("\n");
  assert.equal(lines.length, 1);
  assert.equal(JSON.parse(lines[0]).source, "gitlab.ci");
  assert.equal((await logRoute.GET!(req("", ISSUER))).status, 403, "issuer журнал не читает");
});

test("маршрут: токен сессии разбора — только своя область, 403 вне её", async () => {
  const issued = await sessionsRoute.POST!(new Request("http://x/api/triage/sessions", { method: "POST", headers: { authorization: `Bearer ${ISSUER}`, "content-type": "application/json" }, body: JSON.stringify({ incident_id: "INC-7" }) }));
  const issuedText = await issued.text();
  assert.equal(issued.status, 201, issuedText);
  const { token } = JSON.parse(issuedText);
  const get = (qs: string) => logRoute.GET!(req(qs, token));
  const noAnchor = await get("?log=ci");
  assert.equal(noAnchor.status, 403, "без сущности инцидента");
  assert.equal((await noAnchor.json()).error, "out_of_scope");
  const foreign = await get("?actor=other");
  assert.equal(foreign.status, 403);
  assert.equal((await get("?node=web-01")).status, 403);
  assert.equal((await get("?src_ip=203.0.113.9")).status, 403);
  const free = await get("?actor=project_7_bot&q=secret");
  assert.equal(free.status, 400, "свободный текст закрыт");
  const n = sqlLog.length;
  const own = await get("?actor=project_7_bot&log=ci&limit=1000&since=30d");
  const ownText = await own.text();
  assert.equal(own.status, 200, ownText);
  assert.equal(JSON.parse(ownText).count, 1);
  const q = sqlLog.slice(n).find((x) => x.sql.includes("ORDER BY ts DESC"))!;
  assert.ok(q, "запрос к хранилищу выполнен");
  assert.match(q.sql, /\(actor_name IN \(\{ba0:String\}\) OR node IN \(\{bn0:String\}\)\)/, "строки привязаны к субъекту и узлу инцидента");
  assert.equal(q.params.ba0, "project_7_bot");
  assert.equal(q.params.limit, 200, "не больше 200 строк");
  assert.ok(String(q.params.from) >= "2026-09-12 04:01", `окно не раньше first_ts − 30 дней: ${q.params.from}`);
  assert.equal((await get("?actor=project_7_bot&since=1h&until=2026-01-01T00:00:00Z")).status, 400, "until раньше since");
});
