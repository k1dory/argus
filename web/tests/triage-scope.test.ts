// Область чтения токена triage-session: отказ происходит на сервере, а не по
// согласию модели или клиента-агента. Модуль Wazuh включён: частота значений
// считается и по wazuh_alerts.
import { test } from "node:test";
import assert from "node:assert/strict";
import { installNextMocks, loadAuth } from "./_next-mock";
import { checkTriageSearch, incidentAccess, TRIAGE_TTL_MAX_SEC, type TriageScope } from "../src/lib/shared/triage";
import { VERDICT_OK, verdictWith } from "./_verdict-fixture";

const auth = loadAuth();
const mocks = installNextMocks();
const API = "a".repeat(40);
const ISSUER = "i".repeat(40);
process.env.ARGUS_API_TOKEN = API;
process.env.ARGUS_TRIAGE_ISSUER_TOKEN = ISSUER;
process.env.ARGUS_INTEGRATION_WAZUH = "1";

/* eslint-disable @typescript-eslint/no-require-imports -- маршруты грузятся после моков */
type Route = { GET?: (req: Request, ctx?: unknown) => Promise<Response>; POST?: (req: Request) => Promise<Response>; DELETE?: (req: Request) => Promise<Response> };
const sessionsRoute = require("../src/app/api/triage/sessions/route") as Route;
const verdictsRoute = require("../src/app/api/triage/verdicts/route") as Route;
const incidentActions = require("../src/lib/incident-actions") as typeof import("../src/lib/incident-actions");
const contextRoute = require("../src/app/api/triage/context/route") as Route;
const incidentRoute = require("../src/app/api/incidents/[id]/route") as Route;
const incidentsRoute = require("../src/app/api/incidents/route") as Route;
const markdownRoute = require("../src/app/api/incidents/[id]/markdown/route") as Route;
const searchRoute = require("../src/app/api/search/route") as Route;
const sourcesRoute = require("../src/app/api/sources/route") as Route;
const { ipTokenPattern } = require("../src/lib/triage-queries") as typeof import("../src/lib/triage-queries");
const { buildWhere } = require("../src/lib/search") as typeof import("../src/lib/search");
/* eslint-enable @typescript-eslint/no-require-imports */

// Утечка секрета в CI (INC-7), рядом — тот же бот (INC-5) и чужой инцидент INC-9.
const INC7 = {
  incident_id: "INC-7", rule_id: "a41c-cicd-007", rule_title: "CI job echoed a secret", level: "high", status: "new",
  owner: "", note: "", actor_name: "project_7_bot", node: "runner-07", sources: ["gitlab.ci"], event_count: 1,
  first_ts: "2026-10-12 04:01:38.000", last_ts: "2026-10-12 04:01:38.000", created_at: "2026-10-12 04:02:00", pii: 0,
  chain: ["04:01:38 gitlab.ci runner-07 gitlab.build.success REGISTRY_TOKEN=[REDACTED]"], tags: [], enrichment: [], similar: [],
};
const INC5 = { incident_id: "INC-5", level: "medium", rule_id: "a41c-cicd-002", rule_title: "Runner pulled unknown image", status: "closed",
  first_ts: "2026-10-10 11:00:00.000", last_ts: "2026-10-10 11:05:00.000", created_at: "2026-10-10 11:06:00",
  actor_name: "project_7_bot", node: "runner-07", chain: ["секрет"], note: "заметка" };

const sql: string[] = [];
const spreadMock = { fail: false, actor: false };
const sqlParams: Record<string, string | number>[] = [];
mocks.queries.incidentGet = async (id) => (id === "INC-7" ? { ...INC7 } : id === "INC-5" ? { ...INC5 } : id === "INC-9" ? { ...INC7, incident_id: "INC-9", actor_name: "other" } : null);
mocks.queries.chQuery = async (q, params = {}) => {
  sql.push(q);
  sqlParams.push(params);
  // Частота: 10.0.0.53 — DNS, его видят все узлы; 192.0.2.1
  // частый только в wazuh_alerts (семь чужих агентов) — виден, лишь если
  // запрос считает и алерты. spreadMock меняют тесты второго мнения.
  if (q.includes("HAVING uniqExactIf")) {
    if (spreadMock.fail) throw new Error("Code: 159. DB::Exception: Timeout exceeded");
    const out: Record<string, unknown>[] = [{ k: "v", v: "10.0.0.53" }];
    if (q.includes("FROM wazuh_alerts") && Object.values(params).includes("192.0.2.1")) out.push({ k: "v", v: "192.0.2.1" });
    if (spreadMock.actor && q.includes("'actor' AS k")) out.push({ k: "actor", v: params.actor });
    return out;
  }
  if (q.includes("FROM events")) {
    return [{ k: "ip", v: "10.20.4.31" }, { k: "ip", v: "10.0.0.53" }, { k: "ip", v: "192.0.2.1" }, { k: "attr.domain", v: "harbor.example.org" }, { k: "attr.namespace", v: "default" }];
  }
  if (q.includes("multiIf(")) return [{ incident_id: "INC-5", relation: "same_subject" }];
  if (q.includes("WHERE incident_id IN")) return [INC5];
  if (q.includes("GROUP BY status")) return [{ status: "false_positive", c: "9", last_at: "2026-10-01 10:00:00" }, { status: "closed", c: "4", last_at: "2026-10-02 10:00:00" }];
  return [];
};

const req = (path: string, token: string, init: RequestInit = {}) =>
  new Request(`http://x${path}`, { ...init, headers: { authorization: `Bearer ${token}`, "content-type": "application/json", ...(init.headers ?? {}) } });
const params = (id: string) => ({ params: Promise.resolve({ id }) });

async function issue(body: unknown = { incident_id: "INC-7" }): Promise<Response> {
  return sessionsRoute.POST!(req("/api/triage/sessions", ISSUER, { method: "POST", body: JSON.stringify(body) }));
}

async function session(): Promise<{ token: string; incident_id: string; related_ids: string[]; expires_at: string }> {
  const res = await issue();
  assert.equal(res.status, 201);
  return res.json();
}

test("выпуск: по incident_id, связанные посчитаны сервером, срок не больше часа", async () => {
  const s = await session();
  assert.equal(s.incident_id, "INC-7");
  assert.deepEqual(s.related_ids, ["INC-5"]);
  const ttl = Date.parse(s.expires_at) - Date.now();
  assert.ok(ttl > 0 && ttl <= TRIAGE_TTL_MAX_SEC * 1000, "срок не больше часа");
  assert.ok(!sql.some((q) => q.includes("webhook_deliveries")), "внешний id задачи консоль не читает");
  assert.ok(mocks.audit.some((a) => a.action === "triage.session" && a.target === "INC-7"), "выпуск в журнале");
});

test("выпуск: incident_id обязателен и проверяется по форме и по хранилищу", async () => {
  assert.equal((await issue({})).status, 400, "без incident_id сессии нет");
  assert.equal((await issue({ incident_id: 187 })).status, 400, "число — не id инцидента");
  assert.equal((await issue({ incident_id: "INC-7 OR 1=1" })).status, 400);
  assert.equal((await issue({ incident_id: "INC-404" })).status, 404, "инцидента нет в хранилище");
  assert.equal((await issue({ incident_id: "INC-7", ttl_sec: 7200 })).status, 400, "больше часа — нельзя");
  assert.equal((await issue({ incident_id: "INC-7", ttl_sec: 600 })).status, 201);
});

test("выпуск: только triage-issuer; issuer ничего не читает", async () => {
  const viaApi = await sessionsRoute.POST!(req("/api/triage/sessions", API, { method: "POST", body: JSON.stringify({ incident_id: "INC-7" }) }));
  assert.equal(viaApi.status, 403, "ARGUS_API_TOKEN сессии не выпускает");
  const r = await incidentRoute.GET!(req("/api/incidents/INC-7", ISSUER), params("INC-7"));
  assert.equal(r.status, 403, "issuer не читает инциденты");
  process.env.ARGUS_TRIAGE_ISSUER_TOKEN = API;
  try {
    const same = await sessionsRoute.POST!(req("/api/triage/sessions", API, { method: "POST", body: JSON.stringify({ incident_id: "INC-7" }) }));
    assert.equal(same.status, 403, "токен issuer, равный ARGUS_API_TOKEN, не действует");
  } finally {
    process.env.ARGUS_TRIAGE_ISSUER_TOKEN = ISSUER;
process.env.ARGUS_INTEGRATION_WAZUH = "1";
  }
});

test("чтение своего INC — полностью, связанного — сводкой, чужого — 403 out_of_scope", async () => {
  const { token } = await session();
  const own = await incidentRoute.GET!(req("/api/incidents/INC-7", token), params("INC-7"));
  assert.equal(own.status, 200);
  assert.equal((await own.json()).incident.actor_name, "project_7_bot");

  const rel = await incidentRoute.GET!(req("/api/incidents/INC-5", token), params("INC-5"));
  assert.equal(rel.status, 200);
  const body = await rel.json();
  assert.equal(body.scope, "related");
  assert.equal(body.incident.relation, "same_subject");
  for (const hidden of ["actor_name", "node", "chain", "note", "comments"]) assert.ok(!(hidden in body.incident), `в сводке нет ${hidden}`);

  const foreign = await incidentRoute.GET!(req("/api/incidents/INC-9", token), params("INC-9"));
  assert.equal(foreign.status, 403);
  assert.equal((await foreign.json()).error, "out_of_scope");
  // Существующий в базе, но чужой — тот же отказ, что и несуществующий: перебором не узнать.
  const missing = await incidentRoute.GET!(req("/api/incidents/INC-404", token), params("INC-404"));
  assert.equal(missing.status, 403);
});

test("список инцидентов, markdown и выгрузка поиска сессии разбора закрыты", async () => {
  const { token } = await session();
  assert.equal((await incidentsRoute.GET!(req("/api/incidents", token))).status, 403);
  assert.equal((await markdownRoute.GET!(req("/api/incidents/INC-7/markdown", token), params("INC-7"))).status, 403);
  assert.equal((await searchRoute.GET!(req(`/api/search?index=events&format=export&q=${encodeURIComponent('actor:"project_7_bot"')}`, token))).status, 403);
  assert.equal((await searchRoute.GET!(req(`/api/search?index=events&format=csv&q=${encodeURIComponent('actor:"project_7_bot"')}`, token))).status, 403);
  assert.equal((await searchRoute.GET!(req(`/api/search?index=events&raw=1&q=${encodeURIComponent('actor:"project_7_bot"')}`, token))).status, 403);
  assert.equal((await sourcesRoute.GET!(req("/api/sources", token))).status, 200, "живость источников доступна");
});

test("поиск по чужой сущности — 403, по своей — проходит проверку области", async () => {
  const { token } = await session();
  const get = (q: string, extra = "") => searchRoute.GET!(req(`/api/search?index=events&q=${encodeURIComponent(q)}${extra}`, token));
  for (const q of ['actor:"other"', 'node:"web-01"', 'src:"203.0.113.9"', 'attr.domain:"evil.example"', "action:secret_read", 'actor:"other" action:"secret_read"']) {
    const r = await get(q);
    assert.equal(r.status, 403, q);
    assert.equal((await r.json()).error, "out_of_scope", q);
  }
  // Своя сущность: проверка области пройдена, дальше — хранилище (в тесте его нет, ответ 400 с ошибкой хранилища).
  for (const q of ['actor:"project_7_bot"', 'src:"10.20.4.31" action:"session.allow"', 'attr.domain:"harbor.example.org"', 'actor:"project_7_bot" attr.project:"sec/argus"']) {
    const r = await get(q);
    assert.notEqual(r.status, 403, q);
    const b = await r.json();
    assert.notEqual(b.error, "out_of_scope", q);
  }
  assert.equal((await get('actor:"project_7_bot"', "&page=5")).status, 403, "больше 200 строк");
  assert.equal((await get('-actor:"project_7_bot"')).status, 400, "отрицание");
  assert.equal((await get("actor:project_7_*")).status, 400, "маска");
  assert.equal((await get("")).status, 400, "без фильтра");
  // Свободный текст (подстрока по raw) закрыт даже для своей сущности — как QueryStrict.
  assert.equal((await get('"harbor.example.org"')).status, 400, "свободный текст");
  assert.equal((await get('actor:~"project_7*"')).status, 400, "маска ~\"…\"");
  assert.equal((await get('actor:"project_7*"')).status, 400, "старая маска в кавычках");
});

test("контекст: связанные с типом связи, счётчики правила, без чужих данных", async () => {
  const { token } = await session();
  const r = await contextRoute.GET!(req("/api/triage/context", token));
  assert.equal(r.status, 200);
  const b = await r.json();
  assert.equal(b.incident.incident_id, "INC-7");
  assert.deepEqual(b.related, [{ relation: "same_subject", incident_id: "INC-5", level: "medium", rule_id: "a41c-cicd-002", rule_title: "Runner pulled unknown image",
    status: "closed", first_ts: "2026-10-10 11:00:00.000", last_ts: "2026-10-10 11:05:00.000", created_at: "2026-10-10 11:06:00" }]);
  assert.deepEqual(b.rule_history, { window_days: 90, total: 13, by_status: { false_positive: 9, closed: 4 }, last_false_positive_at: "2026-10-01 10:00:00" });
  assert.equal(b.session.incident_id, "INC-7");
  // Якоря шлюза — те же сущности области с видом, что проверяет поиск.
  assert.ok(Array.isArray(b.session.anchors) && b.session.anchors.length > 0);
  assert.ok(b.session.anchors.some((a: { kind: string; value: string }) => a.kind === "actor" && a.value === "project_7_bot"), "свой субъект");
  for (const a of b.session.anchors) assert.ok(["actor", "node", "ip"].includes(a.kind) || a.kind.startsWith("attr."), a.kind);
  assert.ok(!b.session.anchors.some((a: { kind: string }) => ["attr.project", "attr.namespace", "attr.job"].includes(a.kind)), "project/namespace/job — не якоря");
  // Обычный API-токен контекста сессии не имеет.
  assert.equal((await contextRoute.GET!(req("/api/triage/context", API))).status, 403);
});

test("токен: подделка, чужой ключ и отзыв не проходят", async () => {
  const { token } = await session();
  const [h, p, sig] = token.split(".");
  const forged = JSON.parse(Buffer.from(p, "base64url").toString());
  forged.sub = "INC-9";
  const tampered = [h, Buffer.from(JSON.stringify(forged)).toString("base64url"), sig].join(".");
  assert.equal(await auth.apiSession(req("/api/triage/context", tampered)), null, "подменённый инцидент");
  // JWT сессии консоли (тот же секрет auth.json, другой ключ) за токен разбора не сойдёт.
  const consoleJwt = await auth.signSessionToken("admin", "admin", false);
  assert.equal(await auth.apiSession(req("/api/triage/context", consoleJwt)), null);

  const del = await sessionsRoute.DELETE!(req("/api/triage/sessions", token, { method: "DELETE" }));
  assert.equal(del.status, 204);
  const after = await incidentRoute.GET!(req("/api/incidents/INC-7", token), params("INC-7"));
  assert.equal(after.status, 401, "после отзыва токен не действует");
});

test("отзыв переживает рестарт web: список читается из ClickHouse; без него токены не принимаются", async () => {
  const stored = new Map<string, number>();
  mocks.queries.saveTriageRevocation = async (sid, _inc, exp) => void stored.set(sid, Date.parse(exp));
  mocks.queries.triageRevocations = async () => new Map(stored);
  try {
    const { token } = await session();
    assert.equal((await sessionsRoute.DELETE!(req("/api/triage/sessions", token, { method: "DELETE" }))).status, 204);
    assert.equal(stored.size, 1, "отзыв записан в базу");
    auth.forgetTriageMemory(); // рестарт процесса: память пуста
    assert.equal(await auth.apiSession(req("/api/triage/context", token)), null, "после рестарта отозванный токен не действует");
    const fresh = await session();
    assert.ok(await auth.apiSession(req("/api/triage/context", fresh.token)), "неотозванный — действует");

    // ClickHouse недоступен при первом чтении списка — отказ, затем повтор.
    auth.forgetTriageMemory();
    mocks.queries.triageRevocations = async () => { throw new Error("ECONNREFUSED"); };
    assert.equal(await auth.apiSession(req("/api/triage/context", fresh.token)), null, "без списка отзывов — отказ");
    mocks.queries.triageRevocations = async () => new Map(stored);
    assert.ok(await auth.apiSession(req("/api/triage/context", fresh.token)), "список прочитан — токен действует");

    // Запись отзыва не удалась — 503, сессия не считается отозванной.
    mocks.queries.saveTriageRevocation = async () => { throw new Error("ECONNREFUSED"); };
    assert.equal((await sessionsRoute.DELETE!(req("/api/triage/sessions", fresh.token, { method: "DELETE" }))).status, 503);
  } finally {
    mocks.queries.saveTriageRevocation = async () => undefined;
    mocks.queries.triageRevocations = async () => new Map();
    auth.forgetTriageMemory();
  }
});

test("лимит запросов на сессию: свой бюджет, 429 budget_exhausted", async () => {
  process.env.ARGUS_TRIAGE_SESSION_REQUESTS = "3";
  try {
    const { token } = await session();
    const other = await session();
    for (let i = 0; i < 3; i++) assert.equal((await incidentRoute.GET!(req("/api/incidents/INC-7", token), params("INC-7"))).status, 200);
    const r = await incidentRoute.GET!(req("/api/incidents/INC-7", token), params("INC-7"));
    assert.equal(r.status, 429);
    assert.equal((await r.json()).error, "budget_exhausted");
    assert.equal((await incidentRoute.GET!(req("/api/incidents/INC-7", other.token), params("INC-7"))).status, 200, "у другой сессии свой бюджет");
  } finally {
    delete process.env.ARGUS_TRIAGE_SESSION_REQUESTS;
  }
});

/* ===== Чистые проверки области ===== */

const scope: TriageScope = {
  sessionId: "s1", incidentId: "INC-7", related: { "INC-5": "same_subject" },
  entities: [{ kind: "actor", value: "project_7_bot" }, { kind: "node", value: "runner-07" }, { kind: "ip", value: "10.20.4.31" }, { kind: "attr.domain", value: "harbor.example.org" }],
  bind: { actors: ["project_7_bot"], nodes: ["runner-07"] },
  searchFrom: "2026-09-12T04:01:38.000Z", expiresAt: "2026-10-12T05:00:00.000Z",
};
const base = { index: "events" as const, range: "24h" as const, page: 1, pageSize: 50 };
const NOW = Date.parse("2026-10-12T06:00:00Z");

test("incidentAccess: свой, связанный, остальные", () => {
  assert.equal(incidentAccess(scope, "INC-7"), "own");
  assert.equal(incidentAccess(scope, "INC-5"), "related");
  assert.equal(incidentAccess(scope, "INC-9"), "out_of_scope");
  assert.equal(incidentAccess(scope, "__proto__"), "out_of_scope");
});

test("окно поиска: не раньше first_ts − 30 дней", () => {
  const early = checkTriageSearch(scope, { ...base, q: 'actor:"project_7_bot"', from: "2026-01-01T00:00", to: "2026-10-01T00:00" }, NOW);
  assert.deepEqual(early, { ok: true, from: "2026-09-12T04:01", to: "2026-10-01T00:00" });
  const tooEarly = checkTriageSearch(scope, { ...base, q: 'actor:"project_7_bot"', from: "2026-01-01T00:00", to: "2026-02-01T00:00" }, NOW);
  assert.equal(tooEarly.ok, false);
  const range = checkTriageSearch(scope, { ...base, q: 'actor:"project_7_bot"', range: "30d" }, NOW);
  assert.ok(range.ok && range.from === "2026-09-12T06:00", JSON.stringify(range));
});

test("значение с оператором внутри кавычек — один литерал, но всё равно чужое", () => {
  // Значение из события с оператором внутри — не сущность инцидента.
  const r = checkTriageSearch(scope, { ...base, q: 'actor:"project_7_bot -action:secret_read"' }, NOW);
  assert.equal(r.ok, false);
  assert.ok(!r.ok && r.error === "out_of_scope");
  // Без кавычек — отрицание и отказ.
  const neg = checkTriageSearch(scope, { ...base, q: "actor:project_7_bot -action:secret_read" }, NOW);
  assert.ok(!neg.ok && neg.error === "invalid_value");
});

test("алерты: якорь — агент или srcip инцидента", () => {
  assert.equal(checkTriageSearch(scope, { ...base, index: "alerts", q: 'agent:"runner-07"' }, NOW).ok, true);
  assert.equal(checkTriageSearch(scope, { ...base, index: "alerts", q: 'srcip:"10.20.4.31" rule:5710' }, NOW).ok, true);
  const desc = checkTriageSearch(scope, { ...base, index: "alerts", q: 'agent:"runner-07" desc:"x"' }, NOW);
  assert.ok(!desc.ok && desc.error === "invalid_value", "свободный текст по полю недоступен");
});

/* ===== Правки ревью области разбора ===== */

test("S1: каждое поле-сущность — из области, а не хотя бы одно", () => {
  // Примеры ревью: рядом с якорем node — догадка о логине или о секрете.
  const s1: TriageScope = { ...scope, entities: [{ kind: "actor", value: "ci-bot" }, { kind: "node", value: "runner-01" }, { kind: "ip", value: "10.0.0.53" }] };
  const guess = checkTriageSearch(s1, { ...base, q: 'node:"runner-01" actor:"a.sidorova"' }, NOW);
  assert.ok(!guess.ok && guess.status === 403 && guess.error === "out_of_scope", JSON.stringify(guess));
  const secret = checkTriageSearch(s1, { ...base, q: 'node:"runner-01" attr.password:"Hunter2"' }, NOW);
  assert.ok(!secret.ok && secret.error === "invalid_value", "attr.* — только из списка");
  assert.equal(checkTriageSearch(s1, { ...base, q: 'node:"runner-01" actor:"ci-bot"' }, NOW).ok, true, "обе сущности свои");
  // Вид сущности: IP — только в src/dst, узел — только в node.
  assert.ok(!checkTriageSearch(s1, { ...base, q: 'actor:"10.0.0.53"' }, NOW).ok, "IP в поле субъекта не якорь");
  assert.ok(!checkTriageSearch(s1, { ...base, q: 'attr.domain:"runner-01"' }, NOW).ok, "узел в attr.domain не якорь");
  assert.equal(checkTriageSearch(s1, { ...base, q: 'dst:"10.0.0.53"' }, NOW).ok, true);
  assert.equal(checkTriageSearch(s1, { ...base, index: "alerts", q: 'srcip:"10.0.0.53"' }, NOW).ok, true);
  assert.ok(!checkTriageSearch(s1, { ...base, index: "alerts", q: 'agent:"10.0.0.53"' }, NOW).ok);
});

test("S2: project, namespace, job — фильтры, но не якоря", () => {
  const s2: TriageScope = { ...scope, entities: [{ kind: "node", value: "runner-01" }] };
  for (const q of ['attr.namespace:"default"', 'attr.job:"build"', 'attr.project:"sec/argus"']) {
    const r = checkTriageSearch(s2, { ...base, q }, NOW);
    assert.ok(!r.ok && r.status === 403, q);
    assert.equal(checkTriageSearch(s2, { ...base, q: `node:"runner-01" ${q}` }, NOW).ok, true, `${q} рядом с якорем`);
  }
});

test("S2: частое значение (DNS) не якорь; namespace не сущность; порог из конфига", async () => {
  process.env.ARGUS_TRIAGE_ANCHOR_MAX_SPREAD = "7";
  try {
    const n = sql.length;
    const { token } = await session();
    const freq = sql.slice(n).findIndex((q) => q.includes("HAVING uniqExactIf"));
    assert.ok(freq >= 0, "частота значений считается при выпуске");
    assert.equal(sqlParams[n + freq].spread, 7, "порог — ARGUS_TRIAGE_ANCHOR_MAX_SPREAD");
    const get = (q: string) => searchRoute.GET!(req(`/api/search?index=events&q=${encodeURIComponent(q)}`, token));
    for (const q of ['dst:"10.0.0.53"', 'attr.namespace:"default"']) {
      const r = await get(q);
      assert.equal(r.status, 403, q);
    }
    assert.notEqual((await get('src:"10.20.4.31"')).status, 403, "редкий IP инцидента — якорь");
  } finally {
    delete process.env.ARGUS_TRIAGE_ANCHOR_MAX_SPREAD;
  }
});

test("S2: фасеты сессии разбора не считаются и не отдаются", async () => {
  const { token } = await session();
  const bodies: string[] = [];
  const realFetch = globalThis.fetch;
  globalThis.fetch = (async (_url: unknown, init?: RequestInit) => {
    bodies.push(String(init?.body ?? ""));
    return new Response("", { status: 200 });
  }) as typeof fetch;
  try {
    const r = await searchRoute.GET!(req(`/api/search?index=events&q=${encodeURIComponent('actor:"project_7_bot"')}`, token));
    assert.equal(r.status, 200);
    assert.deepEqual((await r.json()).facets, []);
    assert.ok(bodies.length > 0, "строки и гистограмма — из хранилища");
    assert.ok(!bodies.some((b) => b.includes("LIMIT 6 BY field")), "запроса фасетов нет");
  } finally {
    globalThis.fetch = realFetch;
  }
});

test("S4: same_remote_ip — по границам токена, не подстрокой", async () => {
  const re = new RegExp(ipTokenPattern("10.0.0.1"));
  for (const hit of ["10.0.0.1", "ssh from 10.0.0.1 port 22", "10.0.0.1:443", "(10.0.0.1)"]) assert.ok(re.test(hit), hit);
  for (const miss of ["10.0.0.15", "10.0.0.100", "110.0.0.1", "src=10.0.0.10"]) assert.ok(!re.test(miss), miss);
  const v6 = new RegExp(ipTokenPattern("fe80::1"));
  assert.ok(v6.test("from fe80::1 port 22") && !v6.test("fe80::1a"));
  const n = sql.length;
  await session();
  const rel = sql.slice(n).find((q) => q.includes("multiIf("))!;
  assert.ok(rel.includes("multiMatchAny") && !rel.includes("multiSearchAny(c"), rel);
});

test("S5: закрытие сессии не тратит бюджет — проходит и после 429", async () => {
  process.env.ARGUS_TRIAGE_SESSION_REQUESTS = "2";
  try {
    const { token } = await session();
    for (let i = 0; i < 2; i++) assert.equal((await incidentRoute.GET!(req("/api/incidents/INC-7", token), params("INC-7"))).status, 200);
    assert.equal((await incidentRoute.GET!(req("/api/incidents/INC-7", token), params("INC-7"))).status, 429);
    assert.equal((await sessionsRoute.DELETE!(req("/api/triage/sessions", token, { method: "DELETE" }))).status, 204);
  } finally {
    delete process.env.ARGUS_TRIAGE_SESSION_REQUESTS;
  }
});

test("токен со строковыми сущностями (старый формат) не даёт якорей", async () => {
  const { token } = await session();
  const s = await auth.apiSession(req("/api/triage/context", token));
  assert.ok(s?.triage && s.triage.entities.every((e) => typeof e.kind === "string" && typeof e.value === "string"));
  assert.ok(s.triage.entities.some((e) => e.kind === "ip" && e.value === "10.20.4.31"));
  assert.ok(!s.triage.entities.some((e) => e.value === "10.0.0.53" || e.value === "default"), "частое и namespace — не в области");
});

/* ===== Второе мнение ревью (security-repro.patch): каждый обход — отказ ===== */

test("S1: регистр значим — OwnBot и ownbot разные субъекты", () => {
  const s1: TriageScope = { ...scope, entities: [{ kind: "actor", value: "OwnBot" }, { kind: "node", value: "own-runner" }, { kind: "actor", value: "svc" }] };
  const lower = checkTriageSearch(s1, { ...base, q: 'actor:"ownbot"' }, NOW);
  assert.ok(!lower.ok && lower.status === 403, "ownbot — чужой субъект, хоть и отличается только регистром");
  assert.equal(checkTriageSearch(s1, { ...base, q: 'actor:"OwnBot"' }, NOW).ok, true);
  assert.ok(!checkTriageSearch(s1, { ...base, q: 'actor:"SVC"' }, NOW).ok);
  assert.ok(!checkTriageSearch(s1, { ...base, q: 'node:"OWN-RUNNER"' }, NOW).ok);
});

test("S2: частота — по всему окну поиска и по wazuh_alerts; частый в алертах IP не якорь", async () => {
  const n = sql.length;
  const { token } = await session();
  const i = sql.slice(n).findIndex((q) => q.includes("HAVING uniqExactIf"));
  assert.ok(i >= 0);
  const q = sql[n + i];
  const ps = sqlParams[n + i];
  assert.ok(q.includes("FROM wazuh_alerts") && q.includes("FROM events"), "оба индекса");
  assert.equal(ps.days, 30, "от first_ts − 30 дней");
  assert.ok(!/\+ INTERVAL/.test(q), "без верхней границы окна инцидента: до текущего момента");
  assert.ok(q.includes("'actor' AS k") && q.includes("'node' AS k"), "субъект и узел инцидента тоже проверяются");
  const alerts = await searchRoute.GET!(req(`/api/search?index=alerts&q=${encodeURIComponent('srcip:"192.0.2.1"')}`, token));
  assert.equal(alerts.status, 403, "IP частый в алертах — не якорь (проба srcip:192.0.2.1)");
  assert.equal((await searchRoute.GET!(req(`/api/search?index=events&q=${encodeURIComponent('dst:"10.0.0.53"')}`, token))).status, 403, "проба dst DNS-IP");
});

test("S2: частый субъект инцидента (root) — только в паре и строки не привязывает", async () => {
  spreadMock.actor = true;
  try {
    const { token } = await session();
    const s = await auth.apiSession(req("/api/triage/context", token));
    assert.deepEqual(s?.triage?.bind, { actors: [], nodes: ["runner-07"] }, "частый субъект не открывает свои события на всех узлах");
    const get = (q: string) => searchRoute.GET!(req(`/api/search?index=events&q=${encodeURIComponent(q)}`, token));
    assert.equal((await get('actor:"project_7_bot"')).status, 403, "один частый субъект — отказ");
    assert.notEqual((await get('actor:"project_7_bot" node:"runner-07"')).status, 403, "в паре с узлом — можно");
  } finally {
    spreadMock.actor = false;
  }
});

test("S2: подсчёт частоты не уложился — сессия выдаётся, якорей нет (не 503)", async () => {
  spreadMock.fail = true;
  try {
    const res = await issue();
    assert.equal(res.status, 201);
    const { token } = await res.json();
    const s = await auth.apiSession(req("/api/triage/context", token));
    assert.ok(s?.triage);
    assert.ok(!s.triage.entities.some((e) => e.kind === "ip" || e.kind.startsWith("attr.")), "значения не якоря");
    assert.ok(s.triage.entities.every((e) => e.weak), "субъект и узел — только в паре");
    const get = (q: string) => searchRoute.GET!(req(`/api/search?index=events&q=${encodeURIComponent(q)}`, token));
    assert.equal((await get('src:"10.20.4.31"')).status, 403);
    assert.equal((await get('node:"runner-07"')).status, 403);
    assert.notEqual((await get('actor:"project_7_bot" node:"runner-07"')).status, 403);
  } finally {
    spreadMock.fail = false;
  }
});

test("S2: обязательный предикат привязки — в каждом запросе поиска сессии", async () => {
  const ev = buildWhere({ index: "events", q: 'dst:"203.0.113.53"', range: "30d", page: 1, bind: { actors: ["OwnBot"], nodes: ["own-runner"] } });
  assert.match(ev.where, /\(actor_name IN \(\{p\d+:String\}\) OR node IN \(\{p\d+:String\}\)\)/);
  assert.ok(Object.values(ev.params).includes("OwnBot") && Object.values(ev.params).includes("own-runner"));
  const al = buildWhere({ index: "alerts", q: 'srcip:"192.0.2.1"', range: "30d", page: 1, bind: { actors: ["OwnBot"], nodes: ["own-runner"] } });
  assert.match(al.where, /agent_name IN \(\{p\d+:String\}\)/);
  assert.ok(!al.where.includes("actor_name"), "у алертов субъекта нет — только агенты");
  const none = buildWhere({ index: "events", q: 'dst:"203.0.113.53"', range: "30d", page: 1, bind: { actors: [], nodes: [] } });
  assert.ok(none.where.endsWith(" AND 0"), "нечем привязать — ни одной строки");
  // Маршрут: SQL строк и гистограммы уходит с предикатом.
  const { token } = await session();
  const bodies: string[] = [];
  const urls: string[] = [];
  const realFetch = globalThis.fetch;
  globalThis.fetch = (async (url: unknown, init?: RequestInit) => {
    urls.push(String(url));
    bodies.push(String(init?.body ?? ""));
    return new Response("", { status: 200 });
  }) as typeof fetch;
  try {
    assert.equal((await searchRoute.GET!(req(`/api/search?index=events&q=${encodeURIComponent('src:"10.20.4.31"')}`, token))).status, 200);
  } finally {
    globalThis.fetch = realFetch;
  }
  assert.ok(bodies.length >= 2 && bodies.every((b) => /actor_name IN \(.*\) OR node IN \(/.test(b)), "строки и гистограмма — с привязкой");
  assert.ok(urls.every((u) => u.includes("project_7_bot") && u.includes("runner-07")));
});

// Вердикт агента: пишется в ARGUS самим токеном triage-session, после записи
// выпуск сессии по инциденту — 409 verdict_published, снимает отметку только
// человек в консоли.
test("вердикт: только токен сессии, схема и область проверяются, запись — в agent_verdicts и комментарий", async () => {
  const store = installVerdictStore();
  try {
    const { token, related_ids } = await session();
    assert.deepEqual(related_ids, ["INC-5"]);
    const post = (tok: string, body: unknown) => verdictsRoute.POST!(req("/api/triage/verdicts", tok, { method: "POST", body: typeof body === "string" ? body : JSON.stringify(body) }));
    assert.equal((await post(API, VERDICT_OK)).status, 403, "ARGUS_API_TOKEN вердикт не пишет");
    assert.equal((await post(ISSUER, VERDICT_OK)).status, 403, "triage-issuer — тоже");
    assert.equal((await post(token, "{not json")).status, 400);
    assert.equal((await post(token, [1])).status, 400);
    assert.equal((await post(token, { ...VERDICT_OK, agent: "Bad Agent!" })).status, 400, "имя агента — токен");
    const big = await post(token, verdictWith({ gaps: ["x".repeat(70_000)] }));
    assert.equal(big.status, 413);

    const expect422 = async (body: unknown, path: string, code: string, why: string) => {
      const r = await post(token, body);
      assert.equal(r.status, 422, why);
      const b = await r.json();
      assert.equal(b.error, "invalid_verdict", why);
      assert.ok(b.rejections.some((x: { path: string; code: string }) => x.path === path && x.code === code), `${why}: ${JSON.stringify(b.rejections)}`);
    };
    await expect422(verdictWith({ extra: 1 }), "/extra", "schema", "лишнее поле");
    await expect422(verdictWith({ summary: "см. http://evil.example.org/x" }), "/summary", "schema", "ссылка в тексте — отказ схемы");
    await expect422(verdictWith({ verdict: "false_positive" }), "", "schema", "FP без независимого довода benign — условие между полями");
    await expect422(verdictWith({ incident_id: "INC-9" }), "/incident_id", "incident", "чужой инцидент при схемно верном документе");
    await expect422(verdictWith({ level: "low" }), "/level", "incident", "уровень не инцидента сессии");
    await expect422(verdictWith({ related: [{ incident_id: "INC-9", relation: "same_subject" }] }), "/related/0/incident_id", "unknown_ref", "related вне области");
    await expect422(verdictWith({ evidence: [{ ...VERDICT_OK.evidence[0], refs: ["INC-9"] }] }), "/evidence/0/refs/0", "unknown_ref", "ссылка довода вне области");
    await expect422(verdictWith({ gaps: ["см. INC-9"] }), "/gaps/0", "unknown_ref", "чужой номер инцидента в тексте");
    await expect422(verdictWith({ summary: "пишите mention:ops" }), "/summary", "unsafe_text", "схема ссылки без ://");
    await expect422(verdictWith({ summary: "скры\u200bтый текст" }), "/summary", "unsafe_text", "невидимый символ");
    assert.equal(store.verdicts.length, 0, "ни один отказ не записан");

    const ok = await post(token, { ...VERDICT_OK, agent: "triage-bot" });
    const okText = await ok.text();
    assert.equal(ok.status, 201, okText);
    const body = JSON.parse(okText);
    assert.equal(body.incident_id, "INC-7");
    assert.ok(body.id && body.markdown.startsWith("**Вердикт агента: подтверждённая атака (true positive) · нужен человек: да."), body.markdown);
    assert.equal(store.verdicts.length, 1);
    assert.equal(store.verdicts[0].agent, "triage-bot");
    assert.equal(store.verdicts[0].verdict, "true_positive");
    assert.equal(store.verdicts[0].human_needed, 1);
    assert.deepEqual(store.comments.map((c) => c.author), ["agent:triage-bot"]);
    assert.equal(store.comments[0].body, body.markdown);
    assert.ok(mocks.audit.some((a) => a.action === "triage.verdict" && a.target === "INC-7"));

    const again = await post(token, VERDICT_OK);
    assert.equal(again.status, 409, "одна сессия — один вердикт");
    assert.equal((await again.json()).error, "verdict_exists");
    assert.equal(store.verdicts.length, 1);

    const reissue = await issue();
    assert.equal(reissue.status, 409);
    assert.equal((await reissue.json()).error, "verdict_published");

    // Человек в консоли (аналитик) разрешает повторный разбор.
    await auth.getAuthState();
    const created = await auth.createUser("triage-analyst", "analyst");
    assert.ok("password" in created);
    await auth.createSession("triage-analyst", "analyst");
    const before = mocks.audit.length;
    const r = await incidentActions.reopenTriageAction({ error: null }, formDataOf({ incident_id: "INC-7" }));
    assert.equal(r.error, null, String(r.error));
    assert.ok(mocks.audit.slice(before).some((a) => a.action === "triage.reopen" && a.target === "INC-7"));
    assert.deepEqual(store.log.map((x) => x.state), ["claim", "reopened"]);
    assert.equal((await issue()).status, 201, "после разрешения — сессия выдаётся");
    const none = await incidentActions.reopenTriageAction({ error: null }, formDataOf({ incident_id: "INC-7" }));
    assert.ok(none.error, "снимать больше нечего");
  } finally {
    resetVerdictStore();
  }
});

// Две сессии одного инцидента получили доступ до первой записи — записать
// вердикт может только одна; после reopened — снова можно.
test("вердикт: вторая сессия того же инцидента — 409 verdict_published, после reopened — снова можно", async () => {
  const store = installVerdictStore();
  try {
    const a = await session();
    const b = await session();
    const post = (tok: string) => verdictsRoute.POST!(req("/api/triage/verdicts", tok, { method: "POST", body: JSON.stringify(VERDICT_OK) }));
    assert.equal((await post(a.token)).status, 201);
    const second = await post(b.token);
    assert.equal(second.status, 409);
    assert.equal((await second.json()).error, "verdict_published");
    assert.equal(store.verdicts.length, 1, "вердикт второй сессии не записан");
    assert.ok(mocks.audit.some((x) => x.action === "triage.verdict_conflict"));
    await mocks.queries.saveTriageVerdict({ incidentId: "INC-7", state: "reopened", sessionId: "", actor: "triage-analyst" });
    assert.equal((await post(b.token)).status, 201, "новое поколение — вторая сессия пишет");
    assert.equal(store.verdicts.length, 2);
  } finally {
    resetVerdictStore();
  }
});

// Гонка: сессии прочли «отметки нет» и вызывают claim одновременно. Мок ведёт
// себя как ClickHouse с дедупликацией: первый claim эпохи занимает её целиком,
// остальные получают чужого победителя. Реальная конкурентность — в
// triage-claim-ch.test.ts.
test("вердикт: параллельные сессии — ровно один 201, остальные 409, победитель один", async () => {
  const store = installVerdictStore();
  try {
    const tokens = await Promise.all(Array.from({ length: 8 }, () => session().then((s) => s.token)));
    const res = await Promise.all(tokens.map((t) => verdictsRoute.POST!(req("/api/triage/verdicts", t, { method: "POST", body: JSON.stringify(VERDICT_OK) }))));
    const statuses = res.map((r) => r.status);
    assert.equal(statuses.filter((s) => s === 201).length, 1, `ровно один победитель: ${statuses}`);
    assert.equal(statuses.filter((s) => s === 409).length, tokens.length - 1);
    assert.equal(store.log.filter((r) => r.state === "claim").length, 1, "claim записан один раз");
    assert.equal(store.verdicts.length, 1);
    assert.equal(await mocks.queries.triageVerdictWinner("INC-7"), store.verdicts[0].session_id, "победитель неизменяем");
  } finally {
    resetVerdictStore();
  }
});

type LogRow = { incidentId: string; state: string; sessionId: string; actor: string };
type StoredVerdict = { incident_id: string; session_id: string; agent: string; verdict: string; human_needed: number; markdown: string };

/** Хранилище как argus.triage_verdict_claims_v2 / triage_verdicts / agent_verdicts /
 *  incident_comments: claim первой сессии эпохи неизменяем, reopened открывает
 *  новую эпоху, один вердикт на сессию. */
function installVerdictStore(): { log: LogRow[]; verdicts: StoredVerdict[]; comments: { author: string; body: string }[] } {
  const log: LogRow[] = [];
  const verdicts: StoredVerdict[] = [];
  const comments: { author: string; body: string }[] = [];
  const owner = new Map<string, string>();
  const delay = () => new Promise<void>((r) => setImmediate(r));
  mocks.queries.saveTriageVerdict = async (m) => {
    log.push({ ...m });
    owner.delete(m.incidentId);
  };
  mocks.queries.claimTriageVerdict = async (m) => {
    await delay();
    if (!owner.has(m.incidentId)) {
      owner.set(m.incidentId, m.sessionId);
      log.push({ incidentId: m.incidentId, state: "claim", sessionId: m.sessionId, actor: m.actor });
    }
    await delay();
    return owner.get(m.incidentId)!;
  };
  mocks.queries.triageVerdictClaim = async (inc) => (owner.has(inc) ? { incident_id: inc, session_id: owner.get(inc)!, claimed_at: "2026-10-12 05:00:00.000" } : null);
  mocks.queries.triageVerdictWinner = async (inc) => owner.get(inc) ?? null;
  mocks.queries.saveAgentVerdict = async (row) => void verdicts.push(row as StoredVerdict);
  mocks.queries.agentVerdictBySession = async (inc, sid) => verdicts.find((v) => v.incident_id === inc && v.session_id === sid) ?? null;
  mocks.queries.agentVerdictsFor = async (inc) => verdicts.filter((v) => v.incident_id === inc);
  mocks.queries.addIncidentComment = async (...args: unknown[]) => void comments.push({ author: String(args[1]), body: String(args[2]) });
  return { log, verdicts, comments };
}

function resetVerdictStore(): void {
  mocks.queries.saveTriageVerdict = async () => undefined;
  mocks.queries.triageVerdictClaim = async () => null;
  mocks.queries.triageVerdictWinner = async () => null;
  mocks.queries.claimTriageVerdict = async (m) => m.sessionId;
  mocks.queries.saveAgentVerdict = async () => undefined;
  mocks.queries.agentVerdictBySession = async () => null;
  mocks.queries.agentVerdictsFor = async () => [];
  mocks.queries.addIncidentComment = async () => undefined;
}

function formDataOf(v: Record<string, string>): FormData {
  const fd = new FormData();
  for (const [k, x] of Object.entries(v)) fd.set(k, x);
  return fd;
}
