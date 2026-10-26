// API паспорта субъекта: роли (viewer — 403), токен API, токен сессии разбора
// (только субъект своего инцидента, окно и привязка строк), аудит strict,
// PUT /api/v1/identities (422 с путём), DELETE алиаса. ClickHouse — подмена
// fetch по тексту SQL, как в incidents-pagination.test.ts.
import { test, before } from "node:test";
import assert from "node:assert/strict";
import fs from "node:fs";
import { installNextMocks, loadAuth } from "./_next-mock";

const auth = loadAuth();
const mocks = installNextMocks();
const API = "a".repeat(40);
const ISSUER = "i".repeat(40);
process.env.ARGUS_API_TOKEN = API;
process.env.ARGUS_TRIAGE_ISSUER_TOKEN = ISSUER;

/* eslint-disable @typescript-eslint/no-require-imports -- маршруты грузятся после моков */
type Ctx = { params: Promise<Record<string, string>> };
type Route = { GET?: (req: Request, ctx?: Ctx) => Promise<Response>; POST?: (req: Request) => Promise<Response>; PUT?: (req: Request) => Promise<Response>; DELETE?: (req: Request, ctx?: Ctx) => Promise<Response> };
const resolveRoute = require("../src/app/api/v1/actors/route") as Route;
const actorRoute = require("../src/app/api/v1/actors/[id]/route") as Route;
const reportRoute = require("../src/app/api/v1/actors/[id]/report/route") as Route;
const identitiesRoute = require("../src/app/api/v1/identities/route") as Route;
const aliasesRoute = require("../src/app/api/v1/identities/[person]/aliases/route") as Route;
const sessionsRoute = require("../src/app/api/triage/sessions/route") as Route;
const actions = require("../src/lib/actor-actions") as typeof import("../src/lib/actor-actions");
/* eslint-enable @typescript-eslint/no-require-imports */

/* ===== Поддельный ClickHouse поверх fetch ===== */

const PERSONS = [
  { person_id: "i.petrov", display: "Иван Петров", kind: "person", team: "platform", note: "VIP" },
  { person_id: "a.sidorov", display: "Алексей Сидоров", kind: "person", team: "ops", note: "" },
  // Тот же логин, но алиас закончился до инцидента INC-7 (first_ts 2026-10-12): не субъект сессии разбора.
  { person_id: "early", display: "Прежний владелец", kind: "person", team: "", note: "" },
];
const ALIASES = [
  { person_id: "i.petrov", alias_kind: "login", alias_value: "project_7_bot", valid_from: "2026-10-01 00:00:00.000", valid_to_raw: null, source: "yaml", confidence: 1, note: "" },
  { person_id: "i.petrov", alias_kind: "ip", alias_value: "10.0.0.5", valid_from: "2026-10-01 00:00:00.000", valid_to_raw: "2026-10-20 00:00:00.000", source: "yaml", confidence: 1, note: "" },
  { person_id: "a.sidorov", alias_kind: "login", alias_value: "other", valid_from: "2026-10-01 00:00:00.000", valid_to_raw: null, source: "yaml", confidence: 1, note: "" },
  { person_id: "a.sidorov", alias_kind: "ip", alias_value: "10.0.0.5", valid_from: "2026-10-20 00:00:00.000", valid_to_raw: null, source: "event:vpn", confidence: 1, note: "" },
  // Тот же логин второй строкой из события — в резолве персона одна.
  { person_id: "i.petrov", alias_kind: "login", alias_value: "project_7_bot", valid_from: "2026-10-05 00:00:00.000", valid_to_raw: null, source: "event:idp", confidence: 1, note: "" },
  { person_id: "early", alias_kind: "login", alias_value: "project_7_bot", valid_from: "2026-09-01 00:00:00.000", valid_to_raw: "2026-10-05 00:00:00.000", source: "yaml", confidence: 1, note: "" },
  // Удержан политикой идентичности движка: виден в паспорте, но не сшивает события и не резолвит персону.
  { person_id: "i.petrov", alias_kind: "login", alias_value: "held_bot", valid_from: "2026-10-01 00:00:00.000", valid_to_raw: null, source: "event:idp", confidence: 0.3, note: "policy:hold:max_logins" },
  { person_id: "a.sidorov", alias_kind: "phone", alias_value: "+79991234567", valid_from: "2026-10-01 00:00:00.000", valid_to_raw: null, source: "yaml", confidence: 1, note: "" },
];
const EVENTS = [
  { ts: "2026-10-24 11:00:00.000", source: "idp.example", source_class: "identity", action: "auth.login", outcome: "success", severity: 2, actor_name: "project_7_bot", actor_kind: "user", object: "portal", node: "web-01", session_id: "s1", src_ip: "10.0.0.9", dst_ip: "", value: 0, unit: "", attrs: {}, pii: 1 },
  { ts: "2026-10-24 10:00:00.000", source: "syslog.linux", source_class: "syslog", action: "sudo.run", outcome: "success", severity: 3, actor_name: "project_7_bot", actor_kind: "user", object: "/bin/bash", node: "web-01", session_id: "s1", src_ip: "", dst_ip: "", value: 0, unit: "", attrs: {}, pii: 0 },
];
/** Сбой INSERT (проверка второй записи аудита при провале мутации). */
const fail = { insert: false };
type Call = { sql: string; params: URLSearchParams };
const calls: Call[] = [];
const rows = (r: unknown[]) => new Response(r.map((x) => JSON.stringify(x)).join("\n") + (r.length ? "\n" : ""));

globalThis.fetch = (async (url: URL | string, init?: RequestInit) => {
  const u = new URL(String(url));
  const sql = String(init?.body ?? "");
  const p = u.searchParams;
  calls.push({ sql, params: p });
  if (sql.startsWith("INSERT")) return fail.insert ? new Response("Code: 241. DB::Exception: Memory limit exceeded", { status: 500 }) : new Response("");
  if (sql.includes("countIf(")) {
    // Список персон: на персону — e<j>/l<j> или i<j>; отвечаем по именам колонок из SQL.
    const out: Record<string, string> = {};
    for (const m of sql.matchAll(/AS ([eli]\d+)/g)) out[m[1]] = m[1].startsWith("e") ? "2" : m[1].startsWith("i") ? "1" : "2026-10-24 11:00:00.000";
    return rows([out]);
  }
  if (sql.includes("ORDER BY ts DESC")) return rows(EVENTS);
  if (sql.includes("GROUP BY source_class ORDER BY")) return rows([{ source_class: "identity", count: "1" }, { source_class: "syslog", count: "1" }]);
  if (sql.includes("GROUP BY node ORDER BY")) return rows([{ node: "web-01", count: "2", first_ts: "2026-10-24 10:00:00.000", last_ts: "2026-10-24 11:00:00.000" }]);
  if (sql.includes("GROUP BY src_ip ORDER BY")) return rows([{ src_ip: "10.0.0.9", count: "1", first_ts: "2026-10-24 11:00:00.000", last_ts: "2026-10-24 11:00:00.000" }]);
  if (sql.includes("GROUP BY source, source_class")) return rows([{ source: "idp.example", source_class: "identity", count: "1", first_ts: "2026-10-24 11:00:00.000", last_ts: "2026-10-24 11:00:00.000" }]);
  if (sql.includes("FROM incidents_current WHERE (")) return rows([
    { id: "INC-7", level: "high", status: "new", rule_id: "a41c-cicd-007", rule_title: "CI job echoed a secret", created_s: "2026-10-12 04:02:00", actor_name: "project_7_bot", first_s: "2026-10-12 04:01:38.000" },
    { id: "INC-8", level: "medium", status: "new", rule_id: "r8", rule_title: "другой инцидент того же субъекта", created_s: "2026-10-15 00:00:00", actor_name: "project_7_bot", first_s: "2026-10-15 00:00:00.000" },
    { id: "INC-3", level: "low", status: "closed", rule_id: "r", rule_title: "старый", created_s: "2026-09-30 00:00:00", actor_name: "project_7_bot", first_s: "2026-09-30 00:00:00.000" },
  ]);
  if (sql.includes("GROUP BY actor_name ORDER BY count")) return rows([{ actor_name: "nobody", count: "5", first_ts: "2026-10-24 00:00:00.000", last_ts: "2026-10-24 11:00:00.000", sources: ["x"] }]);
  if (p.has("param_lv")) {
    // Резолв (closeAlias тоже передаёт param_v, но без lv/at).
    const v = p.get("param_v")!, lv = p.get("param_lv")!, pv = p.get("param_pv")!, at = p.get("param_at")!;
    // Как SQL: значение и действие алиаса в момент at (формат времени сортируется лексикографически).
    return rows(ALIASES.filter((a) => (a.alias_value === v || a.alias_value === lv || a.alias_value === pv) && a.valid_from <= at && (a.valid_to_raw === null || at < a.valid_to_raw))
      .map((a) => ({ ...a, display: PERSONS.find((x) => x.person_id === a.person_id)?.display ?? "", kind: "person" })));
  }
  // Алиасы персоны; с param_k/param_v (closeAlias, confirmAlias) — только строки этого вида и значения.
  if (sql.includes("FROM identity_aliases")) return rows(p.has("param_id") ? ALIASES.filter((a) => a.person_id === p.get("param_id") && (!p.has("param_k") || a.alias_kind === p.get("param_k")) && (!p.has("param_v") || a.alias_value === p.get("param_v"))) : ALIASES);
  if (sql.includes("FROM identities")) return rows(p.has("param_id") ? PERSONS.filter((x) => x.person_id === p.get("param_id")) : PERSONS);
  return rows([]);
}) as typeof fetch;

// Сессия разбора по INC-7 (субъект project_7_bot, узел runner-07) — через argus-queries (подменены).
const INC7 = {
  incident_id: "INC-7", rule_id: "a41c-cicd-007", rule_title: "CI job echoed a secret", level: "high", status: "new",
  owner: "", note: "", actor_name: "project_7_bot", node: "runner-07", sources: ["gitlab.ci"], event_count: 1,
  first_ts: "2026-10-12 04:01:38.000", last_ts: "2026-10-12 04:01:38.000", created_at: "2026-10-12 04:02:00", pii: 0,
  chain: [], tags: [], enrichment: [], similar: [],
};
mocks.queries.incidentGet = async (id) => (id === "INC-7" ? { ...INC7 } : null);
mocks.queries.chQuery = async (sql) => (sql.includes("FROM events") ? [{ k: "ip", v: "10.20.4.31" }] : []);

const bearer = (path: string, token: string, init: RequestInit = {}) => new Request(`http://x${path}`, { ...init, headers: { authorization: `Bearer ${token}`, "content-type": "application/json", ...(init.headers ?? {}) } });
const cookie = (path: string, init: RequestInit = {}) => new Request(`http://x${path}`, { ...init, headers: { "content-type": "application/json", ...(init.headers ?? {}) } });
const ctx = (params: Record<string, string>): Ctx => ({ params: Promise.resolve(params) });
const since = () => calls.length;
const lastTimeline = (from: number) => calls.slice(from).find((c) => c.sql.includes("ORDER BY ts DESC"));

before(async () => {
  await auth.getAuthState();
  const pwd = fs.readFileSync(auth.ADMIN_PASSWORD_FILE, "utf8").trim();
  assert.equal(await auth.changePassword("admin", pwd, "AdminPassw0rd."), null);
  for (const [name, role] of [["viewer1", "viewer"], ["analyst1", "analyst"], ["api-token", "viewer"]] as const) assert.ok("password" in (await auth.createUser(name, role)));
  console.error = () => undefined;
});

test("резолв: токен API — unbound/resolved/ambiguous, 400 на мусор, аудит actor.view", async () => {
  assert.equal((await resolveRoute.GET!(new Request("http://x/api/v1/actors?alias=x"))).status, 401);
  const n = mocks.audit.length;
  const un = await resolveRoute.GET!(bearer("/api/v1/actors?alias=nobody", API));
  assert.equal(un.status, 200);
  const unBody = await un.json();
  assert.deepEqual(unBody, { alias: "nobody", at: unBody.at, status: "unbound", matches: [] });
  assert.match(unBody.at, /^\d{4}-\d{2}-\d{2}T/);
  const res = await resolveRoute.GET!(bearer("/api/v1/actors?alias=project_7_bot&at=2026-10-24T12:00:00Z", API));
  const body = await res.json();
  assert.equal(res.status, 200, JSON.stringify(body));
  assert.equal(body.status, "resolved");
  assert.equal(body.at, "2026-10-24T12:00:00.000Z");
  assert.deepEqual(body.matches, [{ person_id: "i.petrov", display: "Иван Петров", kind: "person", alias_kind: "login", valid_from: "2026-10-01 00:00:00.000", valid_to: null }], "две строки одного алиаса (yaml + event) — одна персона");
  // Адрес передан другому человеку: на «сейчас» владелец один, а в день пересечения логинов — двое.
  const handed = await resolveRoute.GET!(bearer("/api/v1/actors?alias=10.0.0.5", API));
  const handedBody = await handed.json();
  assert.equal(handedBody.status, "resolved");
  assert.equal(handedBody.matches[0].person_id, "a.sidorov", "интервал i.petrov закончился 2026-10-20");
  const amb = await resolveRoute.GET!(bearer("/api/v1/actors?alias=project_7_bot&at=2026-10-03T00:00:00Z", API));
  const ambBody = await amb.json();
  assert.equal(ambBody.status, "ambiguous");
  assert.deepEqual(ambBody.matches.map((m: { person_id: string }) => m.person_id).sort(), ["early", "i.petrov"], "кандидаты показаны явно, первый не выбран");
  // Телефон — в канонической форме E.164: пробелы и скобки в запросе не мешают.
  const phone = await resolveRoute.GET!(bearer("/api/v1/actors?alias=%2B7%20(999)%20123-45-67", API));
  const phoneBody = await phone.json();
  assert.equal(phoneBody.status, "resolved", JSON.stringify(phoneBody));
  assert.equal(phoneBody.matches[0].person_id, "a.sidorov");
  assert.equal(phoneBody.matches[0].alias_kind, "phone");
  // Удержанный алиас персону не резолвит.
  const held = await resolveRoute.GET!(bearer("/api/v1/actors?alias=held_bot", API));
  assert.equal((await held.json()).status, "unbound", "алиас на удержании — не привязан");
  for (const bad of ["", "alias=", "alias=a%00b", "alias=x&at=yesterday", "alias=x&at=2026-10-24", `alias=${"a".repeat(300)}`]) assert.equal((await resolveRoute.GET!(bearer(`/api/v1/actors?${bad}`, API))).status, 400, bad);
  const audits = mocks.audit.slice(n).filter((a) => a.action === "actor.view");
  assert.equal(audits.length, 6);
  assert.equal(audits[0].user, "api-token");
  assert.equal(audits[0].target, "nobody");
  assert.equal((await resolveRoute.GET!(bearer("/api/v1/actors?alias=x", ISSUER))).status, 403, "issuer паспорта не читает");
});

test("паспорт: токен API — форма ответа, 404 на неизвестную персону, инциденты только в интервале алиаса", async () => {
  const from = since();
  const res = await actorRoute.GET!(bearer("/api/v1/actors/i.petrov?range=24h&limit=50", API), ctx({ id: "i.petrov" }));
  const body = await res.json();
  assert.equal(res.status, 200, JSON.stringify(body));
  assert.deepEqual(body.person, PERSONS[0]);
  assert.deepEqual(body.aliases[0], { kind: "login", value: "project_7_bot", valid_from: "2026-10-01 00:00:00.000", valid_to: null, source: "yaml", confidence: 1, hold: false });
  const heldAlias = body.aliases.find((a: { value: string }) => a.value === "held_bot");
  assert.deepEqual(heldAlias, { kind: "login", value: "held_bot", valid_from: "2026-10-01 00:00:00.000", valid_to: null, source: "event:idp", confidence: 0.3, hold: true, policy: "max_logins" }, "удержанный алиас виден с пометкой");
  assert.equal(body.range.key, "24h");
  assert.match(body.range.from, /^\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}\.\d{3}$/);
  assert.deepEqual(body.summary.by_source_class, { identity: 1, syslog: 1 });
  assert.equal(body.summary.events, 2);
  assert.equal(body.summary.nodes[0].node, "web-01");
  assert.equal(body.summary.incidents, 2);
  assert.deepEqual(body.incidents.map((i: { id: string }) => i.id), ["INC-7", "INC-8"], "INC-3 раньше valid_from алиаса — не субъекта");
  assert.deepEqual(body.incidents[0], { id: "INC-7", level: "high", status: "new", rule_id: "a41c-cicd-007", rule_title: "CI job echoed a secret", created_at: "2026-10-12 04:02:00" });
  assert.equal(body.timeline[0].pii, 1, "признак ПДн не теряется");
  assert.equal(body.logins[0].pii, 1);
  assert.equal(body.hosts[0].pii, 0);
  assert.deepEqual(body.ambiguous, [], "форма ambiguous — алиасы персоны {kind, value}");
  assert.equal(body.person.note, "VIP", "без сессии разбора заметка видна");
  assert.equal(body.logins.length, 1);
  assert.equal(body.hosts.length, 1);
  assert.deepEqual(body.network, []);
  assert.equal(body.timeline.length, 2);
  assert.equal(body.timeline[0].level, "info");
  assert.ok(!("raw" in body.timeline[0]));
  const tl = lastTimeline(from)!;
  assert.equal(tl.params.get("param_limit"), "50");
  assert.equal(tl.params.get("param_a0"), "project_7_bot");
  assert.ok(tl.sql.includes("(lowerUTF8(actor_name) = {a0:String}"), "login сравнивается без учёта регистра");
  assert.ok(!tl.sql.includes("src_ip = "), "ip-алиас закончился 2026-10-20 — вне окна 24h");
  assert.ok(![...tl.params.values()].includes("held_bot"), "удержанный алиас в предикате событий не участвует");
  const incSql = calls.slice(from).find((c) => c.sql.includes("FROM incidents_current WHERE ("))!;
  assert.ok(incSql.sql.includes("lowerUTF8(actor_name) IN ({l0:String}, {l1:String})") && !incSql.sql.includes(" actor_name IN"), incSql.sql);
  assert.equal(incSql.params.get("param_l0"), "project_7_bot");
  assert.ok(![...incSql.params.values()].includes("held_bot"), "удержанный алиас не ищет инциденты");
  assert.ok(!tl.sql.includes("actor_name IN"), "без сессии разбора привязки строк нет");
  assert.equal((await actorRoute.GET!(bearer("/api/v1/actors/nobody", API), ctx({ id: "nobody" }))).status, 404);
  assert.equal((await actorRoute.GET!(bearer("/api/v1/actors/i.petrov?range=1h", API), ctx({ id: "i.petrov" }))).status, 400);
  assert.equal((await actorRoute.GET!(bearer("/api/v1/actors/Bad%20Id", API), ctx({ id: "Bad Id" }))).status, 400);
  const md = await reportRoute.GET!(bearer("/api/v1/actors/i.petrov/report?range=7d", API), ctx({ id: "i.petrov" }));
  assert.equal(md.status, 200);
  assert.ok(md.headers.get("content-type")?.startsWith("text/markdown"));
  assert.equal(md.headers.get("content-disposition"), 'attachment; filename="actor-i.petrov.md"');
  const text = await md.text();
  assert.ok(text.startsWith("# Паспорт субъекта — Иван Петров\n"));
  assert.ok(text.includes("| login | project\\_7\\_bot |"));
  assert.equal(mocks.audit.filter((a) => a.action === "actor.export").length, 1);
});

test("RBAC по виду аутентификации: локальный наблюдатель с логином api-token — не служебный токен", async () => {
  await auth.createSession("api-token", "viewer");
  const from = since();
  assert.equal((await resolveRoute.GET!(cookie("/api/v1/actors?alias=project_7_bot"))).status, 403);
  assert.equal((await actorRoute.GET!(cookie("/api/v1/actors/i.petrov"), ctx({ id: "i.petrov" }))).status, 403);
  assert.equal((await identitiesRoute.PUT!(cookie("/api/v1/identities", { method: "PUT", body: JSON.stringify({ persons: { x: {} } }) }))).status, 403);
  assert.equal((await aliasesRoute.DELETE!(cookie("/api/v1/identities/i.petrov/aliases?kind=login&value=project_7_bot", { method: "DELETE" }), ctx({ person: "i.petrov" }))).status, 403);
  assert.equal(calls.length, from, "хранилище не трогалось");
  const s = await auth.apiSession(cookie("/api/v1/actors"));
  assert.equal(s?.kind, "console");
  assert.equal((await auth.apiSession(bearer("/x", API)))?.kind, "api-token");
  mocks.jar.clear();
});

test("сессия консоли: наблюдатель — 403 без обращения к хранилищу, аналитик — 200", async () => {
  await auth.createSession("viewer1", "viewer");
  const from = since();
  const v = await resolveRoute.GET!(cookie("/api/v1/actors?alias=project_7_bot"));
  assert.equal(v.status, 403);
  assert.equal((await v.json()).error, "forbidden");
  assert.equal((await actorRoute.GET!(cookie("/api/v1/actors/i.petrov"), ctx({ id: "i.petrov" }))).status, 403);
  assert.equal((await reportRoute.GET!(cookie("/api/v1/actors/i.petrov/report"), ctx({ id: "i.petrov" }))).status, 403);
  assert.equal(calls.length, from, "наблюдателю хранилище не опрашивается");
  await auth.createSession("analyst1", "analyst");
  const a = await actorRoute.GET!(cookie("/api/v1/actors/i.petrov"), ctx({ id: "i.petrov" }));
  assert.equal(a.status, 200);
  assert.equal(mocks.audit.at(-1)?.user, "analyst1");
  assert.equal(mocks.audit.at(-1)?.action, "actor.view");
  mocks.jar.clear();
});

test("аудит strict: без записи о просмотре данные не отдаются", async () => {
  const orig = mocks.queries.audit;
  mocks.queries.audit = async () => { throw new Error("журнал действий недоступен — действие отменено"); };
  try {
    const from = since();
    const r = await actorRoute.GET!(bearer("/api/v1/actors/i.petrov", API), ctx({ id: "i.petrov" }));
    assert.equal(r.status, 503);
    assert.equal((await r.json()).error, "журнал действий недоступен — действие отменено");
    assert.equal(lastTimeline(from), undefined, "события не читались");
    const rs = await resolveRoute.GET!(bearer("/api/v1/actors?alias=project_7_bot", API));
    assert.equal(rs.status, 503);
  } finally {
    mocks.queries.audit = orig;
  }
});

test("токен сессии разбора: только субъект своего инцидента, окно и привязка строк", async () => {
  const issued = await sessionsRoute.POST!(bearer("/api/triage/sessions", ISSUER, { method: "POST", body: JSON.stringify({ incident_id: "INC-7" }) }));
  const issuedText = await issued.text();
  assert.equal(issued.status, 201, issuedText);
  const { token } = JSON.parse(issuedText) as { token: string };
  const foreign = await resolveRoute.GET!(bearer("/api/v1/actors?alias=other", token));
  assert.equal(foreign.status, 403);
  assert.equal((await foreign.json()).error, "out_of_scope");
  assert.equal((await resolveRoute.GET!(bearer("/api/v1/actors?alias=10.0.0.5", token))).status, 403, "IP не субъект");
  const own = await resolveRoute.GET!(bearer("/api/v1/actors?alias=project_7_bot", token));
  assert.equal(own.status, 200);
  assert.equal((await own.json()).matches[0].person_id, "i.petrov");
  assert.equal(mocks.audit.at(-1)?.user.startsWith("triage:"), true);

  const other = await actorRoute.GET!(bearer("/api/v1/actors/a.sidorov", token), ctx({ id: "a.sidorov" }));
  assert.equal(other.status, 403);
  assert.equal((await other.json()).error, "out_of_scope");
  // Исторический алиас не делает персону субъектом: алиас должен действовать в момент инцидента.
  const early = await actorRoute.GET!(bearer("/api/v1/actors/early", token), ctx({ id: "early" }));
  assert.equal(early.status, 403, "алиас закончился 2026-10-05, инцидент 2026-10-12");
  assert.equal((await early.json()).error, "out_of_scope");
  assert.equal((await actorRoute.GET!(bearer("/api/v1/actors/early", API), ctx({ id: "early" }))).status, 200, "токену API та же персона доступна");
  const from = since();
  const mine = await actorRoute.GET!(bearer("/api/v1/actors/i.petrov?range=30d", token), ctx({ id: "i.petrov" }));
  const body = await mine.json();
  assert.equal(mine.status, 200, JSON.stringify(body));
  const bound = /\(actor_name IN \(\{ba0:String\}\) OR node IN \(\{bn0:String\}\)\)/;
  const tl = lastTimeline(from)!;
  assert.match(tl.sql, bound, "строки привязаны к субъекту и узлу инцидента");
  assert.equal(tl.params.get("param_ba0"), "project_7_bot");
  assert.equal(tl.params.get("param_bn0"), "runner-07");
  assert.ok(tl.params.get("param_from")! >= "2026-09-12 04:01", `окно не раньше first_ts − 30 дней: ${tl.params.get("param_from")}`);
  // Привязка и окно — на все части отчёта, не только таймлайн.
  for (const marker of ["GROUP BY source_class ORDER BY", "GROUP BY node ORDER BY", "GROUP BY src_ip ORDER BY", "GROUP BY source, source_class"]) {
    const q = calls.slice(from).find((c) => c.sql.includes(marker))!;
    assert.ok(q, marker);
    assert.match(q.sql, bound, `${marker}: привязка строк`);
    assert.ok(q.params.get("param_from")! >= "2026-09-12 04:01", `${marker}: окно области`);
  }
  assert.deepEqual(body.incidents.map((i: { id: string }) => i.id), ["INC-7"], "только свой инцидент и связанные (INC-8 того же субъекта — нет)");
  const incQ = calls.slice(from).find((c) => c.sql.includes("FROM incidents_current WHERE ("))!;
  assert.ok(/incident_id IN \(\{ids:Array\(String\)\}\)[\s\S]*ORDER BY created_at DESC LIMIT 200/.test(incQ.sql), "область — в SQL до LIMIT, иначе 200 чужих инцидентов вытеснят свой");
  assert.equal(incQ.params.get("param_ids"), "['INC-7']", "свой инцидент (связанных у сессии в этом тесте нет)");
  const apiInc = calls.find((c) => c.sql.includes("FROM incidents_current WHERE (") && !c.sql.includes("incident_id IN"));
  assert.ok(apiInc, "без сессии разбора фильтра по инцидентам нет");
  assert.equal(body.summary.incidents, 1);
  assert.deepEqual(body.aliases.map((a: { kind: string; value: string }) => `${a.kind}=${a.value}`), ["login=project_7_bot", "login=project_7_bot"], "только алиасы, совпавшие с областью; ip 10.0.0.5 не отдаётся");
  assert.ok(!tl.sql.includes("src_ip = "), "чужой алиас не участвует и в выборке");
  assert.equal(body.person.note, "", "заметка скрыта");
  assert.equal(body.person.team, "", "команда скрыта");
  assert.equal(body.timeline.length, 2);
  assert.ok(!("raw" in body.timeline[0]));
  // Экспорт — выгрузка ПДн: токену сессии разбора закрыт, агенту хватает JSON в области инцидента.
  const md = await reportRoute.GET!(bearer("/api/v1/actors/i.petrov/report", token), ctx({ id: "i.petrov" }));
  assert.equal(md.status, 403);
  assert.equal((await identitiesRoute.PUT!(bearer("/api/v1/identities", token, { method: "PUT", body: "{}" }))).status, 403, "сессия разбора не пишет identities");
});

test("PUT /api/v1/identities: токен API или admin; 422 с путём; upsert source=api; аудит", async () => {
  const doc = { persons: { "s.ivanova": { display: "Светлана Иванова", team: "sec", aliases: [{ kind: "email", value: "S.Ivanova@Example.org" }, { kind: "ip", value: "10.77.0.12", from: "2026-10-01" }] } } };
  await auth.createSession("analyst1", "analyst");
  assert.equal((await identitiesRoute.PUT!(cookie("/api/v1/identities", { method: "PUT", body: JSON.stringify(doc) }))).status, 403);
  mocks.jar.clear();
  assert.equal((await identitiesRoute.PUT!(new Request("http://x/api/v1/identities", { method: "PUT", body: "{}" }))).status, 401);
  const badIp = await identitiesRoute.PUT!(bearer("/api/v1/identities", API, { method: "PUT", body: JSON.stringify({ persons: { x: { aliases: [{ kind: "ip", value: "10.0.0.300" }] } } }) }));
  assert.equal(badIp.status, 422);
  assert.deepEqual(await badIp.json(), { error: "invalid_value", path: "persons.x.aliases[0].value", detail: "ожидается IPv4 или IPv6" });
  assert.equal((await identitiesRoute.PUT!(bearer("/api/v1/identities", API, { method: "PUT", body: "not json" }))).status, 400);
  const from = since();
  const ok = await identitiesRoute.PUT!(bearer("/api/v1/identities", API, { method: "PUT", body: JSON.stringify(doc) }));
  assert.equal(ok.status, 200);
  assert.deepEqual(await ok.json(), { persons: 1, aliases: 2 });
  const inserts = calls.slice(from).filter((c) => c.sql.startsWith("INSERT"));
  assert.equal(inserts.length, 2);
  assert.ok(inserts[0].sql.startsWith("INSERT INTO identities (person_id, display, kind, team, note, updated_at, deleted) VALUES"));
  assert.equal(inserts[0].params.get("param_p0"), "s.ivanova");
  assert.ok(inserts[1].sql.startsWith("INSERT INTO identity_aliases (person_id, alias_kind, alias_value, valid_from, valid_to, source, confidence, note, updated_at, deleted) VALUES"));
  assert.equal(inserts[1].params.get("param_src"), "api");
  assert.equal(inserts[1].params.get("param_v0"), "s.ivanova@example.org", "email в нижнем регистре");
  assert.equal(inserts[1].params.get("param_f0"), "1970-01-01 00:00:00.000", "без from — на всю историю, повторный импорт даёт тот же ключ строки");
  assert.equal(inserts[1].params.get("param_f1"), "2026-10-01 00:00:00.000");
  assert.equal(inserts[1].params.get("param_t1"), "", "открытый valid_to → NULL через OrNull");
  assert.ok(!inserts[1].sql.includes("s.ivanova"), "значения не в тексте SQL");
  assert.equal(mocks.audit.at(-1)?.action, "identity.import");
  await auth.createSession("admin", "admin");
  assert.equal((await identitiesRoute.PUT!(cookie("/api/v1/identities", { method: "PUT", body: JSON.stringify(doc) }))).status, 200, "администратор консоли пишет");
  mocks.jar.clear();
});

test("аудит мутаций обязателен: нет журнала — нет импорта/закрытия (503); провал записи — вторая запись аудита", async () => {
  const doc = { persons: { "s.ivanova": { display: "Светлана", aliases: [{ kind: "login", value: "sivanova" }] } } };
  const orig = mocks.queries.audit;
  mocks.queries.audit = async () => { throw new Error("журнал действий недоступен — действие отменено"); };
  try {
    const from = since();
    const r = await identitiesRoute.PUT!(bearer("/api/v1/identities", API, { method: "PUT", body: JSON.stringify(doc) }));
    assert.equal(r.status, 503);
    assert.equal((await r.json()).error, "журнал действий недоступен — действие отменено");
    assert.equal(calls.slice(from).filter((c) => c.sql.startsWith("INSERT")).length, 0, "ни одной записи без журнала");
    const d = await aliasesRoute.DELETE!(bearer("/api/v1/identities/i.petrov/aliases?kind=login&value=project_7_bot", API, { method: "DELETE" }), ctx({ person: "i.petrov" }));
    assert.equal(d.status, 503);
    assert.equal(calls.slice(from).filter((c) => c.sql.startsWith("INSERT")).length, 0);
  } finally {
    mocks.queries.audit = orig;
  }
  // Журнал есть, хранилище отказало на INSERT: 503 и вторая запись о провале.
  fail.insert = true;
  try {
    const n = mocks.audit.length;
    const r = await identitiesRoute.PUT!(bearer("/api/v1/identities", API, { method: "PUT", body: JSON.stringify(doc) }));
    assert.equal(r.status, 503);
    const added = mocks.audit.slice(n).map((a) => a.action);
    assert.deepEqual(added, ["identity.import", "identity.import.failed"], "журнал до изменения, затем запись о провале");
    const n2 = mocks.audit.length;
    assert.equal((await aliasesRoute.DELETE!(bearer("/api/v1/identities/i.petrov/aliases?kind=login&value=project_7_bot", API, { method: "DELETE" }), ctx({ person: "i.petrov" }))).status, 503);
    assert.deepEqual(mocks.audit.slice(n2).map((a) => a.action), ["identity.alias.close", "identity.alias.close.failed"]);
  } finally {
    fail.insert = false;
  }
});

test("список персон: каждая считается своим предикатом по алиасам, без дедупликации по хешу", async () => {
  const { listPersons } = require("../src/lib/actors") as typeof import("../src/lib/actors"); // eslint-disable-line @typescript-eslint/no-require-imports -- после моков
  const from = since();
  const list = await listPersons("7d");
  const ev = calls.slice(from).find((c) => c.sql.includes("countIf(") && c.sql.includes("FROM events"))!;
  assert.ok(ev, "один проход по окну событий на партию персон");
  assert.ok(!ev.sql.includes("cityHash64") && !ev.sql.includes("uniqExact") && !ev.sql.includes("JOIN"), "два разных события в одну мс — два события: считается countIf по предикату");
  assert.match(ev.sql, /countIf\(\(\(lowerUTF8\(actor_name\) = \{p0_a0:String\}/, "предикат персоны 0 с её префиксом параметров");
  assert.ok(ev.sql.includes("AS e1") && ev.sql.includes("AS l1"), "вторая персона — свои колонки");
  assert.equal(ev.params.get("param_p0_a0"), "project_7_bot");
  const inc = calls.slice(from).find((c) => c.sql.includes("countIf(") && c.sql.includes("FROM incidents_current"))!;
  assert.ok(inc.sql.includes("first_ts >= parseDateTime64BestEffort({p0_f0:String}"), "инциденты — по first_ts алиаса");
  const petrov = list.find((p) => p.person_id === "i.petrov")!;
  assert.equal(petrov.events, 2);
  assert.equal(petrov.incidents, 1);
  assert.equal(petrov.last_ts, "2026-10-24 11:00:00.000");
  assert.equal(petrov.aliases, 4, "удержанный алиас в счётчике алиасов есть");
  assert.ok(![...ev.params.values()].includes("held_bot"), "но в предикате активности его нет");
});

test("DELETE алиаса: valid_to = сейчас новой версией, 204; нет действующего — 404; роли", async () => {
  const from = since();
  const r = await aliasesRoute.DELETE!(bearer("/api/v1/identities/i.petrov/aliases?kind=login&value=project_7_bot", API, { method: "DELETE" }), ctx({ person: "i.petrov" }));
  assert.equal(r.status, 204);
  const ins = calls.slice(from).find((c) => c.sql.startsWith("INSERT INTO identity_aliases"))!;
  assert.ok(ins, "новая версия строки записана");
  assert.equal(ins.params.get("param_p0"), "i.petrov");
  assert.equal(ins.params.get("param_f0"), "2026-10-01 00:00:00.000", "тот же ключ строки (valid_from)");
  assert.match(ins.params.get("param_t0") ?? "", /^\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}\.\d{3}$/, "valid_to = сейчас");
  assert.ok(ins.sql.includes("parseDateTime64BestEffortOrNull({t0:String}, 3, 'UTC')"));
  assert.equal(ins.params.get("param_c0"), "1", "уверенность не меняется");
  assert.equal(mocks.audit.at(-1)?.action, "identity.alias.close");
  assert.equal((await aliasesRoute.DELETE!(bearer("/api/v1/identities/nobody/aliases?kind=login&value=x", API, { method: "DELETE" }), ctx({ person: "nobody" }))).status, 404);
  const badKind = await aliasesRoute.DELETE!(bearer("/api/v1/identities/i.petrov/aliases?kind=badge&value=x", API, { method: "DELETE" }), ctx({ person: "i.petrov" }));
  assert.equal(badKind.status, 400);
  assert.equal((await badKind.json()).detail, "kind: email|login|uid|ip|host|sid|peer|phone");
  await auth.createSession("analyst1", "analyst");
  assert.equal((await aliasesRoute.DELETE!(cookie("/api/v1/identities/i.petrov/aliases?kind=login&value=project_7_bot", { method: "DELETE" }), ctx({ person: "i.petrov" }))).status, 403);
  mocks.jar.clear();
});

test("подтверждение удержанного алиаса (admin): confidence = 1 новой версией с тем же ключом, пометка policy:confirmed, аудит", async () => {
  const fd = new FormData();
  fd.set("person_id", "i.petrov"); fd.set("kind", "login"); fd.set("value", "held_bot");
  await auth.createSession("analyst1", "analyst");
  assert.match((await actions.confirmAliasAction(fd)).error ?? "", /Недостаточно прав/);
  await auth.createSession("admin", "admin");
  const from = since();
  const n = mocks.audit.length;
  assert.deepEqual(await actions.confirmAliasAction(fd), { error: null, ok: true });
  const ins = calls.slice(from).filter((c) => c.sql.startsWith("INSERT INTO identity_aliases"));
  assert.equal(ins.length, 1);
  assert.equal(ins[0].params.get("param_p0"), "i.petrov");
  assert.equal(ins[0].params.get("param_k0"), "login");
  assert.equal(ins[0].params.get("param_v0"), "held_bot");
  assert.equal(ins[0].params.get("param_f0"), "2026-10-01 00:00:00.000", "тот же ключ строки");
  assert.equal(ins[0].params.get("param_t0"), "", "открытый valid_to сохраняется");
  assert.equal(ins[0].params.get("param_c0"), "1");
  assert.equal(ins[0].params.get("param_n0"), "policy:confirmed:max_logins");
  assert.equal(ins[0].params.get("param_s0"), "event:idp", "источник строки не подменяется");
  assert.ok(!ins[0].params.has("param_p1"), "только удержанные строки, остальные алиасы персоны не трогаются");
  assert.deepEqual(mocks.audit.slice(n).map((a) => a.action), ["identity.alias.confirm"]);
  assert.equal(mocks.audit.at(-1)?.detail, "login = held_bot");
  // Не удержанный алиас подтверждать нечего: ошибка и запись о провале.
  fd.set("value", "project_7_bot");
  const n2 = mocks.audit.length;
  assert.match((await actions.confirmAliasAction(fd)).error ?? "", /Удержанного алиаса/);
  assert.deepEqual(mocks.audit.slice(n2).map((a) => a.action), ["identity.alias.confirm", "identity.alias.confirm.failed"]);
  mocks.jar.clear();
});
