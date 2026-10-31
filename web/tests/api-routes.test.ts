// Маршруты API под токеном ARGUS_API_TOKEN (сценарии сессии разбора — в
// triage-scope.test.ts): /api/incidents (фильтры и страница — только проверенные
// значения доходят до запроса), /api/incidents/{id} и /markdown (форма ответа,
// заголовки выгрузки, 400/404/503), /api/search (страница, csv/export, raw=0,
// alerts без модуля Wazuh), /api/sources (форма SourceHealth из спецификации).
import { test } from "node:test";
import assert from "node:assert/strict";
import fs from "node:fs";
import path from "node:path";
import { installNextMocks, loadAuth } from "./_next-mock";

loadAuth();
const mocks = installNextMocks();
const API = "a".repeat(40);
process.env.ARGUS_API_TOKEN = API;
delete process.env.ARGUS_INTEGRATION_WAZUH;

/* eslint-disable @typescript-eslint/no-require-imports -- маршруты грузятся после моков */
type Ctx = { params: Promise<{ id: string }> };
type Route = { GET: (req: Request, ctx: Ctx) => Promise<Response> };
const incidentsRoute = require("../src/app/api/incidents/route") as Route;
const incidentRoute = require("../src/app/api/incidents/[id]/route") as Route;
const markdownRoute = require("../src/app/api/incidents/[id]/markdown/route") as Route;
const searchRoute = require("../src/app/api/search/route") as Route;
const sourcesRoute = require("../src/app/api/sources/route") as Route;
const yaml = require("js-yaml") as { load: (s: string) => unknown };
/* eslint-enable @typescript-eslint/no-require-imports */

const spec = yaml.load(fs.readFileSync(path.resolve(__dirname, "../../api/openapi.yaml"), "utf8")) as { components: { schemas: Record<string, { required?: string[] }> } };
const required = (schema: string): string[] => spec.components.schemas[schema].required ?? [];

const req = (p: string, token: string | null = API) => new Request(`http://x${p}`, { headers: token ? { authorization: `Bearer ${token}` } : {} });
const ctx = (id: string): Ctx => ({ params: Promise.resolve({ id }) });

const INC = {
  incident_id: "INC-12", rule_id: "ssh-bruteforce", rule_title: "Перебор SSH", level: "high", status: "new", owner: "", note: "",
  actor_name: "203.0.113.7", node: "bastion", sources: ["host.sshd"], event_count: 12, pii: 0,
  first_ts: "2026-10-12 04:01:38.000", last_ts: "2026-10-12 04:05:38.000", created_at: "2026-10-12 04:02:00",
  chain: ["04:01:38  host.sshd         bastion        ssh.login.failed         root"], tags: ["attack.t1110"], enrichment: [], similar: [],
};

console.error = () => undefined;

test("/api/incidents: 401 без токена; фильтры доходят до запроса только проверенными; 503 при отказе хранилища", async () => {
  assert.equal((await incidentsRoute.GET(req("/api/incidents", null), ctx(""))).status, 401);
  let seen: Record<string, unknown> = {};
  mocks.queries.incidentsList = async (...args: unknown[]) => {
    seen = args[0] as Record<string, unknown>;
    return { rows: [INC], total: 1, page: seen.page, pageSize: 50 };
  };
  const ok = await incidentsRoute.GET(req("/api/incidents?status=new&level=high&q=ssh&page=3"), ctx(""));
  assert.equal(ok.status, 200);
  const body = (await ok.json()) as Record<string, unknown>;
  for (const k of required("IncidentsPage")) assert.ok(k in body, `IncidentsPage.${k}`);
  assert.deepEqual(seen, { status: "new", level: "high", q: "ssh", page: 3 });

  await incidentsRoute.GET(req(`/api/incidents?status=opened&level=High1&q=${"x".repeat(300)}&page=-5`), ctx(""));
  assert.equal(seen.status, undefined, "неизвестный статус отброшен");
  assert.equal(seen.level, undefined, "level не по [a-z]{1,16} отброшен");
  assert.equal((seen.q as string).length, 200, "q обрезан");
  assert.equal(seen.page, 1, "страница зажата снизу");

  mocks.queries.incidentsList = async () => { throw new Error("Code: 159. DB::Exception: Timeout exceeded"); };
  const down = await incidentsRoute.GET(req("/api/incidents"), ctx(""));
  assert.equal(down.status, 503);
  assert.equal(((await down.json()) as { error: string }).error, "хранилище недоступно");
});

test("/api/incidents/{id}: id строго INC-N; 404; полная карточка с историей, действиями и заголовком выгрузки; 503", async () => {
  mocks.queries.incidentGet = async (id) => (id === "INC-12" ? { ...INC } : null);
  mocks.queries.verdictGet = async () => ({ incident_id: "INC-12", summary_ru: "перебор" });
  mocks.queries.incidentStateHistory = async () => [{ event_id: "e1", revision: 1, changed_at: "2026-10-12 04:02:00.000", actor: "argus-engine", kind: "created", status: "new", owner: "", reason: "" }];
  mocks.queries.incidentComments = async () => [{ comment_id: "c1", author: "admin", text: "смотрю", created_at: "2026-10-12 04:10:00.000" }];
  mocks.queries.incidentFirstResponse = async () => "2026-10-12 04:10:00.000";
  const seenParams: Record<string, string | number>[] = [];
  mocks.queries.chQuery = async (sql, params = {}) => {
    seenParams.push(params);
    assert.ok(sql.includes("FROM console_audit"));
    return [{ ts: "2026-10-12 04:10:00", user: "admin", action: "incident.take", target: "INC-12", detail: "" }];
  };
  for (const bad of ["INC-", "inc-12", "INC-1234567890", "12", "INC-12;drop"]) {
    assert.equal((await incidentRoute.GET(req(`/api/incidents/${bad}`), ctx(bad))).status, 400, bad);
  }
  assert.equal((await incidentRoute.GET(req("/api/incidents/INC-12", null), ctx("INC-12"))).status, 401);
  assert.equal((await incidentRoute.GET(req("/api/incidents/INC-404"), ctx("INC-404"))).status, 404);

  const ok = await incidentRoute.GET(req("/api/incidents/INC-12"), ctx("INC-12"));
  assert.equal(ok.status, 200);
  assert.match(ok.headers.get("content-disposition") ?? "", /^attachment; filename="INC-12-\d{4}-\d{2}-\d{2}\.json"$/);
  const body = (await ok.json()) as Record<string, unknown>;
  assert.deepEqual(Object.keys(body).sort(), ["actions", "comments", "comments_truncated", "exported_at", "first_response_at", "history", "history_truncated", "incident", "verdict"]);
  assert.equal((body.incident as typeof INC).incident_id, "INC-12");
  assert.equal(body.history_truncated, false);
  assert.equal((body.actions as unknown[]).length, 1);
  assert.ok(!Number.isNaN(Date.parse(body.exported_at as string)));
  // Действия ищутся точными параметрами, а не LIKE '%INC-1%' (цеплял бы INC-10…INC-19).
  assert.deepEqual(seenParams.at(-1), { id: "INC-12", prefix: "INC-12 ", from: "(из INC-12)" });

  mocks.queries.incidentStateHistory = async () => { throw new Error("Code: 241. DB::Exception: Memory limit exceeded"); };
  const down = await incidentRoute.GET(req("/api/incidents/INC-12"), ctx("INC-12"));
  assert.equal(down.status, 503);
  mocks.queries.incidentStateHistory = async () => [];
});

test("/api/incidents/{id}/markdown: 400/401/404; text/markdown с именем файла и без кеша; 503", async () => {
  mocks.queries.incidentGet = async (id) => (id === "INC-12" ? { ...INC } : null);
  mocks.queries.verdictGet = async () => null;
  mocks.queries.incidentComments = async () => [];
  assert.equal((await markdownRoute.GET(req("/api/incidents/x/markdown"), ctx("x"))).status, 400);
  assert.equal((await markdownRoute.GET(req("/api/incidents/INC-12/markdown", null), ctx("INC-12"))).status, 401);
  assert.equal((await markdownRoute.GET(req("/api/incidents/INC-7/markdown"), ctx("INC-7"))).status, 404);
  const ok = await markdownRoute.GET(req("/api/incidents/INC-12/markdown"), ctx("INC-12"));
  assert.equal(ok.status, 200);
  assert.equal(ok.headers.get("content-type"), "text/markdown; charset=utf-8");
  assert.equal(ok.headers.get("content-disposition"), 'attachment; filename="INC-12.md"');
  assert.equal(ok.headers.get("cache-control"), "private, no-store");
  const md = await ok.text();
  assert.ok(/INC\\?-12/.test(md) && md.includes("Перебор SSH"), md.slice(0, 200)); // дефис в Markdown экранирован
  mocks.queries.incidentGet = async () => { throw new Error("Code: 159. DB::Exception: Timeout exceeded"); };
  const down = await markdownRoute.GET(req("/api/incidents/INC-12/markdown"), ctx("INC-12"));
  assert.equal(down.status, 503);
  assert.equal(((await down.json()) as { error: string }).error, "досье временно недоступно");
  mocks.queries.incidentGet = async () => null;
});

const ROW = { ts: "2026-10-12 04:01:38.000", source: "host.sshd", action: "ssh.login.failed", outcome: "failure", severity: 5, actor_name: "root", node: "bastion", src_ip: "203.0.113.7", raw: "{\"a\":1}" };
const line = (o: unknown) => JSON.stringify(o) + "\n";

test("/api/search: страница с гистограммой и фасетами; значения — параметрами; alerts без Wazuh — 400; ошибка хранилища — 400 с текстом", async (t) => {
  const calls: { sql: string; url: string }[] = [];
  t.mock.method(globalThis, "fetch", async (u: unknown, init?: RequestInit) => {
    const sql = String(init?.body ?? "");
    calls.push({ sql, url: String(u) });
    if (sql.includes("toStartOfInterval")) return new Response(line({ bucket: "2026-10-12 04:00:00", low: "2", high: "1", critical: "0" }));
    if (sql.includes("UNION ALL") || /AS field/.test(sql)) return new Response(line({ field: "source", value: "host.sshd", count: "3" }));
    return new Response(line(ROW) + line({ ...ROW, actor_name: "admin" }));
  });
  assert.equal((await searchRoute.GET(req("/api/search?index=events", null), ctx(""))).status, 401);
  const alerts = await searchRoute.GET(req("/api/search?index=alerts&q=x"), ctx(""));
  assert.equal(alerts.status, 400);
  assert.match(((await alerts.json()) as { error: string }).error, /Wazuh/);

  const ok = await searchRoute.GET(req(`/api/search?index=events&q=${encodeURIComponent('actor:"root" sshd')}&range=24h&page=2`), ctx(""));
  assert.equal(ok.status, 200);
  const body = (await ok.json()) as Record<string, unknown>;
  for (const k of required("SearchResult")) assert.ok(k in body, `SearchResult.${k}`);
  assert.equal(body.page, 2);
  assert.equal(body.pageSize, 50);
  assert.equal(body.total, 3, "итог — сумма гистограммы");
  assert.equal((body.rows as unknown[]).length, 2);
  assert.equal(body.error, null);
  assert.ok(calls.some((c) => c.url.includes("param_") && c.url.includes("root")), "значение запроса — параметром");
  assert.ok(!calls.some((c) => c.sql.includes("'root'")), "значение не вклеено в SQL");
  assert.ok(calls.some((c) => c.url.includes("param_offset=50")), "страница 2 — offset 50");

  t.mock.restoreAll();
  t.mock.method(globalThis, "fetch", async () => new Response("Code: 159. DB::Exception: Timeout exceeded", { status: 500 }));
  const down = await searchRoute.GET(req("/api/search?index=events&q=root"), ctx(""));
  assert.equal(down.status, 400, "ошибка хранилища — в панель запроса, не 500");
  const e = (await down.json()) as { error: string; rows: unknown[] };
  assert.match(e.error, /20 с|хранилище/);
  assert.deepEqual(e.rows, []);
});

test("/api/search: export json и csv — до 10 000 строк, имя файла с датой, BOM, raw=0 без исходного JSON", async (t) => {
  const calls: { sql: string; url: string }[] = [];
  t.mock.method(globalThis, "fetch", async (u: unknown, init?: RequestInit) => {
    calls.push({ sql: String(init?.body ?? ""), url: String(u) });
    return new Response(line(ROW) + line({ ...ROW, actor_name: "=cmd|' /C calc'!A0" }));
  });
  const json = await searchRoute.GET(req("/api/search?index=events&q=root&format=export&limit=99999"), ctx(""));
  assert.equal(json.status, 200);
  assert.match(json.headers.get("content-disposition") ?? "", /^attachment; filename="argus-events-\d{4}-\d{2}-\d{2}-\d{2}-\d{2}\.json"$/);
  const body = (await json.json()) as { query: Record<string, unknown>; rows: Record<string, unknown>[]; exported_at: string };
  assert.deepEqual(Object.keys(body).sort(), ["exported_at", "query", "rows"]);
  assert.equal(body.rows.length, 2);
  assert.ok("raw" in body.rows[0], "по умолчанию исходный JSON в выгрузке есть");
  assert.ok(calls.at(-1)!.url.includes("param_limit=10000"), "лимит зажат до 10 000");

  const csv = await searchRoute.GET(req("/api/search?index=events&q=root&format=csv&limit=0"), ctx(""));
  assert.equal(csv.status, 200);
  assert.equal(csv.headers.get("content-type"), "text/csv; charset=utf-8");
  assert.match(csv.headers.get("content-disposition") ?? "", /filename="argus-events-.*\.csv"/);
  const bytes = new Uint8Array(await csv.arrayBuffer());
  assert.deepEqual([...bytes.slice(0, 3)], [0xef, 0xbb, 0xbf], "BOM для Excel (text() его срезает — смотрим байты)");
  const text = new TextDecoder().decode(bytes);
  assert.ok(text.includes("\"'=cmd|"), "формула экранирована апострофом (CSV-инъекция)");
  assert.ok(calls.at(-1)!.url.includes("param_limit=1"), "limit=0 → 1");

  const noRaw = await searchRoute.GET(req("/api/search?index=events&q=root&format=export&raw=0"), ctx(""));
  assert.equal(noRaw.status, 200);
  assert.ok(!/,\s*raw\s+FROM/.test(calls.at(-1)!.sql) && !calls.at(-1)!.sql.trimEnd().endsWith("raw"), "raw=0 — колонка raw не запрашивается");
  const sqlNoRaw = calls.at(-1)!.sql;
  assert.ok(!/\braw\b/.test(sqlNoRaw.slice(0, sqlNoRaw.indexOf("FROM"))), sqlNoRaw.slice(0, 200));

  t.mock.restoreAll();
  t.mock.method(globalThis, "fetch", async () => new Response("Code: 241. DB::Exception: Memory limit exceeded", { status: 500 }));
  const down = await searchRoute.GET(req("/api/search?index=events&q=root&format=export"), ctx(""));
  assert.equal(down.status, 400);
  assert.match(((await down.json()) as { error: string }).error, /хранилище/);
});

test("/api/search: ошибка синтаксиса запроса — 400 с текстом, хранилище не опрашивается", async (t) => {
  const fetched = t.mock.method(globalThis, "fetch", async () => new Response(""));
  const r = await searchRoute.GET(req(`/api/search?index=events&q=${encodeURIComponent("severity>=abc")}`), ctx(""));
  assert.equal(r.status, 400);
  const body = (await r.json()) as { error: string | null; rows: unknown[] };
  assert.ok(body.error, "причина отдана");
  assert.deepEqual(body.rows, []);
  assert.equal(fetched.mock.callCount(), 0);
});

test("/api/sources: 401; форма SourceHealth по спецификации с полями ритма; 503", async () => {
  assert.equal((await sourcesRoute.GET(req("/api/sources", null), ctx(""))).status, 401);
  mocks.queries.sourcesHealth = async () => [
    { source: "host.sshd", source_class: "auth", events_1h: 120, eps_60s: 0.3, last_ts: "2026-10-29 10:00:00", pii_share: 0, alive: 1, events_window: 86400, rhythm_sec: 60, silence_threshold_sec: 300, silent_for_sec: 12 },
    { source: "ci.nightly", source_class: "ci", events_1h: 0, eps_60s: 0, last_ts: "2026-10-28 03:00:00", pii_share: 0, alive: 1, events_window: 30, rhythm_sec: 86400, silence_threshold_sec: 259200, silent_for_sec: 111600 },
    { source: "once", source_class: "syslog", events_1h: 0, eps_60s: 0, last_ts: "2026-10-01 03:00:00", pii_share: 0, alive: 0, events_window: 1, rhythm_sec: null, silence_threshold_sec: 300, silent_for_sec: 2444400 },
  ];
  const ok = await sourcesRoute.GET(req("/api/sources"), ctx(""));
  assert.equal(ok.status, 200);
  const body = (await ok.json()) as { sources: Record<string, unknown>[]; checked_at: string; omitted: number };
  assert.deepEqual(Object.keys(body).sort(), ["checked_at", "omitted", "sources"]);
  assert.equal(body.omitted, 0, "без пропущенных — omitted 0");
  assert.ok(!Number.isNaN(Date.parse(body.checked_at)));
  assert.equal(body.sources.length, 3);
  const fields = required("SourceHealth");
  assert.ok(["events_window", "rhythm_sec", "silence_threshold_sec", "silent_for_sec"].every((f) => fields.includes(f)), "поля ритма обязательны в спецификации");
  for (const s of body.sources) {
    for (const k of fields) assert.ok(k in s, `SourceHealth.${k} у ${s.source}`);
    for (const k of ["events_1h", "eps_60s", "events_window", "silence_threshold_sec", "silent_for_sec", "alive"]) assert.equal(typeof s[k], "number", `${k} число у ${s.source}`);
    assert.ok(s.rhythm_sec === null || typeof s.rhythm_sec === "number");
  }
  // Замолчавших сверх предела — в omitted, список не обрывается молча.
  const origReport = mocks.queries.sourcesHealthReport;
  mocks.queries.sourcesHealthReport = async () => ({ sources: [], omitted: 37 });
  const capped = (await (await sourcesRoute.GET(req("/api/sources"), ctx(""))).json()) as { omitted: number };
  assert.equal(capped.omitted, 37);
  mocks.queries.sourcesHealthReport = origReport;
  mocks.queries.sourcesHealth = async () => { throw new Error("Code: 159. DB::Exception: Timeout exceeded"); };
  const down = await sourcesRoute.GET(req("/api/sources"), ctx(""));
  assert.equal(down.status, 503);
  mocks.queries.sourcesHealth = async () => [];
});
