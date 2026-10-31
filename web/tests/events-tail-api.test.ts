// GET /api/events/tail: доступ, разбор курсора, форма ответа и Cache-Control, ошибка
// хранилища — 400 с текстом, а не 500. ClickHouse подменён на уровне fetch: journal.ts
// ходит через chQuery, а не через argus-queries.
import { test } from "node:test";
import assert from "node:assert/strict";
import { installNextMocks, loadAuth } from "./_next-mock";
import { formatTailCursor, parseTailCursor } from "../src/lib/shared/journal";

loadAuth();
installNextMocks();
const API = "a".repeat(40);
process.env.ARGUS_API_TOKEN = API;

/* eslint-disable @typescript-eslint/no-require-imports -- маршрут грузится после моков */
const tailRoute = require("../src/app/api/events/tail/route") as { GET: (req: Request) => Promise<Response> };
/* eslint-enable @typescript-eslint/no-require-imports */

const req = (qs: string, token?: string) => new Request(`http://x/api/events/tail?${qs}`, { headers: token ? { authorization: `Bearer ${token}` } : {} });
const CURSOR = "2026-10-24 12:00:00|7";

test("tail: без сессии 401; курсор обязателен и строго «YYYY-MM-DD HH:MM:SS|id»", async () => {
  assert.equal((await tailRoute.GET(req(`cursor=${encodeURIComponent(CURSOR)}`))).status, 401);
  for (const bad of ["", "cursor=now", "cursor=2026-10-24T12:00:00|7", "cursor=2026-10-24%2012:00:00", "cursor=2026-10-24%2012:00:00|x", "cursor=2026-10-24%2012:00:00|99999999999999999999"]) {
    const r = await tailRoute.GET(req(bad, API));
    assert.equal(r.status, 400, bad);
    assert.match(((await r.json()) as { error: string }).error, /cursor/);
  }
  assert.ok(parseTailCursor("2026-10-24 12:00:00|18446744073709551615"), "UInt64 max — допустимый id");
});

test("tail: порция по курсору — rows/incidents/cursor/more/pending, no-store; хранилище недоступно — 400 с причиной", async (t) => {
  const sql: string[] = [], urls: string[] = [];
  t.mock.method(globalThis, "fetch", async (u: unknown, init?: RequestInit) => {
    sql.push(String(init?.body ?? "")); urls.push(String(u));
    return new Response("", { status: 200 });
  });
  const r = await tailRoute.GET(req(`cursor=${encodeURIComponent(CURSOR)}&source=host.sshd&sev=5`, API));
  assert.equal(r.status, 200);
  assert.equal(r.headers.get("cache-control"), "no-store");
  const body = (await r.json()) as { rows: unknown[]; incidents: Record<string, unknown>; cursor: string; more: boolean; pending: number; error: string | null };
  assert.deepEqual(Object.keys(body).sort(), ["cursor", "error", "incidents", "more", "pending", "rows"]);
  assert.deepEqual(body.rows, []); assert.equal(body.more, false); assert.equal(body.error, null);
  assert.equal(body.cursor, formatTailCursor(parseTailCursor(CURSOR)!), "пустая порция — курсор не двигается");
  assert.ok(sql.some((s) => s.includes("received_at") && /\{p\d+:String\}/.test(s)), "фильтр источника — параметром запроса");
  assert.ok(urls.some((u) => u.includes("param_p0=host.sshd") && u.includes("param_after=7") && u.includes("param_since=2026-10-24")), "значения — в param_* URL, курсор разобран");
  assert.ok(!sql.some((s) => s.includes("host.sshd")), "значение фильтра не вклеено в SQL");
  t.mock.restoreAll();
  t.mock.method(globalThis, "fetch", async () => new Response("Code: 159. DB::Exception: Timeout exceeded", { status: 500 }));
  const down = await tailRoute.GET(req(`cursor=${encodeURIComponent(CURSOR)}`, API));
  assert.equal(down.status, 400);
  const e = (await down.json()) as { error: string; rows: unknown[] };
  assert.ok(e.error && e.error.length > 0, "причина отдана клиенту");
  assert.deepEqual(e.rows, []);
});
