import { test, type TestContext } from "node:test";
import assert from "node:assert/strict";
import { installNextMocks, loadAuth } from "./_next-mock";
import { assertOpenAPIResponse } from "./_openapi-response";

loadAuth();
installNextMocks();
const API = "search-contract-" + "a".repeat(40);
process.env.ARGUS_API_TOKEN = API;
delete process.env.ARGUS_INTEGRATION_WAZUH;

/* eslint-disable @typescript-eslint/no-require-imports -- route loads after Next/auth mocks; search and ClickHouse client stay real */
const route = require("../src/app/api/search/route") as { GET: (request: Request) => Promise<Response> };
/* eslint-enable @typescript-eslint/no-require-imports */

const ROW = { time: "2026-10-30 12:00:00.000", severity: 5, source: "host.sshd", source_class: "auth", action: "ssh.login.failed", outcome: "failure", actor_name: "root", node: "bastion", raw: "failed login" };
const req = (q = 'actor:"root"') => new Request(`http://x/api/search?index=events&range=24h&q=${encodeURIComponent(q)}`, { headers: { authorization: `Bearer ${API}` } });
const jsonEachRow = (...rows: unknown[]) => new Response(rows.map((row) => JSON.stringify(row)).join("\n") + "\n");

function mockClickHouse(t: TestContext, failed: string[] = []) {
  t.mock.method(console, "error", () => undefined);
  return t.mock.method(globalThis, "fetch", async (_url: unknown, init?: RequestInit) => {
    const sql = String(init?.body ?? "");
    const part = sql.includes("OFFSET {offset:UInt32}") ? "rows" : sql.includes("toStartOfInterval") ? "series" : sql.includes("arrayJoin") ? "facets" : "unknown";
    assert.notEqual(part, "unknown", `unexpected ClickHouse request: ${sql}`);
    if (failed.includes(part)) {
      return new Response("Code: 159. DB::Exception: Timeout exceeded. (TIMEOUT_EXCEEDED)", { status: 500, headers: { "X-ClickHouse-Exception-Code": "159" } });
    }
    if (part === "rows") return jsonEachRow(ROW, { ...ROW, actor_name: "admin" });
    if (part === "series") return jsonEachRow({ bucket: "2026-10-30 12:00:00", low: "2", high: "1", critical: "0" });
    return jsonEachRow({ field: "source", value: "host.sshd", count: "3", sample: "3" });
  });
}

test("GET /api/search: real successful response conforms to the documented JSON schema", async (t) => {
  const fetched = mockClickHouse(t);
  const response = await route.GET(req());
  assert.equal(response.status, 200);
  const body = await assertOpenAPIResponse("/api/search", response);
  assert.equal(fetched.mock.callCount(), 3);
  assert.equal((body.rows as unknown[]).length, 2);
  assert.equal(body.total, 3);
  assert.equal(body.total_exact, true);
  assert.equal(body.facets_sample, 3);
  assert.deepEqual(body.incomplete, []);
  assert.equal(body.notice, null);
  assert.equal(body.error, null);
});

test("GET /api/search: partial timeouts keep rows and expose typed incompleteness metadata", async (t) => {
  for (const failed of [["series"], ["facets"], ["series", "facets"]]) {
    await t.test(failed.join(" + "), async (t) => {
      mockClickHouse(t, failed);
      const response = await route.GET(req());
      assert.equal(response.status, 200);
      const body = await assertOpenAPIResponse("/api/search", response);
      assert.deepEqual(body.rows, [ROW, { ...ROW, actor_name: "admin" }]);
      assert.deepEqual(body.incomplete, failed);
      assert.equal(body.total_exact, !failed.includes("series"));
      assert.equal(body.total, failed.includes("series") ? 2 : 3);
      assert.equal(body.facets_sample, failed.includes("facets") ? null : 3);
      assert.equal(body.error, null);
      assert.equal(typeof body.notice, "string");
      if (failed.includes("series")) assert.deepEqual(body.series, []);
      if (failed.includes("facets")) assert.deepEqual(body.facets, []);
    });
  }
});

test("GET /api/search: invalid query's actual 400 body conforms to its response schema", async (t) => {
  const fetched = t.mock.method(globalThis, "fetch", async () => { throw new Error("invalid query must not reach ClickHouse"); });
  const response = await route.GET(req("severity>=abc"));
  assert.equal(response.status, 400);
  assert.equal(fetched.mock.callCount(), 0);
  const body = await assertOpenAPIResponse("/api/search", response);
  assert.equal(typeof body.error, "string");
  assert.deepEqual(body.rows, []);
});

for (const scenario of [
  { page: 1, count: 50, seriesFails: true, total: 50, more: false },
  { page: 1, count: 51, seriesFails: true, total: 50, more: true },
  { page: 1, count: 51, seriesFails: false, total: 51, more: true },
  { page: 100, count: 0, seriesFails: true, total: 0, more: false },
]) {
  test(`GET /api/search: page=${scenario.page}, совпадений=${scenario.count}, seriesFails=${scenario.seriesFails} — честные total и has_more`, async (t) => {
    t.mock.method(console, "error", () => undefined);
    t.mock.method(globalThis, "fetch", async (input: URL | string, init?: RequestInit) => {
      const sql = String(init?.body ?? "");
      if (sql.includes("OFFSET {offset:UInt32}")) {
        const url = new URL(String(input));
        const limit = Number(url.searchParams.get("param_limit"));
        assert.equal(limit, 51, "следующая страница доказывается 51-й строкой из настоящего SQL-запроса");
        assert.equal(Number(url.searchParams.get("param_offset")), (scenario.page - 1) * 50);
        return jsonEachRow(...Array.from({ length: Math.min(limit, scenario.count) }, (_, i) => ({ ...ROW, raw: `row-${i}` })));
      }
      if (sql.includes("toStartOfInterval")) {
        return scenario.seriesFails
          ? new Response("Code: 159. DB::Exception: Timeout exceeded. (TIMEOUT_EXCEEDED)", { status: 500, headers: { "X-ClickHouse-Exception-Code": "159" } })
          : jsonEachRow({ bucket: "2026-10-30 12:00:00", low: scenario.count, high: 0, critical: 0 });
      }
      if (sql.includes("arrayJoin")) return new Response("");
      throw new Error(`unexpected SQL: ${sql}`);
    });
    const url = new URL(req().url);
    url.searchParams.set("page", String(scenario.page));
    const response = await route.GET(new Request(url, { headers: { authorization: `Bearer ${API}` } }));
    assert.equal(response.status, 200);
    const body = await assertOpenAPIResponse("/api/search", response);
    assert.equal(body.total, scenario.total, "навигация не прибавляет выдуманные строки к нижней границе");
    assert.equal(body.total_exact, !scenario.seriesFails);
    assert.equal(body.has_more, scenario.more);
    assert.equal(body.page, scenario.page);
    const rows = body.rows as Record<string, unknown>[];
    assert.equal(rows.length, Math.min(50, scenario.count));
    assert.ok(rows.every((row) => row.raw !== "row-50"), "51-я строка не должна попадать в текущую страницу");
  });
}
