// Дополнительный lookup отличает heartbeat-only от источников, уже учтённых
// за LIMIT проекции. Его отказ не доказывает отсутствие events: такой результат
// нельзя выдавать как точный omitted с HTTP 200.
import { test, type TestContext } from "node:test";
import assert from "node:assert/strict";
import { installNextMocks, loadAuth } from "./_next-mock";
import { assertOpenAPIResponse } from "./_openapi-response";

process.env.CLICKHOUSE_URL = "http://127.0.0.1:9";

/* eslint-disable @typescript-eslint/no-require-imports -- сохраняем настоящую функцию до установки делегатов Next/auth */
const realQueries = require("../src/lib/argus-queries") as typeof import("../src/lib/argus-queries");
const { ClickHouseError } = require("../src/lib/clickhouse") as typeof import("../src/lib/clickhouse");
const sourcesHealthReport = realQueries.sourcesHealthReport;
const limit = realQueries.STALE_SOURCES_LIMIT;

const mocks = installNextMocks();
loadAuth();
// Маршрут тоже выполняет настоящий sourcesHealthReport, а не заглушку, которая
// сама бросает ожидаемую ошибку. Подменён только HTTP-транспорт ClickHouse.
mocks.queries.sourcesHealthReport = sourcesHealthReport;
const route = require("../src/app/api/sources/route") as { GET: (request: Request) => Promise<Response> };
/* eslint-enable @typescript-eslint/no-require-imports */

const token = "sources-lookup-test-" + "a".repeat(40);
process.env.ARGUS_API_TOKEN = token;

function lookupFailure(t: TestContext) {
  const now = Math.floor(Date.now() / 1000);
  const last = now - 2 * 3600;
  const name = (n: number) => `dead.${String(n).padStart(5, "0")}`;
  const lastTS = new Date(last * 1000).toISOString().slice(0, 19).replace("T", " ");
  const projection = Array.from({ length: limit }, (_, i) => ({
    source: name(i), source_class: "system", last_ts: lastTS,
    last_sec: last, stale_total: String(limit + 1),
  }));
  const heartbeats = [{ source: name(limit), events_window: "10", gap_q: null, last_sec: last, now_sec: now }];
  const calls = { hour: 0, rhythm: 0, projection: 0, lookup: 0 };
  t.mock.method(console, "error", () => undefined);
  t.mock.method(globalThis, "fetch", async (_url: unknown, options?: RequestInit) => {
    const sql = String(options?.body);
    let rows: unknown[];
    if (sql.includes("FROM collector_health_log")) {
      calls.rhythm++;
      rows = heartbeats;
    } else if (sql.includes("AS events_1h")) {
      calls.hour++;
      rows = [];
    } else if (sql.includes("AS stale_total")) {
      calls.projection++;
      rows = projection;
    } else if (sql.includes("FROM events") && /source\s+IN\b/i.test(sql)) {
      calls.lookup++;
      return new Response("Code: 159. DB::Exception: Timeout exceeded", {
        status: 500, headers: { "X-ClickHouse-Exception-Code": "159" },
      });
    } else {
      throw new Error(`неожиданный запрос фикстуры: ${sql}`);
    }
    return new Response(rows.map((row) => JSON.stringify(row)).join("\n"));
  });
  return calls;
}

test("sources: отказ lookup после LIMIT отклоняет report вместо выдуманного omitted", async (t) => {
  const calls = lookupFailure(t);
  await assert.rejects(sourcesHealthReport(), (error: unknown) => {
    assert.ok(error instanceof ClickHouseError);
    assert.equal(error.status, 500);
    assert.equal(error.code, 159);
    return true;
  });
  assert.deepEqual(calls, { hour: 1, rhythm: 1, projection: 1, lookup: 1 });
});

test("GET /api/sources: реальный lookup HTTP 500 даёт описанный в OpenAPI ответ 503", async (t) => {
  const calls = lookupFailure(t);
  const response = await route.GET(new Request("http://x/api/sources", {
    headers: { authorization: `Bearer ${token}` },
  }));
  assert.deepEqual(calls, { hour: 1, rhythm: 1, projection: 1, lookup: 1 }, "маршрут выполнил настоящие запросы report");
  assert.equal(response.status, 503, "неизвестное пересечение источников нельзя выдавать как успешный точный отчёт");
  const body = await assertOpenAPIResponse("/api/sources", response);
  assert.deepEqual(body, { error: "хранилище недоступно" });
});
