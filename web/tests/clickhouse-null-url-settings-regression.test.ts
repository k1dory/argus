// PR #52: null должен исключать настройку из фактического HTTP-запроса,
// даже если она уже задана в CLICKHOUSE_URL. Подменён только fetch.
import { test } from "node:test";
import assert from "node:assert/strict";
import type { ChSettings } from "../src/lib/clickhouse";

// Модуль транспорта читает окружение при загрузке: импорт ниже динамический.
process.env.CLICKHOUSE_URL = "http://127.0.0.1:9/?max_execution_time=30&max_memory_usage=2000000000";
process.env.CLICKHOUSE_USER = "pr52-fixture";
process.env.CLICKHOUSE_PASSWORD = "";
process.env.CLICKHOUSE_DB = "argus";

const operations: Array<[string, (settings?: ChSettings) => Promise<unknown>]> = [
  ["chQuery", async (settings) =>
    (await import("../src/lib/clickhouse")).chQuery("SELECT 1 AS n", {}, settings)],
  ["chCommand", async (settings) =>
    (await import("../src/lib/clickhouse")).chCommand(
      "INSERT INTO incident_comments (body) VALUES ({body:String})", { body: "fixture" }, settings)],
];

const cases: Array<{
  name: string;
  settings?: ChSettings;
  executionTime: string[];
  memory?: string[];
}> = [
  { name: "без settings сохраняет max_execution_time=30", executionTime: ["30"] },
  { name: "пустые settings сохраняют max_execution_time=30", settings: {}, executionTime: ["30"] },
  { name: "явный лимит заменяет умолчание", settings: { max_execution_time: 7 }, executionTime: ["7"] },
  { name: "явный ноль не считается null", settings: { max_execution_time: 0 }, executionTime: ["0"] },
  { name: "null удаляет max_execution_time из URL", settings: { max_execution_time: null }, executionTime: [] },
  { name: "null другой настройки сохраняет лимит времени", settings: { max_memory_usage: null }, executionTime: ["30"], memory: [] },
];

for (const [operation, run] of operations) {
  for (const fixture of cases) {
    test(`${operation}: ${fixture.name}`, async (t) => {
      const requests: URL[] = [];
      t.mock.method(globalThis, "fetch", async (input: URL | string | Request, init?: RequestInit) => {
        requests.push(new URL(input instanceof Request ? input.url : String(input)));
        assert.equal(init?.method, "POST");
        assert.ok(init?.signal, "клиентский таймаут остаётся включённым");
        return new Response("");
      });

      await run(fixture.settings);
      // Контроль: отключение настройки одного запроса не меняет умолчания
      // следующего запроса и не удаляет настройки из исходного CLICKHOUSE_URL.
      await run();
      assert.equal(requests.length, 2);
      assert.deepEqual(requests[1].searchParams.getAll("max_execution_time"), ["30"]);
      assert.deepEqual(requests[1].searchParams.getAll("max_memory_usage"), ["2000000000"]);
      assert.equal(requests[0].searchParams.get("wait_end_of_query"), "1");
      assert.deepEqual(requests[0].searchParams.getAll("max_execution_time"), fixture.executionTime,
        "null означает отсутствие настройки в запросе, включая значения из CLICKHOUSE_URL");
      if (fixture.memory) assert.deepEqual(requests[0].searchParams.getAll("max_memory_usage"), fixture.memory);
    });
  }
}

test("agreementMetrics: max_execution_time из CLICKHOUSE_URL также исключается для argus_ro", async (t) => {
  const requests: URL[] = [];
  t.mock.method(globalThis, "fetch", async (input: URL | string | Request) => {
    requests.push(new URL(input instanceof Request ? input.url : String(input)));
    return new Response("");
  });
  const { agreementMetrics } = await import("../src/lib/blind-metrics");
  const result = await agreementMetrics("7d", Date.UTC(2026, 10, 1, 12));
  assert.equal(result.total.labeled, 0);
  assert.equal(requests.length, 1);
  assert.deepEqual(requests[0].searchParams.getAll("max_execution_time"), [],
    "профиль argus_ro задаёт неизменяемые 20 секунд; настройку 30 из URL передавать нельзя");
});
