// PR #27, круг 4: проверка URL на настоящих путях web -> ClickHouse.
// Подменён только fetch; _ch-http и подмена chQuery здесь не используются.
// Диагностический SELECT 1 тоже должен соблюдать новый транспортный контракт.
import { test } from "node:test";
import assert from "node:assert/strict";
import { format } from "node:util";

process.env.CLICKHOUSE_URL = "http://127.0.0.1:9/?wait_end_of_query=0";
process.env.CLICKHOUSE_RO_USER = "fixture-ro";
process.env.CLICKHOUSE_RO_PASSWORD = "fixture-password";

const paths: Array<[string, () => Promise<unknown>]> = [
  ["chQuery (включая попытку переопределить параметр через settings)", async () =>
    (await import("../src/lib/clickhouse")).chQuery("SELECT 1 AS n", {}, { wait_end_of_query: 0 })],
  ["chCommand", async () =>
    (await import("../src/lib/clickhouse")).chCommand("INSERT INTO incident_comments (body) VALUES ({body:String})", { body: "fixture" })],
  ["executePanel", async () =>
    (await import("../src/lib/dashboards")).runPanelQuery("SELECT 1 AS n", "24h")],
  ["export", async () =>
    (await import("../src/lib/search")).searchExport({ index: "events", q: "", range: "24h", page: 1 }, 1)],
  ["triage", async () =>
    (await import("../src/lib/triage-queries")).ruleHistory("fixture-rule", "INC-4")],
  ["actors", async () =>
    (await import("../src/lib/actors")).getPerson("fixture-person")],
  ["labels", async () =>
    (await import("../src/lib/argus-queries")).incidentLabels("2026-01-01T00:00:00Z", 1)],
  ["INSERT FORMAT JSONEachRow", async () =>
    (await import("../src/lib/argus-queries")).saveAgentVerdict({
      incident_id: "INC-4", session_id: "fixture-session", agent: "fixture-bot",
      verdict: "true_positive", confidence: 0.5, human_needed: 1, verdict_json: "{}", markdown: "fixture",
    })],
];

for (const [name, run] of paths) {
  test(`${name}: wait_end_of_query=1 отправляется ровно один раз в URL`, async (t) => {
    const seen: URL[] = [];
    t.mock.method(globalThis, "fetch", async (input: URL | string | Request) => {
      seen.push(new URL(input instanceof Request ? input.url : String(input)));
      return new Response("");
    });
    await run();
    assert.ok(seen.length > 0, "проверяется фактический запрос, а не отсутствие сетевого вызова");
    for (const url of seen) assert.deepEqual(url.searchParams.getAll("wait_end_of_query"), ["1"]);
  });

  test(`${name}: тело HTTP 400 не уходит ни в результат, ни в журнал`, async (t) => {
    const marker = "Round4PrivateClickHouseBodyFixture";
    const logs: string[] = [];
    let calls = 0;
    t.mock.method(console, "error", (...args: unknown[]) => { logs.push(format(...args)); });
    t.mock.method(globalThis, "fetch", async () => {
      calls++;
      return new Response(`Code: 6. DB::Exception: Cannot parse '${marker}' (CANNOT_PARSE_TEXT)\n`, {
        status: 400, headers: { "X-ClickHouse-Exception-Code": "6", "X-ClickHouse-Query-Id": "round4-fixture-query" },
      });
    });
    let result: unknown;
    let rejected = false;
    try {
      result = await run();
    } catch (error) {
      const { ClickHouseError } = await import("../src/lib/clickhouse");
      assert.ok(error instanceof ClickHouseError);
      assert.equal(error.code, 6);
      rejected = true;
      result = format(error);
    }
    assert.ok(calls > 0);
    assert.ok(rejected || Boolean((result as { error?: unknown } | null)?.error), "ошибка не превращается в успех");
    assert.ok(!JSON.stringify(result).includes(marker), "результат/ошибка для вызывающего не содержит тело ответа");
    assert.ok(!logs.join("\n").includes(marker), "ни транспорт, ни его вызывающие не логируют тело ошибки");
  });
}

test("clickhouseState: SELECT 1 буферизуется и код исключения не даёт зелёный статус", async (t) => {
  const { clickhouseState } = await import("../src/lib/clickhouse");
  const seen: URL[] = [];
  t.mock.method(globalThis, "fetch", async (input: URL | string | Request) => {
    const url = new URL(input instanceof Request ? input.url : String(input));
    seen.push(url);
    assert.equal(url.searchParams.get("query"), "SELECT 1");
    // 200 + exception header — поддерживаемая новым контрактом форма ошибки.
    return new Response("Code: 241. DB::Exception: fixture\n", {
      status: 200, headers: { "X-ClickHouse-Exception-Code": "241" },
    });
  });
  const state = await clickhouseState();
  assert.equal(seen.length, 1);
  await t.test("параметр URL", () => {
    assert.deepEqual(seen[0].searchParams.getAll("wait_end_of_query"), ["1"]);
  });
  await t.test("ошибка в заголовке", () => {
    assert.equal(state.ok, false, "HTTP 200 с X-ClickHouse-Exception-Code не означает исправность хранилища");
  });
});
