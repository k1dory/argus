// PR #27, третий круг: явный FORMAT переопределяет default_format.
// JSONCompactEachRowRowOutputFormat::writeSuffix в ClickHouse 24.8.14.39
// записывает позднее исключение как ["Code: …"], а не {"exception": …}:
// https://github.com/ClickHouse/ClickHouse/blob/v24.8.14.39-lts/src/Processors/Formats/Impl/JSONCompactEachRowRowOutputFormat.cpp#L99-L108
// Это транспортные fixtures реального формата, не запуск живого ClickHouse.
import { test } from "node:test";
import assert from "node:assert/strict";
import { format } from "node:util";
import { formData, installNextMocks, loadAuth } from "./_next-mock";

process.env.CLICKHOUSE_RO_USER = "fixture-ro";
process.env.CLICKHOUSE_RO_PASSWORD = "fixture-password";
installNextMocks();
const auth = loadAuth();
/* eslint-disable @typescript-eslint/no-require-imports -- окружение и Next mocks до загрузки настоящего action */
const { previewPanelAction } = require("../src/lib/dashboard-actions") as typeof import("../src/lib/dashboard-actions");
const { panelCacheGet, runPanelQuery, stripPanelDetail, validateSql } = require("../src/lib/dashboards") as typeof import("../src/lib/dashboards");
/* eslint-enable @typescript-eslint/no-require-imports */

const marker = "PrivateCompactExceptionFixture";
const queryId = "8fe2f791-6603-432e-9f49-c6347d231888";
const sql = "SELECT toUInt8(body) AS n FROM incident_comments FORMAT JSONCompactEachRow";
const fixtures = [
  { name: "DB", text: `Code: 6. DB::Exception: Cannot parse string '${marker}' as UInt8. (CANNOT_PARSE_TEXT)` },
  { name: "Poco", text: `Poco::Exception. Code: 1000, e.code() = 0, Data error: ${marker}` },
  { name: "std", text: `std::exception. Code: 1001, type: std::runtime_error, e.what() = ${marker}` },
] as const;

function response(exception: string): Response {
  // Первая строка уже отправлена: статус 200 и заголовки не содержат кода ошибки.
  return new Response("[1]\n" + JSON.stringify([exception]) + "\n", {
    status: 200,
    headers: {
      "Content-Type": "application/x-ndjson",
      "X-ClickHouse-Format": "JSONCompactEachRow",
      "X-ClickHouse-Query-Id": queryId,
    },
  });
}

for (const fixture of fixtures) {
  test(`previewPanelAction: позднее ${fixture.name}-исключение в JSON-массиве не уходит клиенту`, async (t) => {
    await auth.createSession(`sso:compact-exception-${fixture.name}`, "analyst", true);
    const logs: string[] = [];
    t.mock.method(console, "error", (...args: unknown[]) => { logs.push(format(...args)); });
    t.mock.method(globalThis, "fetch", async (_input: unknown, init?: RequestInit) => {
      assert.equal(init?.body, sql);
      return response(fixture.text);
    });

    const result = await previewPanelAction({ data: null, error: null }, formData({ sql, range: "24h" }));
    assert.ok(!JSON.stringify(result).includes(marker),
      "исключение нельзя передавать в data.rows в обход безопасных error/errorDetail");
    assert.ok(result.error, "неподдерживаемый FORMAT или сбой запроса должны давать ошибку");
    assert.deepEqual(result.data?.rows, []);
    assert.ok(!logs.join("\n").includes(marker));
  });
}

test("панель: JSON-массив с исключением не раскрывается viewer и не кэшируется как успех", async (t) => {
  const cachedSql = "SELECT toUInt8(body) AS viewer_n FROM incident_comments FORMAT JSONCompactEachRow";
  const ttlMs = 30_000;
  t.mock.method(console, "error", () => undefined);
  t.mock.method(globalThis, "fetch", async () => response(fixtures[0].text));
  assert.ok(validateSql(cachedSql), "явный FORMAT в SQL панели запрещён: формат ставит консоль (JSONEachRow)");

  const result = await runPanelQuery(cachedSql, "24h", ttlMs);
  // DashboardPage применяет именно stripPanelDetail для роли viewer;
  // TablePanel выводит String(row[column]), включая элементы массива.
  await t.test("выдача viewer без текста исключения", () => {
    const viewer = stripPanelDetail(result);
    assert.ok(!JSON.stringify(viewer).includes(marker),
      "удаление errorDetail не защищает текст исключения, попавший в rows");
    assert.ok(viewer.error);
    assert.deepEqual(viewer.rows, []);
  });
  await t.test("неуспешный результат не попал в кэш", () => {
    assert.equal(panelCacheGet(`24h\0${cachedSql}`, ttlMs), null);
  });
});
