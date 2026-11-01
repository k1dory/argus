// PR #38: слово после колонки format не обязательно является именем формата.
// Алиас без AS и ключевые слова выражений не меняют формат ответа ClickHouse.
// https://github.com/ClickHouse/ClickHouse/blob/v24.8.14.39-lts/src/Parsers/ExpressionElementParsers.cpp#L1500-L1526
// https://github.com/ClickHouse/ClickHouse/blob/v24.8.14.39-lts/src/Parsers/ExpressionListParsers.cpp#L1861-L1908
// https://github.com/ClickHouse/ClickHouse/blob/v24.8.14.39-lts/src/Parsers/ExpressionListParsers.cpp#L2268-L2269
import { test } from "node:test";
import assert from "node:assert/strict";

process.env.CLICKHOUSE_URL = "http://127.0.0.1:9/";
process.env.CLICKHOUSE_RO_USER = "fixture-ro";
process.env.CLICKHOUSE_RO_PASSWORD = "fixture-password";

const cases = [
  {
    name: "алиас без AS",
    sql: "SELECT format value FROM (SELECT 7 AS format)",
    row: { value: 7 },
  },
  {
    name: "условие CASE WHEN format THEN",
    sql: "SELECT CASE WHEN format THEN 1 ELSE 0 END AS n FROM (SELECT 1 AS format)",
    row: { n: 1 },
  },
  {
    name: "аргумент CASE format WHEN",
    sql: "SELECT CASE format WHEN 7 THEN 1 ELSE 0 END AS n FROM (SELECT 7 AS format)",
    row: { n: 1 },
  },
  {
    name: "оператор GLOBAL IN",
    sql: "SELECT format GLOBAL IN (7, 8) AS n FROM (SELECT 7 AS format)",
    row: { n: 1 },
  },
] as const;

for (const { name, sql, row } of cases) {
  test(`validateSql: колонка format — ${name}`, async () => {
    const { validateSql } = await import("../src/lib/dashboards");
    assert.equal(validateSql(sql), null, "в этом SELECT нет выходной секции FORMAT");
  });

  test(`панель: корректный SELECT выполняется с JSONEachRow — ${name}`, async (t) => {
    const { panelQuery, runPanelQuery } = await import("../src/lib/dashboards");
    const sent: Array<{ sql: unknown; format: string | null }> = [];
    t.mock.method(globalThis, "fetch", async (input: URL | string | Request, init?: RequestInit) => {
      const url = new URL(input instanceof Request ? input.url : String(input));
      sent.push({ sql: init?.body, format: url.searchParams.get("default_format") });
      return new Response(JSON.stringify(row) + "\n", { headers: { "X-ClickHouse-Format": "JSONEachRow" } });
    });

    const result = await runPanelQuery(sql, "24h");
    assert.deepEqual({ sent, error: result.error, rows: result.rows },
      { sent: [{ sql: panelQuery(sql, "24h"), format: "JSONEachRow" }], error: undefined, rows: [row] });
  });
}
