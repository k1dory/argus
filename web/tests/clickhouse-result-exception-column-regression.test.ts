// PR #27, третий круг: колонка с именем exception не является служебной
// ошибкой только потому, что её значение начинается с «Code: 1.».
// Подменён только HTTP; оба клиента и JSON.parse остаются настоящими.
import { test } from "node:test";
import assert from "node:assert/strict";
import { format } from "node:util";
import { chQuery } from "../src/lib/clickhouse";

process.env.CLICKHOUSE_RO_USER = "fixture-ro";
process.env.CLICKHOUSE_RO_PASSWORD = "fixture-password";

const cases = [
  {
    name: "обычный текст Code: 1. в единственной колонке",
    sql: "SELECT 'Code: 1.' AS exception",
    rows: [{ exception: "Code: 1." }],
  },
  {
    name: "текст события в первой из нескольких колонок, до последней строки",
    sql: "SELECT body AS exception, author FROM incident_comments ORDER BY created_at",
    rows: [
      { exception: "Code: 1. DB::Exception: archived event text", author: "fixture-analyst" },
      { exception: "обычное сообщение", author: "fixture-analyst" },
    ],
  },
] as const;

for (const fixture of cases) {
  const body = fixture.rows.map((row) => JSON.stringify(row)).join("\n") + "\n";

  test(`chQuery: ${fixture.name} остаётся результатом успешного запроса`, async (t) => {
    const logs: string[] = [];
    t.mock.method(console, "error", (...args: unknown[]) => { logs.push(format(...args)); });
    t.mock.method(globalThis, "fetch", async (_input: unknown, init?: RequestInit) => {
      assert.equal(init?.body, fixture.sql);
      return new Response(body, { headers: { "X-ClickHouse-Format": "JSONEachRow" } });
    });

    assert.deepEqual(await chQuery(fixture.sql), fixture.rows,
      "успешные строки нельзя отбрасывать из-за содержимого колонки exception");
    assert.deepEqual(logs, [], "штатный ответ не должен порождать журнал ошибки ClickHouse");
  });

  test(`панель: ${fixture.name} не превращается в ошибку хранилища`, async (t) => {
    const { panelQuery, runPanelQuery, validateSql } = await import("../src/lib/dashboards");
    const logs: string[] = [];
    t.mock.method(console, "error", (...args: unknown[]) => { logs.push(format(...args)); });
    t.mock.method(globalThis, "fetch", async (_input: unknown, init?: RequestInit) => {
      assert.equal(init?.body, panelQuery(fixture.sql, "24h"));
      return new Response(body, { headers: { "X-ClickHouse-Format": "JSONEachRow" } });
    });

    assert.equal(validateSql(fixture.sql), null);
    const result = await runPanelQuery(fixture.sql, "24h");
    assert.equal(result.error, undefined, "Code: 1. в данных не означает сбой запроса");
    assert.deepEqual(result.rows, fixture.rows);
    assert.deepEqual(result.columns, Object.keys(fixture.rows[0]));
    assert.deepEqual(logs, []);
  });
}
