// PR #27, круг 4. ClickHouse 24.8 распознаёт // как комментарий до LF:
// https://github.com/ClickHouse/ClickHouse/blob/v24.8.14.39-lts/src/Parsers/Lexer.cpp#L310-L319
// Кавычка в таком комментарии не должна скрывать следующий FORMAT от scanSql.
// HTTP подменён напрямую, без _ch-http: [7] — успешный JSONCompactEachRow.
import { test } from "node:test";
import assert from "node:assert/strict";

process.env.CLICKHOUSE_RO_USER = "fixture-ro";
process.env.CLICKHOUSE_RO_PASSWORD = "fixture-password";

for (const quote of ["'", '"', "`"]) {
  test(`validateSql: кавычка ${quote} в // не скрывает FORMAT`, async () => {
    const { validateSql } = await import("../src/lib/dashboards");
    const sql = `SELECT 7 AS n // ${quote}\nfOrMaT/**/JSONCompactEachRow -- ${quote}`;
    assert.ok(validateSql(sql), "ClickHouse видит FORMAT вне комментариев и литералов; консоль обязана отказать");
  });
}

test("панель: FORMAT после // не исполняется и не попадает в общий кэш", async (t) => {
  const { panelCacheGet, runPanelQuery } = await import("../src/lib/dashboards");
  const sql = "SELECT 7 AS round4_n // '\nFORMAT JSONCompactEachRow -- '";
  const key = `24h\0${sql}`;
  let calls = 0;
  t.mock.method(globalThis, "fetch", async (_input: unknown, init?: RequestInit) => {
    calls++;
    assert.equal(init?.body, sql);
    return new Response("[7]\n", { headers: { "X-ClickHouse-Format": "JSONCompactEachRow" } });
  });

  assert.equal(panelCacheGet(key, 60_000), null);
  const data = await runPanelQuery(sql, "24h", 60_000);
  assert.deepEqual({ sent: calls, rejected: Boolean(data.error), rows: data.rows, cached: panelCacheGet(key, 60_000) },
    { sent: 0, rejected: true, rows: [], cached: null },
    "массив [7] нельзя возвращать/кэшировать как объект строки с колонкой n");
});

test("validateSql: прямой FORMAT с регистром и комментариями по-прежнему запрещён", async () => {
  const { validateSql } = await import("../src/lib/dashboards");
  for (const sql of [
    "SELECT 7 FORMAT JSONCompactEachRow",
    "SELECT 7 fOrMaT/**/TabSeparated",
    "SELECT 7 /* outer /* inner */ outer */ FORMAT JSONEachRow",
    "SELECT 7 -- comment\nFORMAT JSONEachRow",
    "SELECT 7 # comment\nFORMAT JSONEachRow",
  ]) assert.ok(validateSql(sql), sql);
  assert.equal(validateSql("SELECT 'FORMAT TabSeparated' AS message /* FORMAT CSV */"), null);
});
