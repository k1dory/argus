// PR #27, круг 4: запрет выходной секции FORMAT не должен запрещать
// встроенную строковую функцию format() и идентификатор с тем же именем.
import { test } from "node:test";
import assert from "node:assert/strict";

process.env.CLICKHOUSE_RO_USER = "fixture-ro";
process.env.CLICKHOUSE_RO_PASSWORD = "fixture-password";

for (const sql of [
  "SELECT format('{} {}', 'Hello', 'World') AS message",
  "SELECT format /* function argument list */ ('{}', 'ok') AS message",
  "SELECT 1 AS format",
  "SELECT format FROM (SELECT 1 AS format)",
]) {
  test(`validateSql: выражение без выходной секции — ${sql}`, async () => {
    const { validateSql } = await import("../src/lib/dashboards");
    assert.equal(validateSql(sql), null, "слово format в выражении не меняет формат HTTP-ответа");
  });
}

test("панель с format() выполняется с заданным консолью JSONEachRow", async (t) => {
  const { panelQuery, runPanelQuery } = await import("../src/lib/dashboards");
  const sql = "SELECT format('{} {}', 'Hello', 'World') AS message";
  let calls = 0;
  t.mock.method(globalThis, "fetch", async (input: URL | string | Request, init?: RequestInit) => {
    calls++;
    const url = new URL(input instanceof Request ? input.url : String(input));
    assert.equal(url.searchParams.get("default_format"), "JSONEachRow");
    assert.equal(url.searchParams.get("wait_end_of_query"), "1");
    assert.equal(init?.body, panelQuery(sql, "24h"));
    return new Response('{"message":"Hello World"}\n');
  });
  const data = await runPanelQuery(sql, "24h");
  assert.equal(data.error, undefined);
  assert.deepEqual(data.rows, [{ message: "Hello World" }]);
  assert.equal(calls, 1);
});
