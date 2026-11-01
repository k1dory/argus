// PR #27: SyntaxError от JSON.parse в Node 22 содержит фрагмент входа.
// Панель допускает явный FORMAT, который переопределяет default_format.
// Проверяется настоящий JSON.parse, а не подставленная ошибка с готовым message.
import { test } from "node:test";
import assert from "node:assert/strict";
import { format } from "node:util";
import { chQuery, safeQuery } from "../src/lib/clickhouse";

process.env.CLICKHOUSE_RO_USER = "fixture-ro";
process.env.CLICKHOUSE_RO_PASSWORD = "fixture-password";
const marker = "CHSecret7"; // короткий маркер целиком помещается в snippet V8

test("панель: FORMAT TabSeparated не переносит значение колонки в журнал через SyntaxError", async (t) => {
  const { runPanelQuery, validateSql } = await import("../src/lib/dashboards");
  const sql = "SELECT body FROM incident_comments FORMAT TabSeparated";
  const logs: string[] = [];
  t.mock.method(console, "error", (...args: unknown[]) => { logs.push(format(...args)); });
  t.mock.method(globalThis, "fetch", async (_input: unknown, init?: RequestInit) => {
    assert.equal(init?.body, sql);
    return new Response(marker + "\n", { headers: { "Content-Type": "text/tab-separated-values" } });
  });
  assert.ok(validateSql(sql), "явный FORMAT в SQL панели запрещён: формат ставит консоль");
  const result = await runPanelQuery(sql, "24h");
  assert.ok(result.error);
  assert.deepEqual(result.rows, []);
  assert.ok(!JSON.stringify(result).includes(marker));
  assert.ok(!logs.join("\n").includes(marker), "JSON.parse цитирует данные в e.message; их нельзя логировать");
});

test("safeQuery: ошибка разбора ответа не переносит данные в журнал вместе со стеком", async (t) => {
  const logs: string[] = [];
  t.mock.method(console, "error", (...args: unknown[]) => { logs.push(format(...args)); });
  // Транспортная fixture: некорректный JSON при завершённом HTTP-ответе.
  t.mock.method(globalThis, "fetch", async () => new Response(marker + "\n"));
  const result = await safeQuery(() => chQuery("SELECT raw FROM events"));
  assert.equal(result.ok, false);
  assert.ok(!JSON.stringify(result).includes(marker));
  assert.ok(!logs.join("\n").includes(marker), "safeQuery логирует исходный SyntaxError вместе со snippet");
});
