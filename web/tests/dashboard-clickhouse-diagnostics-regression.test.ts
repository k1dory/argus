import { test } from "node:test";
import assert from "node:assert/strict";
import { format } from "node:util";

process.env.CLICKHOUSE_RO_USER = "fixture-ro";
process.env.CLICKHOUSE_RO_PASSWORD = "fixture-password";
const queryId = "ed948b42-fc93-41f3-85c9-e13705928f97";

for (const status of [200, 500]) {
  test(`панель: ошибка только в заголовке HTTP ${status} сохраняет код и query_id`, async (t) => {
    const { runPanelQuery } = await import("../src/lib/dashboards");
    const logs: string[] = [];
    t.mock.method(console, "error", (...args: unknown[]) => { logs.push(format(...args)); });
    t.mock.method(globalThis, "fetch", async () => new Response("", {
      status,
      headers: { "X-ClickHouse-Exception-Code": "159", "X-ClickHouse-Query-Id": queryId },
    }));
    const result = await runPanelQuery("SELECT count() AS n FROM events", "24h");
    assert.deepEqual(result.rows, []);
    assert.match(result.error ?? "", /код 159 \(TIMEOUT_EXCEEDED\)/,
      "executePanel должен передать headerCode в shortChError");
    assert.ok((JSON.stringify(result) + logs.join("\n")).includes(queryId),
      "без query_id ни ответ панели, ни серверный журнал не позволяют найти полную ошибку");
  });
}
