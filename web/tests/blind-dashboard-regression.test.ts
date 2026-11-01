// PR #13: SQL-предпросмотр доступен тому же аналитику, который ставит blind-метку.
// Авторизация, server action, валидация SQL и обработка результата — настоящие;
// подменён только HTTP ClickHouse. Production argus_ro имеет SELECT ON argus.*.
import { test } from "node:test";
import assert from "node:assert/strict";
import { formData, installNextMocks, loadAuth } from "./_next-mock";
import { hideVerdicts } from "../src/lib/blind";

process.env.CLICKHOUSE_RO_USER = "argus_ro";
process.env.CLICKHOUSE_RO_PASSWORD = "fixture-only-password";
const mocks = installNextMocks();
const auth = loadAuth();
/* eslint-disable @typescript-eslint/no-require-imports -- конфигурация RO до загрузки настоящего action */
const { previewPanelAction } = require("../src/lib/dashboard-actions") as typeof import("../src/lib/dashboard-actions");
/* eslint-enable @typescript-eslint/no-require-imports */

const id = "INC-4";
const marker = "HiddenDecisionViaDashboardPreview";

for (const [table, column] of [["incident_verdicts", "summary_ru"], ["agent_verdicts", "markdown"]] as const) {
  test(`blind: аналитик не получает ${table} открытого инцидента через previewPanelAction`, async (t) => {
    const incident = { incident_id: id, status: "in_progress" };
    assert.equal(hideVerdicts(incident), true);
    mocks.queries.incidentGet = async () => incident;
    await auth.createSession(`sso:blind-dashboard-${table}`, "analyst", true);
    const sql = `SELECT ${column} FROM ${table} WHERE incident_id = '${id}'`;
    t.mock.method(globalThis, "fetch", async (_input: unknown, init?: RequestInit) => {
      const query = String(init?.body ?? "");
      if (query === "SELECT 1 AS n") return new Response('{"n":1}\n');
      assert.equal(query, sql, "фикстура отвечает только на конкретный запрос скрытого вердикта");
      return new Response(JSON.stringify({ [column]: marker }) + "\n");
    });

    const control = await previewPanelAction({ data: null, error: null }, formData({ sql: "SELECT 1 AS n", range: "24h" }));
    assert.equal(control.error, null, "аналитик авторизован, RO-пользователь настроен");
    assert.deepEqual(control.data?.rows, [{ n: 1 }]);

    const result = await previewPanelAction({ data: null, error: null }, formData({ sql, range: "24h" }));
    assert.ok(!JSON.stringify(result).includes(marker), "SQL-предпросмотр не должен обходить запрет подсказок до закрытия");
  });
}
