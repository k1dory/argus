// PR #27: executePanel использует отдельный HTTP-клиент. Проверяем реальный
// server action: очистка shortChError не должна обходиться через errorDetail.
import { test } from "node:test";
import assert from "node:assert/strict";
import { format } from "node:util";
import { formData, installNextMocks, loadAuth } from "./_next-mock";
import { chHttp } from "./_ch-http";

process.env.CLICKHOUSE_RO_USER = "fixture-ro";
process.env.CLICKHOUSE_RO_PASSWORD = "fixture-password";
installNextMocks();
const auth = loadAuth();
/* eslint-disable @typescript-eslint/no-require-imports -- окружение RO и Next mocks до загрузки клиентов */
const { previewPanelAction } = require("../src/lib/dashboard-actions") as typeof import("../src/lib/dashboard-actions");
/* eslint-enable @typescript-eslint/no-require-imports */

const marker = "PrivateDashboardExceptionFixture";
const detail = `Code: 6. DB::Exception: Cannot parse string '${marker}' as UInt8. (CANNOT_PARSE_TEXT)`;
const fixtures = [
  { name: "HTTP 400", status: 400, body: detail, headers: { "X-ClickHouse-Exception-Code": "6" } },
  { name: "JSON после HTTP 200", status: 200, body: '{"n":1}\n' + JSON.stringify({ exception: detail }) + "\n", headers: {} },
  { name: "строки ответа и код в заголовке", status: 200, body: JSON.stringify({ n: marker }) + "\n", headers: { "X-ClickHouse-Exception-Code": "6" } },
] as const;

for (const fixture of fixtures) {
  test(`previewPanelAction: ${fixture.name} не раскрывает ответ ClickHouse`, async (t) => {
    await auth.createSession("sso:dashboard-error-fixture", "analyst", true);
    const logs: string[] = [];
    t.mock.method(console, "error", (...args: unknown[]) => { logs.push(format(...args)); });
    t.mock.method(globalThis, "fetch", chHttp(fixture.body, {
      status: fixture.status, headers: fixture.headers,
    }));
    const result = await previewPanelAction({ data: null, error: null }, formData({
      sql: "SELECT toUInt8(body) AS n FROM incident_comments", range: "24h",
    }));
    assert.ok(result.error, "сбой остаётся ошибкой панели");
    assert.deepEqual(result.data?.rows, []);
    assert.ok(!JSON.stringify(result).includes(marker), "ни error, ни data.errorDetail не передают цитаты/строки клиенту");
    assert.ok(!logs.join("\n").includes(marker));
  });
}
