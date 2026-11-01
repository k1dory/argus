// Контрольные сценарии PR #27: имя берётся из CH_ERROR_NAMES, а не из
// тела/произвольного заголовка. Текст, SQL-литералы и INSERT-данные скрыты.
import { test } from "node:test";
import assert from "node:assert/strict";
import { format } from "node:util";
import { chCommand, chQuery, ClickHouseError, sqlForLog } from "../src/lib/clickhouse";
import { chHttp, chJsonException } from "./_ch-http";

const marker = "PrivateMetadataFixture";
const queryId = "ed948b42-fc93-41f3-85c9-e13705928f97";

for (const [header, code, name] of [
  ["241", 241, "MEMORY_LIMIT_EXCEEDED"],
  ["60 " + marker, 60, "UNKNOWN_TABLE"],
  ["__proto__", 60, "UNKNOWN_TABLE"],
  ["constructor", 60, "UNKNOWN_TABLE"],
] as const) {
  test(`ClickHouse: заголовок ${header} не внедряет произвольное имя`, async (t) => {
    const logs: string[] = [];
    t.mock.method(console, "error", (...args: unknown[]) => { logs.push(format(...args)); });
    t.mock.method(globalThis, "fetch", async () => new Response(
      `Code: 60. DB::Exception: '${marker}' (${marker})`, {
        status: 500,
        headers: { "X-ClickHouse-Exception-Code": header, "X-ClickHouse-Exception-Name": marker, "X-ClickHouse-Query-Id": queryId },
      },
    ));
    await assert.rejects(chCommand(`SELECT '${marker}'`), (error: unknown) => {
      assert.ok(error instanceof ClickHouseError);
      assert.equal(error.code, code);
      assert.equal(error.status, 500);
      assert.equal(error.message, `код ${code} (${name})`);
      assert.ok(!format(error).includes(marker));
      return true;
    });
    assert.ok(!logs.join("\n").includes(marker));
    assert.ok(logs.join("\n").includes(queryId));
  });
}

test("ClickHouse: штатная JSON DB::Exception после HTTP 200 отклоняется без утечки", async (t) => {
  const logs: string[] = [];
  t.mock.method(console, "error", (...args: unknown[]) => { logs.push(format(...args)); });
  t.mock.method(globalThis, "fetch", chHttp(
    JSON.stringify({ body: marker }) + "\n"
    + chJsonException(`Code: 241. DB::Exception: '${marker}' (SPOOFED_NAME)`) + "\n",
  ));
  await assert.rejects(chQuery("SELECT body FROM incident_comments"), (error: unknown) =>
    error instanceof ClickHouseError && error.code === 241 && error.message === "код 241 (MEMORY_LIMIT_EXCEEDED)");
  assert.ok(!logs.join("\n").includes(marker));
});

test("sqlForLog: реальные формы записи вердикта/аудита и длинный SELECT-литерал скрыты", () => {
  for (const sql of [
    `INSERT INTO agent_verdicts FORMAT JSONEachRow\n${JSON.stringify({ markdown: marker })}`,
    "INSERT INTO console_audit (detail) VALUES ({detail:String})",
    `SELECT '${marker}${"x".repeat(600)}'`,
    `SELECT 'can\\'t ${marker}', 'double''quote ${marker}'`,
  ]) {
    const logged = sqlForLog(sql);
    assert.ok(!logged.includes(marker));
    assert.ok(logged.length <= 500);
  }
});
