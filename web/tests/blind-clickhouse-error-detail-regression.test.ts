// PR #24: безопасный SQL-заголовок не делает безопасным текст исключения.
// ClickHouse возвращает фрагменты входной строки/выражения в диагностике.
// Эти транспортные fixtures проверяют обработку такого ответа, не объявляя
// его воспроизведённым на живом сервере. Запись вердикта и аудит настоящие.
import { test } from "node:test";
import assert from "node:assert/strict";
import { format } from "node:util";
import { audit, saveAgentVerdict, type AgentVerdictRow } from "../src/lib/argus-queries";
import { ClickHouseError, sqlForLog } from "../src/lib/clickhouse";
import { hideVerdicts } from "../src/lib/blind";
import { VERDICT_OK } from "./_verdict-fixture";

const marker = "PrivateDecisionInClickHouseExceptionFixture";
const id = "INC-4";
const row: Omit<AgentVerdictRow, "created_at"> = {
  incident_id: id, session_id: "fixture-session", agent: "fixture-bot",
  verdict: "true_positive", confidence: 0.9, human_needed: 1,
  verdict_json: JSON.stringify({ ...VERDICT_OK, incident_id: id, summary: marker }),
  markdown: marker,
};

for (const status of [500, 200]) {
  test(`blind: HTTP ${status} с диагностикой строки INSERT не раскрывает её в журнале`, async (t) => {
    assert.equal(hideVerdicts({ incident_id: id, status: "in_progress" }), true);
    const logs: string[] = [];
    let fail = false;
    let writes = 0;
    t.mock.method(console, "error", (...args: unknown[]) => { logs.push(format(...args)); });
    t.mock.method(globalThis, "fetch", async (_input: unknown, init?: RequestInit) => {
      writes++;
      const sql = String(init?.body);
      assert.match(sql, /^INSERT INTO agent_verdicts FORMAT JSONEachRow\n/);
      assert.ok(sql.includes(marker));
      assert.ok(!sqlForLog(sql).includes(marker), "SQL уже очищен: проверяется отдельный канал detail");
      return fail ? new Response(
        `Code: 27. DB::Exception: Cannot parse input: '${marker}': (at row 1)\n`,
        { status, headers: { "X-ClickHouse-Exception-Code": "27" } },
      ) : new Response("");
    });

    await saveAgentVerdict(row);
    assert.equal(writes, 1);
    assert.deepEqual(logs, [], "успешная запись не логирует документ");
    fail = true;
    await assert.rejects(saveAgentVerdict(row), (error: unknown) =>
      error instanceof ClickHouseError && error.code === 27 && error.status === status);
    assert.equal(writes, 2);
    assert.match(logs.join("\n"), /27/, "диагностический код должен сохраниться");
    assert.ok(!logs.join("\n").includes(marker), "фрагмент строки в исключении тоже содержит закрытые данные");
  });
}

test("blind: подставленный параметр аудита не попадает в console.error через исключение", async (t) => {
  const logs: string[] = [];
  let writes = 0;
  t.mock.method(console, "error", (...args: unknown[]) => { logs.push(format(...args)); });
  t.mock.method(globalThis, "fetch", async (input: URL | string | Request, init?: RequestInit) => {
    writes++;
    const url = new URL(input instanceof Request ? input.url : String(input));
    assert.equal(url.searchParams.get("param_detail"), marker);
    assert.match(String(init?.body), /^INSERT INTO console_audit/);
    assert.ok(!String(init?.body).includes(marker), "в SQL только плейсхолдер; редактировать его недостаточно");
    return new Response(
      `Code: 6. DB::Exception: Cannot parse string '${marker}' as UInt8: while processing expression. (CANNOT_PARSE_TEXT)\n`,
      { status: 400, headers: { "X-ClickHouse-Exception-Code": "6" } },
    );
  });

  await assert.rejects(audit("triage:fixture-session", "triage.verdict", id, marker, { strict: true }),
    /журнал действий недоступен/);
  assert.equal(writes, 1);
  assert.match(logs.join("\n"), /6/);
  assert.ok(!logs.join("\n").includes(marker), "ни detail ClickHouse, ни повторный лог audit не должны содержать параметр");
});
