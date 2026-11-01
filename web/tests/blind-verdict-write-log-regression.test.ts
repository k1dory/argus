// PR #13, повторное ревью: скрытый вердикт не должен попасть в журнал даже
// при ошибке INSERT. saveAgentVerdict и chCommand настоящие; подменён только
// HTTP-транспорт. JSONEachRow находится в теле SQL, а не только в ответе БД.
import { test } from "node:test";
import assert from "node:assert/strict";
import { format } from "node:util";
import { saveAgentVerdict, type AgentVerdictRow } from "../src/lib/argus-queries";
import { hideVerdicts } from "../src/lib/blind";
import { ClickHouseError } from "../src/lib/clickhouse";
import { VERDICT_OK } from "./_verdict-fixture";

const id = "INC-4";
const marker = "Hidden blind insert decision";
// Валидный документ с summary в начале: порядок ключей JSON не должен
// определять, какая часть скрытого решения утечёт при ошибке хранилища.
const { summary: _summary, ...document } = VERDICT_OK;
void _summary;
const row: Omit<AgentVerdictRow, "created_at"> = {
  incident_id: id, session_id: "fixture-session", agent: "fixture-bot",
  verdict: "true_positive", confidence: 0.9, human_needed: 1,
  verdict_json: JSON.stringify({ summary: marker, ...document, incident_id: id }),
  markdown: `**${marker}**`,
};

for (const status of [500, 200]) {
  test(`blind: ошибка INSERT при HTTP ${status} не логирует документ вердикта`, async (t) => {
    assert.equal(hideVerdicts({ incident_id: id, status: "in_progress" }), true);
    const logs: string[] = [];
    let fail = false;
    let writes = 0;
    t.mock.method(console, "error", (...args: unknown[]) => { logs.push(format(...args)); });
    t.mock.method(globalThis, "fetch", async (_input: unknown, init?: RequestInit) => {
      const sql = String(init?.body);
      assert.match(sql, /^INSERT INTO agent_verdicts\b/);
      assert.ok(sql.includes(marker), "проверяется настоящая запись документа, не пустой запрос");
      writes++;
      return fail
        ? new Response("Code: 241. DB::Exception: Memory limit exceeded\n", {
          status, headers: { "X-ClickHouse-Exception-Code": "241" },
        })
        : new Response("");
    });

    await saveAgentVerdict(row);
    assert.equal(writes, 1, "положительный контроль записи прошёл через настоящий HTTP-клиент");
    assert.deepEqual(logs, []);

    fail = true;
    await assert.rejects(saveAgentVerdict(row), (error: unknown) =>
      error instanceof ClickHouseError && error.code === 241 && error.status === status);
    assert.equal(writes, 2);
    const output = logs.join("\n");
    assert.match(output, /241/, "диагностический код ошибки сохраняется");
    assert.ok(!output.includes(marker), "SQL после FORMAT содержит скрытый документ и не должен логироваться");
    assert.ok(!output.includes('"verdict":"true_positive"'), "категория решения тоже скрыта до завершения");
  });
}
