// PR #24: граница SQL -> console.error. Только HTTP подменён; SQL проходит
// через настоящий chCommand и sqlForLog. Ошибка не содержит исходных данных,
// поэтому эти проверки изолируют именно утечку текста отправленного запроса.
// VALUES/SELECT здесь — контракт клиента, а не утверждение о SQL-инъекции:
// существующие product-вызовы VALUES передают пользовательские поля параметрами.
import { test } from "node:test";
import assert from "node:assert/strict";
import { format } from "node:util";
import { chCommand, ClickHouseError, sqlForLog } from "../src/lib/clickhouse";

const marker = "PrivateDecisionForSqlLogShapeFixture";
const payload = JSON.stringify({ incident_id: "INC-4", markdown: marker });
const errorBody = "Code: 241. DB::Exception: Memory limit exceeded\n";
const cases = [
  ["FORMAT JSONEachRow (контроль)", `INSERT INTO agent_verdicts FORMAT JSONEachRow\n${payload}`],
  ["FORMAT с блочным комментарием", `INSERT INTO agent_verdicts FORMAT /* fixture */ JSONEachRow\n${payload}`],
  ["FORMAT со строчным комментарием", `INSERT INTO agent_verdicts FORMAT -- fixture\nJSONEachRow\n${payload}`],
  ["VALUES с литералом", `INSERT INTO agent_verdicts (incident_id, markdown) VALUES ('INC-4', '${marker}')`],
  ["SELECT с литералом", `INSERT INTO agent_verdicts (incident_id, markdown) SELECT 'INC-4', '${marker}'`],
] as const;

for (const [name, sql] of cases) {
  test(`ClickHouse: ${name} не раскрывает данные INSERT в SQL журнала`, async (t) => {
    const logs: string[] = [];
    let calls = 0;
    t.mock.method(console, "error", (...args: unknown[]) => { logs.push(format(...args)); });
    t.mock.method(globalThis, "fetch", async (_input: unknown, init?: RequestInit) => {
      calls++;
      assert.equal(init?.body, sql, "очистка для журнала не меняет отправляемый запрос");
      assert.ok(String(init?.body).includes(marker), "вход действительно содержит закрытые данные");
      return new Response(errorBody, { status: 500 });
    });

    await assert.rejects(chCommand(sql), (error: unknown) =>
      error instanceof ClickHouseError && error.code === 241 && error.status === 500);
    assert.equal(calls, 1);
    const output = logs.join("\n");
    assert.match(output, /241/, "код ошибки остаётся доступен оператору");
    assert.match(output, /INSERT INTO agent_verdicts/, "сохраняется контекст операции");
    assert.ok(!output.includes(marker), "значение строки INSERT не должно уходить в журнал");
  });
}

test("ClickHouse: параметризованные VALUES и INSERT SELECT не логируют значения param_*", async (t) => {
  const logs: string[] = [];
  let calls = 0;
  t.mock.method(console, "error", (...args: unknown[]) => { logs.push(format(...args)); });
  t.mock.method(globalThis, "fetch", async (input: URL | string | Request, init?: RequestInit) => {
    calls++;
    const url = new URL(input instanceof Request ? input.url : String(input));
    assert.equal(url.searchParams.get("param_text"), marker);
    assert.ok(!String(init?.body).includes(marker), "значение передаётся отдельно от SQL");
    return new Response(errorBody, { status: 500 });
  });
  for (const expression of ["VALUES ('INC-4', {text:String})", "SELECT 'INC-4', {text:String}"]) {
    await assert.rejects(chCommand(`INSERT INTO agent_verdicts (incident_id, markdown) ${expression}`, { text: marker }),
      (error: unknown) => error instanceof ClickHouseError && error.code === 241);
  }
  assert.equal(calls, 2);
  assert.match(logs.join("\n"), /241/);
  assert.ok(!logs.join("\n").includes(marker));
});

test("sqlForLog: обычный SELECT и ограничение длины сохраняются", () => {
  assert.equal(sqlForLog("SELECT count() FROM agent_verdicts"), "SELECT count() FROM agent_verdicts");
  assert.ok(sqlForLog(`INSERT INTO agent_verdicts FORMAT JSONEachRow\n${payload.repeat(100)}`).length <= 500);
});
