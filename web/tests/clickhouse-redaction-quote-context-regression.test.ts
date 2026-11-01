// PR #27: один тип кавычек внутри другого не начинает новый фрагмент.
// Ответы ниже — транспортные fixtures, не запись воспроизведения на сервере.
import { test } from "node:test";
import assert from "node:assert/strict";
import { format } from "node:util";
import { chCommand, ClickHouseError, redactChText, shortChError } from "../src/lib/clickhouse";

const marker = "PrivateQuoteContextFixture";
// Апостроф допустим внутри двойных кавычек, двойная — внутри одинарных.
// Раздельные replace сначала съедают участок от can't до 'field, затем
// от первой двойной кавычки до field", оставляя marker снаружи маски.
const detail = `Code: 27. DB::Exception: parsed text: "can't parse"; Cannot parse input: 'field"${marker}'. (CANNOT_PARSE_INPUT_ASSERTION_FAILED)`;

test("redactChText: соседние фрагменты с разными кавычками маскируются независимо", () => {
  assert.equal(redactChText(detail),
    `Code: 27. DB::Exception: parsed text: "…"; Cannot parse input: '…'. (CANNOT_PARSE_INPUT_ASSERTION_FAILED)`);
});

test("shortChError: смешанные кавычки не раскрывают данные в сообщении для пользователя", () => {
  const error = shortChError(detail, 400);
  assert.equal(error.code, 27);
  assert.ok(!error.message.includes(marker), "короткое сообщение тоже пересекает границу закрытых данных");
});

test("chCommand: смешанные кавычки не раскрывают данные в console.error", async (t) => {
  const logs: string[] = [];
  let calls = 0;
  const sql = `INSERT INTO incident_comments FORMAT JSONEachRow\n${JSON.stringify({ body: `can't parse field"${marker}` })}`;
  t.mock.method(console, "error", (...args: unknown[]) => { logs.push(format(...args)); });
  t.mock.method(globalThis, "fetch", async (_input: unknown, init?: RequestInit) => {
    calls++;
    assert.equal(init?.body, sql, "маскировка не изменяет отправленные данные");
    return new Response(detail, { status: 400, headers: { "X-ClickHouse-Exception-Code": "27" } });
  });
  await assert.rejects(chCommand(sql), (e: unknown) => e instanceof ClickHouseError && e.code === 27);
  assert.equal(calls, 1);
  assert.match(logs.join("\n"), /27/);
  assert.ok(!logs.join("\n").includes(marker), "короткий ответ содержит полностью закрытые кавычки");
});

test("redactChText: контроль экранирования, многострочности и имён в обратных кавычках", () => {
  for (const text of [
    String.raw`'before\'${marker}'`,
    String.raw`'before''${marker}'`,
    String.raw`"before\"${marker}"`,
    String.raw`'${marker}\\'`,
    `'first line\n${marker}\nlast line'`,
    `"first line\n${marker}\nlast line"`,
  ]) {
    assert.ok(!redactChText(text).includes(marker), `закрытый фрагмент: ${JSON.stringify(text)}`);
  }
  const identifier = "Code: 60. DB::Exception: Table `argus.fixture_missing` does not exist";
  assert.equal(redactChText(identifier), identifier, "имя таблицы необходимо для диагностики");
});
