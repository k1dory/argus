// PR #27: ограничение длины лога не должно срезать закрывающую кавычку
// до маскировки. Подменён только HTTP; chCommand и обработка ошибок настоящие.
// ClickHouse 24.8 FunctionsConversion.cpp::throwExceptionForIncompletelyParsedValue
// цитирует весь буфер строки: длинный quoted-фрагмент — допустимый ответ.
import { test } from "node:test";
import assert from "node:assert/strict";
import { format } from "node:util";
import { chCommand, ClickHouseError, sqlForLog } from "../src/lib/clickhouse";

const marker = "PrivateTruncatedExceptionFixture";
const value = `1${marker}${"x".repeat(2200)}`;
const single = `Code: 6. DB::Exception: Cannot parse string '${value}' as UInt8: syntax error at position 1 (parsed just '1'). (CANNOT_PARSE_TEXT)`;
const double = `Code: 6. DB::Exception: parsed text: "${value}". (CANNOT_PARSE_TEXT)`;
const json = `{"exception": ${JSON.stringify(single)}}\n`;

for (const [shape, body, status] of [
  ["одинарные кавычки", single, 400],
  ["одинарные кавычки после HTTP 200", single, 200],
  ["двойные кавычки", double, 400],
  ["двойные кавычки после HTTP 200", double, 200],
  ["JSON-обёртка", json, 400],
] as const) {
  test(`ClickHouse: ${shape} — обрезка не раскрывает начало длинного значения`, async (t) => {
    const logs: string[] = [];
    const sql = "INSERT INTO console_audit (detail) SELECT {detail:String}";
    let calls = 0;
    assert.ok(body.slice(0, 2000).includes(marker), "маркер лежит внутри журнального префикса");
    assert.ok(!sqlForLog(sql).includes(marker), "данные передаются параметром, не текстом SQL");
    t.mock.method(console, "error", (...args: unknown[]) => { logs.push(format(...args)); });
    t.mock.method(globalThis, "fetch", async (input: URL | string | Request, init?: RequestInit) => {
      calls++;
      const url = new URL(input instanceof Request ? input.url : String(input));
      assert.equal(url.searchParams.get("param_detail"), value);
      assert.equal(init?.body, sql);
      return new Response(body, { status, headers: { "X-ClickHouse-Exception-Code": "6" } });
    });

    await assert.rejects(chCommand(sql, { detail: value }), (e: unknown) => {
      assert.ok(e instanceof ClickHouseError);
      assert.equal(e.code, 6);
      assert.ok(!e.message.includes(marker), "короткая ошибка уже получает полный текст");
      return true;
    });
    assert.equal(calls, 1);
    assert.equal(logs.length, 1);
    assert.match(logs.join("\n"), /INSERT INTO console_audit/);
    assert.ok(!logs.join("\n").includes(marker), "закрывающая кавычка после 2000 символов не должна отключать маскировку");
  });
}
