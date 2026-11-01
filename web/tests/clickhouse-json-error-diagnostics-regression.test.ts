// PR #27: JSON-обёртка — транспорт: код и имя исключения сохраняются (текст не выводится).
// Формат ClickHouse 24.8: JSONEachRowRowOutputFormat::writeSuffix вызывает
// JSONUtils::writeException, записывающий {"exception": "Code: ..."}.
// Подменён HTTP-ответ; это проверка клиента, не живого ClickHouse.
import { test } from "node:test";
import assert from "node:assert/strict";
import { format } from "node:util";
import { chQuery, ClickHouseError, shortChError } from "../src/lib/clickhouse";

const plain = "Code: 60. DB::Exception: Table argus.fixture_missing does not exist. (UNKNOWN_TABLE) (version 24.8.14.39 (official build))";
const body = `{"exception": ${JSON.stringify(plain)}}\n`;

test("shortChError: JSON сохраняет код и безопасную причину так же, как текстовый ответ", () => {
  const control = shortChError(plain, 404);
  assert.equal(control.code, 60);
  assert.equal(control.message, "код 60 (UNKNOWN_TABLE)");
  assert.deepEqual(shortChError(body, 404), control, "маскировать нужно содержание exception после разбора JSON");
});

for (const withHeader of [true, false]) {
  test(`chQuery: JSON-исключение ${withHeader ? "с" : "без"} заголовка сохраняет диагностику`, async (t) => {
    const logs: string[] = [];
    let caught: ClickHouseError | undefined;
    let calls = 0;
    t.mock.method(console, "error", (...args: unknown[]) => { logs.push(format(...args)); });
    t.mock.method(globalThis, "fetch", async (input: URL | string | Request) => {
      calls++;
      const url = new URL(input instanceof Request ? input.url : String(input));
      assert.equal(url.searchParams.get("default_format"), "JSONEachRow");
      return new Response(body, {
        status: 404,
        headers: withHeader ? { "X-ClickHouse-Exception-Code": "60" } : {},
      });
    });
    await assert.rejects(chQuery("SELECT * FROM fixture_missing"), (e: unknown) => {
      assert.ok(e instanceof ClickHouseError);
      caught = e;
      return true;
    });
    assert.equal(calls, 1);
    assert.ok(caught);
    const error = caught;
    await t.test("короткое сообщение", () => {
      assert.equal(error.code, 60);
      assert.equal(error.message, "код 60 (UNKNOWN_TABLE)");
    });
    await t.test("серверный журнал", () => {
      assert.match(logs.join("\n"), /код 60 \(UNKNOWN_TABLE\)/);
      assert.ok(!logs.join("\n").includes("fixture_missing does not exist"), "текст исключения не логируется: полный — в system.query_log");
    });
  });
}
