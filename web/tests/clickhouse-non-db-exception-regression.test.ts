// PR #27: ClickHouse 24.8 возвращает не только DB::Exception.
// Форматы взяты из getCurrentExceptionMessageAndPattern:
// https://github.com/ClickHouse/ClickHouse/blob/v24.8.14.39-lts/src/Common/Exception.cpp#L415-L438
// Подменён только транспорт, сеть и живой ClickHouse не используются.
import { test } from "node:test";
import assert from "node:assert/strict";
import { format } from "node:util";
import { chCommand, chQuery, ClickHouseError, shortChError } from "../src/lib/clickhouse";
import { installNextMocks, loadAuth } from "./_next-mock";
import { chHttp } from "./_ch-http";

const marker = "PrivateNonDbExceptionFixture";
const cases = [
  { code: 1000, name: "POCO_EXCEPTION", text: `Poco::Exception. Code: 1000, e.code() = 0, Data error: ${marker} (version 24.8.14.39 (official build))` },
  { code: 1001, name: "STD_EXCEPTION", text: `std::exception. Code: 1001, type: std::runtime_error, e.what() = ${marker} (version 24.8.14.39 (official build))` },
] as const;

for (const fixture of cases) {
  for (const shape of ["plain", "json"] as const) {
    const body = shape === "plain" ? fixture.text + "\n" : JSON.stringify({ exception: fixture.text }) + "\n";

    test(`shortChError: ${fixture.name}/${shape} сохраняет код без заголовка`, () => {
      assert.deepEqual(shortChError(body, 500), {
        code: fixture.code, message: `код ${fixture.code} (${fixture.name})`,
      });
    });

    test(`chQuery: ${fixture.name}/${shape} после HTTP 200 не становится данными`, async (t) => {
      const logs: string[] = [];
      t.mock.method(console, "error", (...args: unknown[]) => { logs.push(format(...args)); });
      t.mock.method(globalThis, "fetch", chHttp('{"n":1}\n' + body));
      await assert.rejects(chQuery("SELECT 1 AS n"), (error: unknown) => {
        assert.ok(error instanceof ClickHouseError, "исключение должно обрабатываться до JSON.parse");
        assert.equal(error.code, fixture.code);
        assert.equal(error.status, 500, "с wait_end_of_query=1 сервер отвечает HTTP-ошибкой, а не 200");
        assert.ok(!format(error).includes(marker), "message и stack не содержат текст сервера");
        return true;
      });
      assert.ok(!logs.join("\n").includes(marker));
    });
  }

  test(`chCommand: ${fixture.name} после HTTP 200 не подтверждает неуспешную запись`, async (t) => {
    t.mock.method(console, "error", () => undefined);
    t.mock.method(globalThis, "fetch", chHttp(fixture.text + "\n"));
    await assert.rejects(chCommand("INSERT INTO console_audit (detail) VALUES ({detail:String})", { detail: marker }),
      (error: unknown) => error instanceof ClickHouseError && error.code === fixture.code);
  });
}

installNextMocks();
loadAuth();
const token = "non-db-export-fixture-" + "a".repeat(40);
process.env.ARGUS_API_TOKEN = token;
/* eslint-disable @typescript-eslint/no-require-imports -- настоящий route после Next/auth mocks; search и clickhouse не подменены */
const route = require("../src/app/api/search/route") as typeof import("../src/app/api/search/route");
/* eslint-enable @typescript-eslint/no-require-imports */

test("GET /api/search: JSON-исключение std::exception не уходит в успешный экспорт", async (t) => {
  const logs: string[] = [];
  t.mock.method(console, "error", (...args: unknown[]) => { logs.push(format(...args)); });
  t.mock.method(globalThis, "fetch", chHttp(
    '{"time":"2026-11-01 10:00:00.000","source":"fixture","action":"login"}\n'
    + JSON.stringify({ exception: cases[1].text }) + "\n",
  ));
  const response = await route.GET(new Request("http://fixture/api/search?index=events&format=export&range=24h", {
    headers: { Authorization: `Bearer ${token}` },
  }));
  const body = await response.text();
  assert.ok(!body.includes(marker), "текст исключения не должен сериализоваться в rows ответа API");
  assert.ok(response.status >= 400, "экспорт с поздним исключением не является успешным");
  assert.ok(!logs.join("\n").includes(marker));
});
