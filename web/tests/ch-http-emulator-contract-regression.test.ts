// PR #27, круг 4. Сервер не определяет успех запроса по содержимому строк.
// Коды HTTP взяты из ClickHouse 24.8, а не из проверяемого helper:
// https://github.com/ClickHouse/ClickHouse/blob/v24.8.14.39-lts/src/Server/HTTP/exceptionCodeToHTTPStatus.cpp
import { test } from "node:test";
import assert from "node:assert/strict";
import { chHttp } from "./_ch-http";

const buffered = new URL("http://127.0.0.1:9/?default_format=JSONEachRow&wait_end_of_query=1");

for (const rows of [
  [{ exception: "Code: 1." }],
  [{ exception: "Code: 159. DB::Exception: archived log entry", author: "fixture" }, { exception: "ok" }],
  [{ nested: { exception: "Code: 241. DB::Exception: ordinary nested data" } }],
]) {
  test(`chHttp: успешные данные ${JSON.stringify(rows)} не становятся HTTP-ошибкой`, async () => {
    const body = rows.map((row) => JSON.stringify(row)).join("\n") + "\n";
    const response = await chHttp(body, { status: 200 })(buffered);
    assert.deepEqual({ status: response.status, code: response.headers.get("X-ClickHouse-Exception-Code"), body: await response.text() },
      { status: 200, code: null, body });
  });
}

for (const [code, name, status] of [
  [6, "CANNOT_PARSE_TEXT", 400],
  [60, "UNKNOWN_TABLE", 404],
  [159, "TIMEOUT_EXCEEDED", 408],
  [241, "MEMORY_LIMIT_EXCEEDED", 500],
] as const) {
  test(`chHttp: исключение ${name} имеет HTTP ${status} в 24.8`, async () => {
    const body = `Code: ${code}. DB::Exception: fixture (${name})\n`;
    const response = await chHttp(body)(new Request(buffered));
    assert.equal(response.headers.get("X-ClickHouse-Exception-Code"), String(code));
    assert.equal(response.status, status, "wait_end_of_query не превращает все виды ошибок в HTTP 500");
  });
}
