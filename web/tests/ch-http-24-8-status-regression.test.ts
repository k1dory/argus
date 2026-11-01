// PR #38: независимые ожидания для exceptionCodeToHTTPStatus в 24.8.14.39.
// Эти значения нельзя выводить из таблицы STATUS проверяемого эмулятора.
// https://github.com/ClickHouse/ClickHouse/blob/v24.8.14.39-lts/src/Server/HTTP/exceptionCodeToHTTPStatus.cpp
// https://github.com/ClickHouse/ClickHouse/blob/v24.8.14.39-lts/src/Common/ErrorCodes.cpp
import { test } from "node:test";
import assert from "node:assert/strict";
import { chHttp } from "./_ch-http";

const buffered = new URL("http://127.0.0.1:9/?wait_end_of_query=1");

for (const [code, name, status] of [
  [25, "CANNOT_PARSE_ESCAPE_SEQUENCE", 400],
  [53, "TYPE_MISMATCH", 400],
  [46, "UNKNOWN_FUNCTION", 404],
  [47, "UNKNOWN_IDENTIFIER", 404],
  [115, "UNKNOWN_SETTING", 404],
  [192, "UNKNOWN_USER", 403],
  [193, "WRONG_PASSWORD", 403],
  [194, "REQUIRED_PASSWORD", 401],
  [512, "SET_NON_GRANTED_ROLE", 403],
  // ACCESS_DENIED отсутствует в специальных ветках: это HTTP 500, не 403.
  [497, "ACCESS_DENIED", 500],
  [48, "NOT_IMPLEMENTED", 501],
  [76, "CANNOT_OPEN_FILE", 503],
  [209, "SOCKET_TIMEOUT", 503],
  [229, "QUERY_IS_TOO_LARGE", 413],
  [381, "HTTP_LENGTH_REQUIRED", 411],
  [439, "CANNOT_SCHEDULE_TASK", 503],
  // Контроль уже поддержанных веток и обычного кода без специального статуса.
  [159, "TIMEOUT_EXCEEDED", 408],
  [516, "AUTHENTICATION_FAILED", 403],
  [241, "MEMORY_LIMIT_EXCEEDED", 500],
] as const) {
  test(`chHttp 24.8: ${name} (${code}) -> HTTP ${status}`, async () => {
    const body = `Code: ${code}. DB::Exception: fixture. (${name})\n`;
    const response = await chHttp(body)(buffered);
    assert.deepEqual({ status: response.status, code: response.headers.get("X-ClickHouse-Exception-Code") },
      { status, code: String(code) }, "HTTP-статус определяется полным контрактом сервера 24.8");
  });
}
