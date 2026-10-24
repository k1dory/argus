import { test } from "node:test";
import assert from "node:assert/strict";
import { ClickHouseError, shortChError } from "../src/lib/clickhouse";
import { searchErrorMessage } from "../src/lib/search";

// Реальные ответы ClickHouse 24.x по HTTP (тело при статусе 500/4xx).
const TIMEOUT = `Code: 159. DB::Exception: Timeout exceeded: elapsed 20.001 seconds, maximum: 20: While executing MergeTreeSelect(pool: ReadPoolInOrder, algorithm: InOrder). (TIMEOUT_EXCEEDED) (version 24.8.4.13 (official build))`;
const MEMORY = `Code: 241. DB::Exception: Memory limit (for query) exceeded: would use 1.87 GiB (attempt to allocate chunk of 4194304 bytes), maximum: 1.86 GiB.: While executing AggregatingTransform. (MEMORY_LIMIT_EXCEEDED) (version 24.8.4.13 (official build))`;
const NO_TABLE = `Code: 60. DB::Exception: Table argus.events_v2 does not exist. Maybe you meant argus.events?. (UNKNOWN_TABLE) (version 24.8.4.13 (official build))`;
const SYNTAX = `Code: 62. DB::Exception: Syntax error: failed at position 8 ('FORM'): FORM events WHERE ts > now() - INTERVAL 1 HOUR. Expected one of: FROM, ... (SYNTAX_ERROR) (version 24.8.4.13 (official build))`;
const AUTH = `Code: 516. DB::Exception: default: Authentication failed: password is incorrect, or there is no user with such name.

If you use ClickHouse Cloud, the password can be reset at https://clickhouse.cloud/ ... (AUTHENTICATION_FAILED) (version 24.8.4.13 (official build))`;

test("shortChError: код и короткая причина без хвоста «while processing»/версии", () => {
  const t = shortChError(TIMEOUT, 500);
  assert.equal(t.code, 159);
  assert.match(t.message, /^код 159: Timeout exceeded: elapsed 20.001 seconds, maximum: 20/);
  assert.ok(!/version|official build/.test(t.message));

  const m = shortChError(MEMORY, 500);
  assert.equal(m.code, 241);
  assert.match(m.message, /^код 241: Memory limit \(for query\) exceeded/);

  const n = shortChError(NO_TABLE, 404);
  assert.equal(n.code, 60);
  assert.match(n.message, /^код 60: Table argus.events_v2 does not exist/);

  const s = shortChError(SYNTAX, 400);
  assert.equal(s.code, 62);
  assert.match(s.message, /^код 62: Syntax error: failed at position 8/);
  assert.ok(s.message.length <= 170, "причина обрезана");

  const a = shortChError(AUTH, 403);
  assert.equal(a.code, 516);
  assert.match(a.message, /^код 516: default: Authentication failed/);
  assert.ok(!a.message.includes("clickhouse.cloud"), "многострочный хвост не попадает");
});

test("shortChError: без кода — по HTTP-статусу; пусто — «запрос не выполнен»", () => {
  assert.deepEqual(shortChError("<html>403 Forbidden</html>", 403), { message: "доступ к ClickHouse отклонён (учётные данные консоли)", code: null });
  assert.deepEqual(shortChError("", 401), { message: "доступ к ClickHouse отклонён (учётные данные консоли)", code: null });
  assert.deepEqual(shortChError("Bad Gateway", 502), { message: "ClickHouse ответил HTTP 502", code: null });
  assert.deepEqual(shortChError("", null), { message: "запрос не выполнен", code: null });
  assert.deepEqual(shortChError("DB::Exception: something odd", null), { message: "something odd", code: null });
});

test("searchErrorMessage: классификация по коду ClickHouseError, не по тексту", () => {
  const mk = (text: string, status: number) => { const { message, code } = shortChError(text, status); return new ClickHouseError(message, status, code); };
  assert.match(searchErrorMessage(mk(TIMEOUT, 500)), /не уложился в 20 с/);
  assert.match(searchErrorMessage(mk(MEMORY, 500)), /не хватило памяти/);
  assert.match(searchErrorMessage(mk(NO_TABLE, 404)), /подробности в логе консоли/);
  assert.match(searchErrorMessage(mk(SYNTAX, 400)), /подробности в логе консоли/);
  // Текст с «TIMEOUT_EXCEEDED», но код другой — не таймаут (раньше ловилось регуляркой по тексту)
  assert.match(searchErrorMessage(new ClickHouseError("код 60: table TIMEOUT_EXCEEDED does not exist", 404, 60)), /подробности в логе/);
  assert.match(searchErrorMessage(new ClickHouseError("ClickHouse не ответил за 30 с")), /подробности в логе/);
  assert.match(searchErrorMessage(new Error("TIMEOUT_EXCEEDED")), /подробности в логе/, "не ClickHouseError — общая фраза");
  assert.match(searchErrorMessage("MEMORY_LIMIT"), /подробности в логе/);
});
