// PR #51: agreementMetrics обещает запрос без настроек, пригодный для argus_ro.
// queryAs из _ro-blind строит другой HTTP-запрос и скрывает настройки chQuery.
// Здесь исполняется настоящий agreementMetrics; перехватывается только fetch.
import { test } from "node:test";
import assert from "node:assert/strict";
import { agreementMetrics } from "../src/lib/blind-metrics";

test("agreementMetrics: HTTP-запрос совместим с неизменяемыми настройками argus_ro", async (t) => {
  const requests: URL[] = [];
  t.mock.method(globalThis, "fetch", async (input: URL | string | Request) => {
    requests.push(new URL(input instanceof Request ? input.url : String(input)));
    return new Response("");
  });

  const result = await agreementMetrics("7d", Date.UTC(2026, 10, 1, 12));
  assert.equal(result.total.labeled, 0);
  assert.equal(requests.length, 1);
  assert.equal(requests[0].searchParams.get("wait_end_of_query"), "1");
  // Это параметры HTTP и привязки SQL, не изменения настроек сессии ClickHouse.
  // В частности, max_execution_time=30 конфликтует с 20 READONLY из migrate.sh.
  const httpParams = new Set(["database", "default_format", "wait_end_of_query", "param_from", "param_to"]);
  const settings = [...requests[0].searchParams].filter(([name]) => !httpParams.has(name));
  assert.deepEqual(settings, [], "настройки argus_ro должны оставаться заданными профилем");
});
