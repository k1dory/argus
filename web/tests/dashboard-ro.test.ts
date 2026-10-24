import { test } from "node:test";
import assert from "node:assert/strict";

// RO-пользователь читается при загрузке модуля — окружение до импорта.
process.env.CLICKHOUSE_RO_USER = "argus_ro";
process.env.CLICKHOUSE_RO_PASSWORD = "test";
const runPanelQuery: typeof import("../src/lib/dashboards").runPanelQuery = async (...args) =>
  (await import("../src/lib/dashboards")).runPanelQuery(...args);

test("панель: в запросе нет настроек ClickHouse — при readonly=1 они отклоняются", async (t) => {
  let seen: URL | null = null;
  t.mock.method(globalThis, "fetch", async (input: URL) => {
    seen = new URL(input);
    return new Response('{"n":1}\n');
  });
  const d = await runPanelQuery("SELECT 1 AS n", "24h");
  assert.equal(d.error, undefined);
  assert.deepEqual(d.rows, [{ n: 1 }]);
  assert.deepEqual([...seen!.searchParams.keys()].sort(), ["database", "default_format"]);
});

test("панель: break режет по блокам — строк не больше 5000, truncated", async (t) => {
  t.mock.method(globalThis, "fetch", async () => new Response(Array.from({ length: 8192 }, (_, i) => `{"i":${i}}`).join("\n") + "\n"));
  const d = await runPanelQuery("SELECT number AS i FROM numbers(8192)", "24h");
  assert.equal(d.rows.length, 5000);
  assert.equal(d.truncated, true);
});

test("панель: исключение после HTTP 200 — ошибка, а не строка данных", async (t) => {
  for (const body of [
    '{"n":1}\n{"exception": "Code: 159. DB::Exception: Timeout exceeded: elapsed 20 seconds"}\n',
    '{"n":1}\nCode: 159. DB::Exception: Timeout exceeded: elapsed 20 seconds\n',
  ]) {
    t.mock.method(globalThis, "fetch", async () => new Response(body));
    const d = await runPanelQuery("SELECT 1 AS n", "24h");
    assert.match(d.error ?? "", /код 159/);
    assert.deepEqual(d.rows, []);
    t.mock.restoreAll();
  }
});

test("панель: не больше 3 одновременных запросов (у argus_ro лимит 4)", async (t) => {
  let now = 0, peak = 0;
  t.mock.method(globalThis, "fetch", async () => {
    peak = Math.max(peak, ++now);
    await new Promise((r) => setTimeout(r, 5));
    now--;
    return new Response('{"n":1}\n');
  });
  const all = await Promise.all(Array.from({ length: 9 }, (_, i) => runPanelQuery(`SELECT ${i} AS n`, "24h")));
  assert.equal(all.filter((d) => !d.error).length, 9);
  assert.equal(peak, 3);
});

test("панель: слот освобождается после ошибки и таймаута fetch", async (t) => {
  let calls = 0;
  t.mock.method(globalThis, "fetch", async () => {
    calls++;
    if (calls % 2) throw new TypeError("fetch failed");
    throw new DOMException("The operation was aborted due to timeout", "TimeoutError");
  });
  // 3 слота: если бы они утекали, 4-й запрос повис бы навсегда.
  const all = await Promise.all(Array.from({ length: 8 }, (_, i) => runPanelQuery(`SELECT ${i} AS n`, "24h")));
  assert.equal(calls, 8);
  assert.ok(all.every((d) => d.error));
  t.mock.restoreAll();
  t.mock.method(globalThis, "fetch", async () => new Response('{"n":1}\n'));
  assert.deepEqual((await runPanelQuery("SELECT 1 AS n", "24h")).rows, [{ n: 1 }]);
});

test("панель: не-200 и X-ClickHouse-Exception-Code — ошибка с кодом", async (t) => {
  t.mock.method(globalThis, "fetch", async () => new Response("Code: 241. DB::Exception: Memory limit (for query) exceeded", {
    status: 500, headers: { "X-ClickHouse-Exception-Code": "241" },
  }));
  const d = await runPanelQuery("SELECT 1 AS n", "24h");
  assert.match(d.error ?? "", /код 241/);
  assert.match(d.errorDetail ?? "", /Memory limit/);
});

test("панель: «Code: …» внутри данных не исключение — смотрим только последнюю строку", async (t) => {
  const body = '{"msg":"Code: 1. DB::Exception: из лога"}\n{"msg":"ok"}\n';
  t.mock.method(globalThis, "fetch", async () => new Response(body));
  const d = await runPanelQuery("SELECT msg FROM t", "24h");
  assert.equal(d.error, undefined);
  assert.equal(d.rows.length, 2);
});

test("панель: хвост \"} у исключения отрезан", async (t) => {
  t.mock.method(globalThis, "fetch", async () => new Response('{"n":1}\n{"exception": "Code: 159. DB::Exception: Timeout exceeded"}\n'));
  const d = await runPanelQuery("SELECT 2 AS n", "24h");
  assert.equal(d.errorDetail, "Code: 159. DB::Exception: Timeout exceeded");
});

test("панель: оборванный JSON — «ответ ClickHouse оборван» и truncated", async (t) => {
  t.mock.method(globalThis, "fetch", async () => new Response('{"n":1}\n{"n":'));
  const d = await runPanelQuery("SELECT 3 AS n", "24h");
  assert.equal(d.error, "ответ ClickHouse оборван");
  assert.equal(d.truncated, true);
});

test("createLimiter: ожидание ограничено по времени и отменяется сигналом", async () => {
  const { createLimiter, LimiterWaitError } = await import("../src/lib/clickhouse");
  const run = createLimiter(1);
  let release!: () => void;
  const busy = run(() => new Promise<void>((r) => { release = r; }));
  await assert.rejects(run(async () => "x", { maxWaitMs: 10 }), (e) => e instanceof LimiterWaitError && e.reason === "timeout");
  const ac = new AbortController();
  const waiting = run(async () => "x", { signal: ac.signal });
  ac.abort();
  await assert.rejects(waiting, (e) => e instanceof LimiterWaitError && e.reason === "aborted");
  const next = run(async () => "after");
  release();
  await busy;
  assert.equal(await next, "after", "снятые из очереди не держат слот");
});
