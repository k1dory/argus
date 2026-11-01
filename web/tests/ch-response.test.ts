import { test } from "node:test";
import assert from "node:assert/strict";
import { chCommand, chQuery, ClickHouseError } from "../src/lib/clickhouse";
import { chHttp } from "./_ch-http";

test("ClickHouse rejects HTTP 200 exceptions for writes and partial reads", async (t) => {
  for (const [body, headers] of [
    ["Code: 241. DB::Exception: Memory limit exceeded", {}],
    ['{"c":1}\nCode: 241. DB::Exception: Memory limit exceeded', {}],
    ["", { "X-ClickHouse-Exception-Code": "241" }],
  ] as const) {
    t.mock.method(globalThis, "fetch", chHttp(body, { status: 200, headers }));
    const fails = (err: unknown) => err instanceof ClickHouseError && err.code === 241;
    await assert.rejects(chCommand("INSERT INTO incident_comments VALUES ()"), fails);
    await assert.rejects(chQuery("SELECT 1"), fails);
    t.mock.restoreAll();
  }
});

test("ClickHouse accepts exception text inside event JSON", async (t) => {
  const row = { raw: "Code: 241. DB::Exception: event content\nCode: 159. DB::Exception: another line" };
  t.mock.method(globalThis, "fetch", async () => new Response(JSON.stringify(row) + "\n"));
  assert.deepEqual(await chQuery("SELECT raw FROM events"), [row]);
});

test("ClickHouse body read failure returns a storage error", async (t) => {
  t.mock.method(globalThis, "fetch", async () => new Response(new ReadableStream({
    start(controller) { controller.error(new TypeError("terminated")); },
  })));
  await assert.rejects(chCommand("INSERT INTO incident_comments VALUES ()"), ClickHouseError);
});
