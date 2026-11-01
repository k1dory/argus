// Multipart changes only query/param_* from the params argument. Settings and
// CLICKHOUSE_URL fields still travel in the URI and need their own size check.
import { test } from "node:test";
import assert from "node:assert/strict";

process.env.CLICKHOUSE_URL = "http://127.0.0.1:9";
process.env.CLICKHOUSE_DB = "argus";
process.env.CLICKHOUSE_USER = "pr95-fixture";
process.env.CLICKHOUSE_PASSWORD = "";

test("PR #95: multipart cannot rescue an oversized field left in the URL", async (t) => {
  let sent = 0;
  t.mock.method(globalThis, "fetch", async () => {
    sent++;
    return new Response("");
  });
  t.mock.method(console, "error", () => undefined);
  const { chQuery, ClickHouseError } = await import("../src/lib/clickhouse");
  const logComment = "漢".repeat(15_000);
  const field = new URLSearchParams({ log_comment: logComment }).toString().split("=")[1];
  assert.ok(Buffer.byteLength(logComment) < 120 * 1024, "raw value fits a form field");
  assert.ok(field.length > 128 * 1024, "actual URL field exceeds ClickHouse's hard limit");

  await assert.rejects(chQuery("SELECT 1", {}, { log_comment: logComment }),
    (e: unknown) => e instanceof ClickHouseError && /не помещается в HTTP ClickHouse/.test(e.message));
  assert.equal(sent, 0, "query cannot be sent with an oversized URL field, even as multipart");
});

test("PR #95: multipart cannot rescue a URI made oversized by fields that stay in the URL", async (t) => {
  let sent = 0;
  t.mock.method(globalThis, "fetch", async () => {
    sent++;
    return new Response("");
  });
  t.mock.method(console, "error", () => undefined);
  const { chQuery, ClickHouseError, FORM_FIELD_MAX } = await import("../src/lib/clickhouse");
  // HTTP query parameters supplied via settings remain in the base URL.
  // Each field is valid; it is their combined URI that is too large.
  const settings: Record<string, string> = Object.fromEntries(Array.from({ length: 10 }, (_, i) =>
    [`param_padding_${i}`, "x".repeat(110 * 1024)]));
  assert.ok(Object.values(settings).every((value) => value.length < FORM_FIELD_MAX));
  assert.ok(new URLSearchParams(settings).toString().length > 1024 * 1024);

  await assert.rejects(chQuery("SELECT 1", {}, settings),
    (e: unknown) => e instanceof ClickHouseError && /не помещается в HTTP ClickHouse/.test(e.message));
  assert.equal(sent, 0, "small query/form fields do not make the remaining URI valid");
});

test("PR #95: a large percent-encoded parameter is valid when its raw multipart value fits", async (t) => {
  const requests: { url: URL; init?: RequestInit }[] = [];
  t.mock.method(globalThis, "fetch", async (input: URL | string | Request, init?: RequestInit) => {
    requests.push({ url: new URL(input instanceof Request ? input.url : String(input)), init });
    return new Response("");
  });
  const { chQuery } = await import("../src/lib/clickhouse");
  const value = "漢".repeat(15_000);
  const sql = "SELECT length({v:String})";
  await chQuery(sql, { v: value });
  assert.equal(requests.length, 1);
  const { url, init } = requests[0];
  assert.equal(url.searchParams.has("param_v"), false);
  assert.ok(Buffer.byteLength(url.pathname + url.search) < 1024 * 1024);
  const form = await new Response(init?.body, { headers: init?.headers }).formData();
  assert.equal(form.get("query"), sql);
  assert.equal(form.get("param_v"), value);
});
