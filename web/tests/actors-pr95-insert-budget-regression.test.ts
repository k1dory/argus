// The INSERT exemption leaves both URL budgets unenforced. The bulk-import
// case also existed at f4194ca: PR #95 must not be credited with fixing it.
import { test } from "node:test";
import assert from "node:assert/strict";
import { parseIdentitiesDoc } from "../src/lib/shared/actors";

process.env.CLICKHOUSE_URL = "http://127.0.0.1:9";
process.env.CLICKHOUSE_DB = "argus";
process.env.CLICKHOUSE_USER = "pr95-fixture";
process.env.CLICKHOUSE_PASSWORD = "";

for (const scenario of ["field", "uri"] as const) {
  test(`PR #95: oversized INSERT ${scenario} is rejected before fetch`, async (t) => {
    let sent = 0;
    t.mock.method(globalThis, "fetch", async () => {
      sent++;
      return new Response("");
    });
    t.mock.method(console, "error", () => undefined);
    const { chCommand, ClickHouseError } = await import("../src/lib/clickhouse");
    const params: Record<string, string> = scenario === "field"
      ? { v: "漢".repeat(15_000) }
      : Object.fromEntries(Array.from({ length: 10 }, (_, i) => [`v${i}`, "x".repeat(110 * 1024)]));
    const sql = `INSERT INTO fixture (v) VALUES ${Object.keys(params).map((key) => `({${key}:String})`).join(", ")}`;
    const url = new URL("http://127.0.0.1:9");
    for (const [key, value] of Object.entries(params)) url.searchParams.set(`param_${key}`, value);
    if (scenario === "field") assert.ok(url.search.slice(1).split("=")[1].length > 128 * 1024);
    else assert.ok(Buffer.byteLength(url.pathname + url.search) > 1024 * 1024);

    await assert.rejects(chCommand(sql, params),
      (e: unknown) => e instanceof ClickHouseError && /не помещается в HTTP ClickHouse/.test(e.message));
    assert.equal(sent, 0, "INSERT data stays in the body, but its URL still needs validation");
  });
}

test("PR #95: valid bulk identity import does not send an INSERT URI over 1 MiB", async (t) => {
  const requests: { sql: string; uriBytes: number }[] = [];
  t.mock.method(globalThis, "fetch", async (input: URL | string | Request, init?: RequestInit) => {
    const url = new URL(input instanceof Request ? input.url : String(input));
    requests.push({ sql: String(init?.body ?? ""), uriBytes: Buffer.byteLength(url.pathname + url.search) });
    return new Response("");
  });
  const parsed = parseIdentitiesDoc({ persons: { "pr95-import": {
    display: "Fixture",
    aliases: Array.from({ length: 200 }, (_, i) => ({
      kind: "uid", value: "漢".repeat(252) + String(i).padStart(4, "0"), note: "漢".repeat(500),
    })),
  } } });
  assert.equal(parsed.ok, true, "document stays within the public import limits");
  if (!parsed.ok) return;
  const { upsertIdentities } = await import("../src/lib/actors");
  assert.deepEqual(await upsertIdentities(parsed.persons, "pr95.fixture"), { persons: 1, aliases: 200 });
  assert.ok(requests.some((r) => /^INSERT INTO identities\b/.test(r.sql)));
  assert.ok(requests.some((r) => /^INSERT INTO identity_aliases\b/.test(r.sql)));
  assert.deepEqual(requests.filter((r) => r.uriBytes > 1024 * 1024).map((r) => r.uriBytes), [],
    "a fixed batch of 200 valid Unicode aliases exceeds ClickHouse's URI limit");
});

test("PR #95: large INSERT data in the body is not subject to URL/form-field limits", async (t) => {
  const requests: { url: URL; body: string; type: string | null }[] = [];
  t.mock.method(globalThis, "fetch", async (input: URL | string | Request, init?: RequestInit) => {
    requests.push({ url: new URL(input instanceof Request ? input.url : String(input)),
      body: String(init?.body ?? ""), type: new Headers(init?.headers).get("content-type") });
    return new Response("");
  });
  const { chCommand, FORM_FIELD_MAX, URI_MAX } = await import("../src/lib/clickhouse");
  const sql = `INSERT INTO fixture FORMAT JSONEachRow\n${JSON.stringify({ v: "x".repeat(URI_MAX + 1) })}`;
  assert.ok(Buffer.byteLength(sql) > FORM_FIELD_MAX && Buffer.byteLength(sql) > URI_MAX);
  await chCommand(sql);
  assert.equal(requests.length, 1);
  assert.equal(requests[0].body, sql);
  assert.equal(requests[0].type, "text/plain");
  assert.ok(Buffer.byteLength(requests[0].url.pathname + requests[0].url.search) < URI_MAX);
});
