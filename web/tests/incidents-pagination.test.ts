import { test } from "node:test";
import assert from "node:assert/strict";
import { incidentsList } from "../src/lib/argus-queries";

test("incident pagination recovers after the last page disappears", async (t) => {
  const offsets: number[] = [];
  t.mock.method(globalThis, "fetch", async (url: URL, options: RequestInit) => {
    const sql = String(options.body);
    if (sql.includes("SELECT count() AS c")) return new Response('{"c":"12"}\n');
    assert.match(sql, /ORDER BY created_at DESC, incident_id DESC/);
    assert.match(sql, /positionCaseInsensitiveUTF8/);
    assert.equal(url.searchParams.get("param_q"), "ПРОВЕРКА");
    const offset = Number(url.searchParams.get("param_offset"));
    offsets.push(offset);
    return new Response(offset === 0 ? '{"incident_id":"INC-12","event_count":"3","pii":"0"}\n' : "");
  });
  const result = await incidentsList({ page: 9, q: "ПРОВЕРКА" });
  assert.equal(result.page, 1);
  assert.equal(result.total, 12);
  assert.equal(result.rows[0].incident_id, "INC-12");
  assert.deepEqual(offsets, [400, 0]);
});

test("empty incident results reset pagination without another list request", async (t) => {
  let calls = 0;
  t.mock.method(globalThis, "fetch", async (_url: URL, options: RequestInit) => {
    calls++;
    return new Response(String(options.body).includes("SELECT count() AS c") ? '{"c":"0"}\n' : "");
  });
  const result = await incidentsList({ page: 999 });
  assert.equal(result.page, 1);
  assert.deepEqual(result.rows, []);
  assert.equal(calls, 2);
});
