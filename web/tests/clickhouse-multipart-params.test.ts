// chFetch: параметры в URL, пока он короткий; больше PARAMS_IN_URL_MAX — телом
// multipart/form-data вместе с запросом; у INSERT — всегда в URL (в теле — данные).
import { test } from "node:test";
import assert from "node:assert/strict";

process.env.CLICKHOUSE_URL = "http://127.0.0.1:9";
process.env.CLICKHOUSE_DB = "argus";

test("chQuery: короткие параметры — в URL, длинные — multipart; INSERT — в URL", async (t) => {
  const seen: { url: URL; body: string; type: string }[] = [];
  t.mock.method(globalThis, "fetch", async (input: URL | string | Request, init?: RequestInit) => {
    seen.push({ url: new URL(String(input)), body: String(init?.body ?? ""), type: String(new Headers(init?.headers).get("content-type")) });
    return new Response("");
  });
  const ch = await import("../src/lib/clickhouse");
  await ch.chQuery("SELECT {v:String} AS v", { v: "короткое" });
  assert.equal(seen[0].type, "text/plain");
  assert.equal(seen[0].url.searchParams.get("param_v"), "короткое");
  assert.equal(seen[0].body, "SELECT {v:String} AS v");
  const big = "x".repeat(ch.PARAMS_IN_URL_MAX + 1);
  await ch.chQuery("SELECT length({v:String}) AS n", { v: big });
  const m = /^multipart\/form-data; boundary=(argus-[0-9a-f-]+)$/.exec(seen[1].type);
  assert.ok(m, seen[1].type);
  assert.equal(seen[1].url.searchParams.get("param_v"), null, "длинный параметр не в URL");
  assert.equal(seen[1].url.searchParams.get("wait_end_of_query"), "1", "настройки остаются в URL");
  assert.ok(seen[1].body.includes(`--${m[1]}\r\nContent-Disposition: form-data; name="query"\r\n\r\nSELECT length({v:String}) AS n\r\n`));
  assert.ok(seen[1].body.includes(`name="param_v"\r\n\r\n${big}\r\n`));
  assert.ok(seen[1].body.endsWith(`--${m[1]}--\r\n`));
  await ch.chCommand("INSERT INTO t (v) VALUES ({v:String})", { v: big });
  assert.equal(seen[2].type, "text/plain");
  assert.equal(seen[2].url.searchParams.get("param_v")?.length, big.length);
});
