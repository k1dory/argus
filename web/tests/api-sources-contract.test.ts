import { test } from "node:test";
import assert from "node:assert/strict";
import { installNextMocks, loadAuth } from "./_next-mock";
import { assertOpenAPIResponse } from "./_openapi-response";

loadAuth();
const mocks = installNextMocks();
const API = "sources-contract-" + "a".repeat(40);
process.env.ARGUS_API_TOKEN = API;

/* eslint-disable @typescript-eslint/no-require-imports -- route loads after the query delegate and auth mocks */
const route = require("../src/app/api/sources/route") as { GET: (request: Request) => Promise<Response> };
/* eslint-enable @typescript-eslint/no-require-imports */

const req = () => new Request("http://x/api/sources", { headers: { authorization: `Bearer ${API}` } });

test("GET /api/sources: serialized omitted count and known/null rhythms conform to OpenAPI", async (t) => {
  const sources = [
    { source: "host.sshd", source_class: "auth", events_1h: 120, eps_60s: 12, last_ts: "2026-10-30 12:00:00.000", pii_share: 0.25, alive: 1, events_window: 86400, rhythm_sec: 60, silence_threshold_sec: 300, silent_for_sec: 12 },
    { source: "ci.nightly", source_class: "ci", events_1h: 0, eps_60s: 0, last_ts: "2026-10-29 03:00:00", pii_share: 0, alive: 1, events_window: 30, rhythm_sec: 86400, silence_threshold_sec: 259200, silent_for_sec: 118800 },
    { source: "argus.system", source_class: "telemetry", events_1h: 0, eps_60s: 0, last_ts: "2026-10-29 10:00:00", pii_share: 0, alive: 0, events_window: 1, rhythm_sec: null, silence_threshold_sec: 300, silent_for_sec: 93600 },
  ];
  const report = t.mock.method(mocks.queries, "sourcesHealthReport", async () => ({ sources, omitted: 37 }));
  const response = await route.GET(req());
  assert.equal(response.status, 200);
  const body = await assertOpenAPIResponse("/api/sources", response);
  assert.equal(report.mock.callCount(), 1);
  assert.equal(body.omitted, 37);
  assert.deepEqual(body.sources, sources, "route must preserve the report, including null rather than zero rhythm");
  assert.equal(typeof body.checked_at, "string");
  assert.ok(Number.isFinite(Date.parse(body.checked_at as string)));
});

test("GET /api/sources: storage failure's actual 503 body conforms to its referenced schema", async (t) => {
  t.mock.method(console, "error", () => undefined);
  t.mock.method(mocks.queries, "sourcesHealthReport", async () => { throw new Error("storage fixture unavailable"); });
  const response = await route.GET(req());
  assert.equal(response.status, 503);
  const body = await assertOpenAPIResponse("/api/sources", response);
  assert.deepEqual(body, { error: "хранилище недоступно" });
});
