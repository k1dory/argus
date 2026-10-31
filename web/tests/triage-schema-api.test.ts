// GET /api/triage/schema: схема вердикта только токену сессии разбора, ETag/304,
// заголовок версии совпадает с const схемы, запросы схемы не тратят бюджет сессии.
import { test } from "node:test";
import assert from "node:assert/strict";
import { installNextMocks, loadAuth } from "./_next-mock";
import { VERDICT_SCHEMA, VERDICT_SCHEMA_ID } from "../src/lib/shared/triage-verdict";

loadAuth();
const mocks = installNextMocks();
const API = "a".repeat(40);
const ISSUER = "i".repeat(40);
process.env.ARGUS_API_TOKEN = API;
process.env.ARGUS_TRIAGE_ISSUER_TOKEN = ISSUER;
process.env.ARGUS_TRIAGE_SESSION_REQUESTS = "2"; // маленький бюджет: третий платный запрос — 429

/* eslint-disable @typescript-eslint/no-require-imports -- маршруты грузятся после моков */
type Route = { GET?: (req: Request) => Promise<Response>; POST?: (req: Request) => Promise<Response> };
const schemaRoute = require("../src/app/api/triage/schema/route") as Route;
const sessionsRoute = require("../src/app/api/triage/sessions/route") as Route;
const contextRoute = require("../src/app/api/triage/context/route") as Route;
/* eslint-enable @typescript-eslint/no-require-imports */

const INC = {
  incident_id: "INC-7", rule_id: "a41c-cicd-007", rule_title: "CI job echoed a secret", level: "high", status: "new",
  owner: "", note: "", actor_name: "project_7_bot", node: "runner-07", sources: ["gitlab.ci"], event_count: 1,
  first_ts: "2026-10-12 04:01:38.000", last_ts: "2026-10-12 04:01:38.000", created_at: "2026-10-12 04:02:00", pii: 0,
  chain: ["04:01:38 gitlab.ci runner-07 gitlab.build.success REGISTRY_TOKEN=[REDACTED]"], tags: [], enrichment: [], similar: [],
};
mocks.queries.incidentGet = async (id) => (id === "INC-7" ? { ...INC } : null);

const req = (path: string, token?: string, headers: Record<string, string> = {}) =>
  new Request(`http://x${path}`, { headers: { ...(token ? { authorization: `Bearer ${token}` } : {}), ...headers } });

async function session(): Promise<string> {
  const res = await sessionsRoute.POST!(new Request("http://x/api/triage/sessions", { method: "POST", headers: { authorization: `Bearer ${ISSUER}`, "content-type": "application/json" }, body: JSON.stringify({ incident_id: "INC-7" }) }));
  assert.equal(res.status, 201);
  return ((await res.json()) as { token: string }).token;
}

test("схема: без токена 401, общий API-токен и issuer — 403, токен сессии — 200 с ETag и версией", async () => {
  assert.equal((await schemaRoute.GET!(req("/api/triage/schema"))).status, 401);
  assert.equal((await schemaRoute.GET!(req("/api/triage/schema", API))).status, 403, "общий токен схему не получает");
  assert.equal((await schemaRoute.GET!(req("/api/triage/schema", ISSUER))).status, 403, "issuer только выпускает сессии");
  const token = await session();
  const r = await schemaRoute.GET!(req("/api/triage/schema", token));
  assert.equal(r.status, 200);
  assert.match(r.headers.get("content-type") ?? "", /^application\/schema\+json/);
  assert.equal(r.headers.get("x-argus-schema-version"), VERDICT_SCHEMA_ID);
  assert.match(r.headers.get("cache-control") ?? "", /private/);
  const etag = r.headers.get("etag");
  assert.ok(etag && /^"[0-9a-f]{32}"$/.test(etag), `ETag по содержимому: ${etag}`);
  const body = (await r.json()) as { properties: { schema: { const: string } } };
  assert.deepEqual(body, VERDICT_SCHEMA, "тело — схема как есть");
  assert.equal(body.properties.schema.const, VERDICT_SCHEMA_ID, "версия в заголовке = const поля schema");
  const again = await schemaRoute.GET!(req("/api/triage/schema", token, { "if-none-match": etag! }));
  assert.equal(again.status, 304);
  assert.equal(again.headers.get("etag"), etag);
  assert.equal(await again.text(), "");
});

test("схема не списывает бюджет сессии: после многих запросов схемы карточка доступна ровно бюджет раз", async () => {
  const token = await session();
  for (let i = 0; i < 6; i++) assert.equal((await schemaRoute.GET!(req("/api/triage/schema", token))).status, 200, `схема №${i + 1}`);
  assert.equal((await contextRoute.GET!(req("/api/triage/context", token))).status, 200, "1-й платный запрос");
  assert.equal((await contextRoute.GET!(req("/api/triage/context", token))).status, 200, "2-й платный запрос");
  const exhausted = await contextRoute.GET!(req("/api/triage/context", token));
  assert.equal(exhausted.status, 429);
  assert.equal(((await exhausted.json()) as { error: string }).error, "budget_exhausted");
  assert.equal((await schemaRoute.GET!(req("/api/triage/schema", token))).status, 200, "схема доступна и после исчерпания бюджета");
});
