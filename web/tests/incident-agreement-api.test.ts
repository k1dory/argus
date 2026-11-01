// GET /api/incidents/agreement: настоящий маршрут и agreementMetrics, подменён только
// HTTP-транспорт ClickHouse. Наблюдатель — 403, аналитик и токен API — 200 по схеме
// OpenAPI, неизвестное окно — 400, отказ хранилища — 503.
import { beforeEach, test } from "node:test";
import assert from "node:assert/strict";
import { installNextMocks, loadAuth } from "./_next-mock";
import { assertOpenAPIResponse } from "./_openapi-response";
import type { Session } from "../src/lib/auth";

process.env.CLICKHOUSE_URL = "http://127.0.0.1:9";
const API = "agreement-api-" + "b".repeat(40);
installNextMocks();
const auth = loadAuth();
process.env.ARGUS_API_TOKEN = API;
/* eslint-disable @typescript-eslint/no-require-imports -- маршрут после подмен Next/auth */
const route = require("../src/app/api/incidents/agreement/route") as { GET: (req: Request) => Promise<Response> };
const { agreementApiForbidden } = require("../src/lib/blind-metrics") as typeof import("../src/lib/blind-metrics");
/* eslint-enable @typescript-eslint/no-require-imports */

const rows = [
  { rule_id: "ssh-brute", rule_title: "Перебор SSH", blind: true, labeled: "4", fp: "1", compared: "3", agreed: "2", undetermined: "1", no_verdict: "0" },
  { rule_id: "ssh-brute", rule_title: "Перебор SSH", blind: false, labeled: "6", fp: "2", compared: "5", agreed: "5", undetermined: "0", no_verdict: "1" },
];
let seq = 0;
const request = (query = "", headers: Record<string, string> = {}) => new Request(`http://x/api/incidents/agreement${query}`, { headers });

beforeEach(() => { seq++; });

test("agreement API: наблюдателю — 403, ClickHouse не спрашивается", async (t) => {
  const fetch = t.mock.method(globalThis, "fetch", async () => new Response(""));
  await auth.createSession(`sso:agreement-viewer-${seq}`, "viewer", true);
  const res = await route.GET(request());
  assert.equal(res.status, 403);
  await assertOpenAPIResponse("/api/incidents/agreement", res);
  assert.equal(fetch.mock.callCount(), 0);
});

test("agreement API: аналитику — метрики по правилам по схеме OpenAPI, окно в запросе", async (t) => {
  const seen: URLSearchParams[] = [];
  t.mock.method(globalThis, "fetch", async (input: URL | string | Request) => {
    seen.push(new URL(input instanceof Request ? input.url : String(input)).searchParams);
    return new Response(rows.map((r) => JSON.stringify(r)).join("\n") + "\n");
  });
  await auth.createSession(`sso:agreement-analyst-${seq}`, "analyst", true);
  const res = await route.GET(request("?window=7d"));
  assert.equal(res.status, 200);
  const body = await assertOpenAPIResponse("/api/incidents/agreement", res) as { window: string; from: string; to: string; rules: { rule_id: string; labeled: number; blind: { agreement: { k: number; n: number } } }[] };
  assert.equal(body.window, "7d");
  assert.deepEqual(body.rules.map((r) => [r.rule_id, r.labeled, r.blind.agreement.k, r.blind.agreement.n]), [["ssh-brute", 10, 2, 3]]);
  const days = (Date.parse(body.to.replace(" ", "T") + "Z") - Date.parse(body.from.replace(" ", "T") + "Z")) / 86_400_000;
  assert.ok(Math.abs(days - 7) < 0.001, `окно 7 дней: ${days}`);
  assert.equal(seen[0].get("param_from"), body.from);
});

test("agreement API: токен API — 200; неизвестное окно — 400; отказ хранилища — 503", async (t) => {
  const bearer = { authorization: `Bearer ${API}` };
  t.mock.method(globalThis, "fetch", async () => new Response(""));
  const ok = await route.GET(request("", bearer));
  assert.equal(ok.status, 200);
  const empty = await assertOpenAPIResponse("/api/incidents/agreement", ok) as { window: string; rules: unknown[]; total: { labeled: number } };
  assert.deepEqual([empty.window, empty.rules.length, empty.total.labeled], ["30d", 0, 0]);
  const bad = await route.GET(request("?window=90d", bearer));
  assert.equal(bad.status, 400);
  await assertOpenAPIResponse("/api/incidents/agreement", bad);
  t.mock.method(console, "error", () => undefined);
  t.mock.method(globalThis, "fetch", async () => { throw new TypeError("fixture: connection refused"); });
  const down = await route.GET(request("", bearer));
  assert.equal(down.status, 503);
  assert.deepEqual(await assertOpenAPIResponse("/api/incidents/agreement", down), { error: "хранилище недоступно" });
});

test("agreement API: сессия разбора и issuer не допущены даже после apiGuard", () => {
  const base = { user: "x", role: "admin" as const, sso: false, mustChangePassword: false };
  for (const kind of ["triage-session", "issuer"] as const) {
    const res = agreementApiForbidden({ ...base, kind } as Session);
    assert.equal(res?.status, 403, kind);
  }
  assert.equal(agreementApiForbidden({ ...base, kind: "console", role: "analyst" } as Session), null);
  assert.equal(agreementApiForbidden({ ...base, kind: "api-token" } as Session), null);
});
