// API и настоящий incidentLabels; подменён только HTTP-транспорт ClickHouse.
// since документирован как ISO 8601 UTC, changed_at хранит миллисекунды.
import { beforeEach, test } from "node:test";
import assert from "node:assert/strict";
import { installNextMocks, loadAuth } from "./_next-mock";
import { assertOpenAPIResponse } from "./_openapi-response";

process.env.CLICKHOUSE_URL = "http://127.0.0.1:9";
/* eslint-disable @typescript-eslint/no-require-imports -- сохраняем настоящий запрос до Next/auth delegates */
const realQueries = require("../src/lib/argus-queries") as typeof import("../src/lib/argus-queries");
const mocks = installNextMocks();
const auth = loadAuth();
mocks.queries.incidentLabels = realQueries.incidentLabels;
const route = require("../src/app/api/incidents/labels/route") as { GET: (req: Request) => Promise<Response> };
/* eslint-enable @typescript-eslint/no-require-imports */

const label = {
  event_id: "12345678-9abc-4def-8abc-123456789abc", incident_id: "INC-4", changed_at: "2026-11-01 10:00:00.123", actor: "analyst", status: "closed",
  disposition: "benign_authorized", escalate: false, severity_level: 3, severity_correct: true,
  attack_tactic: "discovery", attack_technique: "T1046", attack_version: "20.0",
  ops_cause: "", ops_act_now: null, ops_urgency: null, ops_action: "",
  blind: true, reason: "Проверено по журналу", rule_id: "fixture-rule", rule_title: "Fixture", level: "high", tags: ["attack.t1110"],
};
let seq = 0;
beforeEach(async () => {
  // У каждого случая свой настоящий бакет export (5/min), без подмены apiGuard.
  await auth.createSession(`sso:labels-review-${++seq}`, "viewer", true);
});
const request = (params: Record<string, string> = {}) => new Request(`http://x/api/incidents/labels?${new URLSearchParams(params)}`);

test("labels API: ISO 8601 UTC с миллисекундами из changed_at пригоден для since", async (t) => {
  const seen: URLSearchParams[] = [];
  t.mock.method(globalThis, "fetch", async (input: URL | string | Request) => {
    seen.push(new URL(input instanceof Request ? input.url : String(input)).searchParams);
    return new Response(JSON.stringify(label) + "\n");
  });
  const initial = await route.GET(request({ since: "2026-11-01", limit: "1" }));
  assert.equal(initial.status, 200);
  const body = await assertOpenAPIResponse("/api/incidents/labels", initial);
  assert.equal(body.truncated, true);
  const last = (body.labels as typeof label[]).at(-1)!;
  // ISO UTC, без потери точности возвращённого changed_at.
  const since = last.changed_at.replace(" ", "T") + "Z";
  const next = await route.GET(request({ since, limit: "1" }));
  assert.equal(next.status, 200, "документированное ISO-время с .sssZ не должно давать 400");
  await assertOpenAPIResponse("/api/incidents/labels", next);
  assert.equal(seen.length, 2, "оба вызова дошли до настоящего incidentLabels");
  assert.equal(Date.parse(seen[1].get("param_since")!), Date.parse(since), "точность границы не потеряна");
});

test("labels API: невозможная дата отклоняется 400", async (t) => {
  t.mock.method(globalThis, "fetch", async () => new Response(""));
  const response = await route.GET(request({ since: "2026-99-99" }));
  assert.equal(response.status, 400, "синтаксически похожая строка не является датой ISO 8601");
  await assertOpenAPIResponse("/api/incidents/labels", response);
});

test("labels API: границы limit и доступ cookie/API/issuer совпадают с OpenAPI", async (t) => {
  const limits: string[] = [];
  t.mock.method(globalThis, "fetch", async (input: URL | string | Request) => {
    limits.push(new URL(input instanceof Request ? input.url : String(input)).searchParams.get("param_limit") ?? "");
    return new Response("");
  });
  for (const limit of ["1", "50000"]) {
    const response = await route.GET(request({ limit }));
    assert.equal(response.status, 200);
    await assertOpenAPIResponse("/api/incidents/labels", response);
  }
  for (const limit of ["0", "50001", "1.5"]) {
    const response = await route.GET(request({ limit }));
    assert.equal(response.status, 400);
    await assertOpenAPIResponse("/api/incidents/labels", response);
  }
  assert.deepEqual(limits, ["1", "50000"]);
  mocks.jar.clear();
  assert.equal((await route.GET(request())).status, 401);
  process.env.ARGUS_API_TOKEN = "labels-api-review-" + "a".repeat(40);
  const api = await route.GET(new Request("http://x/api/incidents/labels", { headers: { authorization: `Bearer ${process.env.ARGUS_API_TOKEN}` } }));
  assert.equal(api.status, 200);
  await assertOpenAPIResponse("/api/incidents/labels", api);
  process.env.ARGUS_TRIAGE_ISSUER_TOKEN = "labels-issuer-review-" + "i".repeat(40);
  const issuer = await route.GET(new Request("http://x/api/incidents/labels", { headers: { authorization: `Bearer ${process.env.ARGUS_TRIAGE_ISSUER_TOKEN}` } }));
  assert.equal(issuer.status, 403);
  await assertOpenAPIResponse("/api/incidents/labels", issuer);
});
