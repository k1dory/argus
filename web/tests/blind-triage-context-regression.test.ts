// PR #13: один и тот же triage-token не должен обходить blind сменой API route.
import { beforeEach, test } from "node:test";
import assert from "node:assert/strict";
import { installNextMocks, loadAuth } from "./_next-mock";
import { hideVerdicts } from "../src/lib/blind";

const mocks = installNextMocks();
const auth = loadAuth();
/* eslint-disable @typescript-eslint/no-require-imports -- реальные routes и проверка подписанного JWT */
const contextRoute = require("../src/app/api/triage/context/route") as { GET: (req: Request) => Promise<Response> };
const incidentRoute = require("../src/app/api/incidents/[id]/route") as {
  GET: (req: Request, ctx: { params: Promise<{ id: string }> }) => Promise<Response>;
};
/* eslint-enable @typescript-eslint/no-require-imports */

const id = "INC-4";
const ts = "2026-11-01 10:00:00.123";
const engineText = "HiddenEngineDecisionFromTriageContext";
const agentText = "HiddenAgentDecisionFromTriageContext";
const humanText = "IndependentHumanObservationFromTriageContext";
let status = "in_progress";
let token = "";

beforeEach(async () => {
  status = "in_progress";
  mocks.queries.incidentGet = async () => ({
    incident_id: id, status, rule_id: "fixture-rule", rule_title: "Fixture", level: "high", tags: [],
    created_at: ts, updated_at: ts, first_ts: ts, last_ts: ts, owner: "analyst", note: "",
    actor_name: "fixture-bot", node: "fixture-node", sources: [], event_count: 1, pii: 0,
    chain: [], enrichment: [], similar: [],
  });
  mocks.queries.verdictGet = async () => ({ incident_id: id, summary_ru: engineText, shown: 1, confidence: 0.9 });
  mocks.queries.incidentComments = async () => [
    { comment_id: "fixture-agent", incident_id: id, created_at: ts, author: "agent:fixture-bot", body: agentText },
    { comment_id: "fixture-human", incident_id: id, created_at: ts, author: "analyst", body: humanText },
  ];
  ({ token } = await auth.signTriageToken({
    incidentId: id, related: {}, entities: [{ kind: "actor", value: "fixture-bot" }],
    bind: { actors: ["fixture-bot"], nodes: ["fixture-node"] },
    searchFrom: "2026-10-01 00:00:00", ttlSec: 600,
  }));
});

const request = (path: string) => new Request(`http://x${path}`, { headers: { authorization: `Bearer ${token}` } });

test("blind: /api/triage/context скрывает вердикт и agent-комментарии как /api/incidents/{id}", async () => {
  assert.equal(hideVerdicts({ incident_id: id, status }), true);
  const card = await incidentRoute.GET(request(`/api/incidents/${id}`), { params: Promise.resolve({ id }) });
  assert.equal(card.status, 200, "тот же токен действительно имеет доступ к инциденту");
  const cardText = await card.text();
  assert.ok(cardText.includes(humanText));
  assert.ok(!cardText.includes(engineText) && !cardText.includes(agentText), "карточка — положительный контроль blind");

  const response = await contextRoute.GET(request("/api/triage/context"));
  assert.equal(response.status, 200);
  const body = await response.json();
  assert.ok(JSON.stringify(body).includes(humanText));
  assert.ok(!JSON.stringify(body).includes(engineText), "соседний API не должен раскрывать анализ движка");
  assert.ok(!JSON.stringify(body).includes(agentText), "копия вердикта в comments тоже должна быть скрыта");
});

test("blind: контекст завершённого инцидента сохраняет анализ и комментарии", async () => {
  status = "closed";
  const response = await contextRoute.GET(request("/api/triage/context"));
  assert.equal(response.status, 200);
  const text = await response.text();
  for (const marker of [engineText, agentText, humanText]) assert.ok(text.includes(marker));
});
