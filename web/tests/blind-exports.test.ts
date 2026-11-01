// Слепой разбор должен скрывать и копии вердикта: triage/verdicts сохраняет
// Markdown в комментарии agent:*, а категорию/уверенность — в console_audit.
// Исполняются настоящие API routes и серверная страница; подменено хранилище.
import { before, test } from "node:test";
import assert from "node:assert/strict";
import { installNextMocks, loadAuth } from "./_next-mock";
import { assertOpenAPIResponse } from "./_openapi-response";
import { VERDICT_OK } from "./_verdict-fixture";
import { agentCommentId, renderVerdictMarkdown, type VerdictDoc } from "../src/lib/shared/triage-verdict";
import { isBlindIncident } from "../src/lib/blind";

const auth = loadAuth();
const mocks = installNextMocks();
const id = "INC-4";
const ts = "2026-11-01 10:00:00.123";
const agent = "review-bot", session = "blind-review-session";
const agentText = "BlindAgentDecisionMustStayHidden";
const humanText = "HumanIndependentObservation";
const engineText = "BlindEngineDecisionMustStayHidden";
const markdown = renderVerdictMarkdown({ ...VERDICT_OK, incident_id: id, summary: agentText } as VerdictDoc, agent, session);
let status = "in_progress";
const incident = {
  incident_id: id, created_at: ts, updated_at: ts, rule_id: VERDICT_OK.rule_id, rule_title: "Review fixture",
  level: "high", tags: ["attack.t1110"], owner: "sso:blind-review", note: "", actor_name: "fixture-bot",
  node: "fixture-node", sources: ["fixture"], event_count: 1, first_ts: ts, last_ts: ts, pii: 0,
  chain: [], enrichment: [], similar: [],
};
const engineVerdict = {
  incident_id: id, evaluated_at: ts, profile: "high", model: "fixture", summary_ru: engineText,
  evidence: [], first_action: "", actions: [], confidence: 0.9, shown: 1, tokens: 1, latency_ms: 1, error: "",
};
const comments = [
  { comment_id: agentCommentId(session), incident_id: id, created_at: ts, author: `agent:${agent}`, body: markdown },
  { comment_id: "01234567-89ab-4cde-8fab-0123456789ab", incident_id: id, created_at: ts, author: "analyst", body: humanText },
];
const actions = [
  { ts, user: `triage:${session}`, action: "triage.verdict", target: id, detail: `вердикт true_positive (high, человек: да) от ${agent}, сессия ${session}` },
  { ts, user: "analyst", action: "incident.comment", target: id, detail: "добавлен комментарий" },
];
mocks.queries.incidentGet = async () => ({ ...incident, status });
mocks.queries.verdictGet = async () => engineVerdict;
mocks.queries.incidentComments = async () => comments;
mocks.queries.incidentFirstResponse = async () => ts;
mocks.queries.incidentStateHistory = async () => status === "closed" ? [{
  event_id: "12345678-9abc-4def-8abc-123456789abc", revision: 1, changed_at: ts, actor: "analyst",
  kind: "status", status: "closed", owner: "analyst", reason: "Проверено человеком", disposition: "benign_authorized",
  escalate: false, severity_level: 3, severity_correct: true, attack_tactic: "discovery", attack_technique: "T1046", attack_version: "20.0",
  ops_cause: "", ops_act_now: null, ops_urgency: null, ops_action: "", blind: true, labeled_by_human: true,
}] : [];
mocks.queries.chQuery = async (sql) => sql.includes("FROM console_audit") ? actions : [];
mocks.queries.agentVerdictsFor = async () => [{
  incident_id: id, session_id: session, agent, verdict: "true_positive", confidence: 0.9,
  human_needed: 1, markdown, verdict_json: "{}", created_at: ts,
}];

/* eslint-disable @typescript-eslint/no-require-imports -- настоящие маршруты после установки Next/auth/storage mocks */
type Route = { GET: (req: Request, ctx: { params: Promise<{ id: string }> }) => Promise<Response> };
const jsonRoute = require("../src/app/api/incidents/[id]/route") as Route;
const markdownRoute = require("../src/app/api/incidents/[id]/markdown/route") as Route;
const page = require("../src/app/(console)/incidents/[id]/page") as { default: (props: { params: Promise<{ id: string }> }) => Promise<unknown> };
/* eslint-enable @typescript-eslint/no-require-imports */

const ctx = () => ({ params: Promise.resolve({ id }) });
const request = (suffix = "") => new Request(`http://x/api/incidents/${id}${suffix}`);

before(async () => {
  assert.equal(isBlindIncident(id), true, "фикстура входит в production слепую выборку");
  await auth.createSession("sso:blind-review", "analyst", true);
});

test("blind JSON: комментарий агента не раскрывает вердикт открытого инцидента", async () => {
  status = "in_progress";
  const response = await jsonRoute.GET(request(), ctx());
  assert.equal(response.status, 200);
  const body = await assertOpenAPIResponse("/api/incidents/{id}", response);
  assert.equal(body.verdict, null);
  assert.equal(body.verdict_hidden, true);
  assert.ok(JSON.stringify(body.comments).includes(humanText), "независимые комментарии людей остаются доступны");
  assert.ok(!JSON.stringify(body.comments).includes(agentText), "копия Markdown вердикта в agent:* тоже должна быть скрыта");
});

test("blind JSON: аудит triage.verdict не раскрывает категорию решения агента", async () => {
  status = "in_progress";
  const response = await jsonRoute.GET(request(), ctx());
  assert.equal(response.status, 200);
  const body = await assertOpenAPIResponse("/api/incidents/{id}", response);
  assert.ok(JSON.stringify(body.actions).includes("incident.comment"), "обычный аудит сохраняется");
  assert.ok(!JSON.stringify(body.actions).includes("true_positive"), "скрытый вердикт не должен читаться в detail журнала действий");
});

test("blind Markdown: agent-комментарий не раскрывает вердикт до завершения", async () => {
  status = "in_progress";
  const response = await markdownRoute.GET(request("/markdown"), ctx());
  assert.equal(response.status, 200);
  const text = await response.text();
  assert.ok(text.includes(humanText));
  assert.ok(!text.includes(engineText), "отдельная секция анализа модели уже скрыта");
  assert.ok(!text.includes(agentText), "раздел комментариев не должен обходить blind");
});

function wikiMarkdown(node: unknown): string[] {
  if (Array.isArray(node)) return node.flatMap(wikiMarkdown);
  if (node && typeof node === "object" && "props" in node) {
    const props = (node as { props: Record<string, unknown> }).props;
    return [...(props.id === id && typeof props.markdown === "string" ? [props.markdown] : []), ...wikiMarkdown(props.children)];
  }
  return [];
}

test("blind UI: в props клиентского досье нет Markdown вердикта агента", async () => {
  status = "in_progress";
  const docs = wikiMarkdown(await page.default(ctx()));
  assert.equal(docs.length, 1, "проверяется реальное досье, переданное серверной страницей в IncidentWiki");
  assert.ok(docs[0].includes(humanText));
  assert.ok(!docs[0].includes(engineText));
  assert.ok(!docs[0].includes(agentText), "скрытый текст нельзя отправлять в клиентские props");
});

test("после завершения JSON и Markdown раскрывают подсказки вместе с человеческими записями", async () => {
  status = "closed";
  const json = await jsonRoute.GET(request(), ctx());
  assert.equal(json.status, 200);
  const body = await assertOpenAPIResponse("/api/incidents/{id}", json);
  assert.ok(JSON.stringify(body.verdict).includes(engineText));
  assert.ok(JSON.stringify(body.comments).includes(agentText));
  assert.ok(JSON.stringify(body.comments).includes(humanText));
  const md = await markdownRoute.GET(request("/markdown"), ctx());
  assert.equal(md.status, 200);
  const text = await md.text();
  assert.ok(text.includes(engineText) && text.includes(agentText) && text.includes(humanText));
});
