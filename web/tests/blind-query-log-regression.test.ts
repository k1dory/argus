// PR #13: фильтрация после запроса не защищает от логирования частичного ответа.
// ClickHouse может прислать JSONEachRow, затем Code: ... при HTTP 200.
import { beforeEach, test } from "node:test";
import assert from "node:assert/strict";
import { installNextMocks, loadAuth } from "./_next-mock";
import { hideVerdicts } from "../src/lib/blind";

process.env.CLICKHOUSE_URL = "http://127.0.0.1:9";
process.env.CLICKHOUSE_USER = "fixture-console";
process.env.CLICKHOUSE_PASSWORD = "fixture-only-password";
/* eslint-disable @typescript-eslint/no-require-imports -- настоящий запрос сохраняется до Next/storage delegates */
const realQueries = require("../src/lib/argus-queries") as typeof import("../src/lib/argus-queries");
const mocks = installNextMocks();
const auth = loadAuth();
type Route = { GET: (req: Request, ctx: { params: Promise<{ id: string }> }) => Promise<Response> };
const routes: [string, Route][] = [
  ["JSON", require("../src/app/api/incidents/[id]/route") as Route],
  ["Markdown", require("../src/app/api/incidents/[id]/markdown/route") as Route],
];
/* eslint-enable @typescript-eslint/no-require-imports */

const id = "INC-4";
const ts = "2026-11-01 10:00:00.123";
const marker = "HiddenAgentDecisionInClickHousePartialResponse";
const humanText = "IndependentObservationInClickHouseResponse";
const comments = [
  { comment_id: "12345678-9abc-4def-8abc-123456789abc", incident_id: id, created_at: ts, author: "agent:fixture-bot", body: marker },
  { comment_id: "12345678-9abc-4def-8abc-123456789abd", incident_id: id, created_at: ts, author: "analyst", body: humanText },
];
let serial = 0;

beforeEach(async () => {
  mocks.queries.incidentGet = async () => ({
    incident_id: id, status: "in_progress", rule_id: "fixture-rule", rule_title: "Fixture", level: "high",
    owner: "analyst", created_at: ts, note: "",
  });
  mocks.queries.incidentComments = realQueries.incidentComments;
  await auth.createSession(`sso:blind-query-log-${++serial}`, "analyst", true);
  assert.equal(hideVerdicts({ incident_id: id, status: "in_progress" }), true);
});

for (const [name, route] of routes) {
  test(`blind: ошибка чтения комментариев для ${name} не пишет вердикт в console.error`, async (t) => {
    let failAfterRow = false;
    const logs: string[] = [];
    t.mock.method(console, "error", (...args: unknown[]) => { logs.push(args.map(String).join(" ")); });
    t.mock.method(globalThis, "fetch", async (_input: unknown, init?: RequestInit) => {
      assert.match(String(init?.body), /FROM incident_comments/);
      const body = failAfterRow
        ? JSON.stringify(comments[0]) + "\nCode: 241. DB::Exception: Memory limit exceeded\n"
        : comments.map((row) => JSON.stringify(row)).join("\n") + "\n";
      return new Response(body, { status: 200 });
    });
    const get = () => route.GET(new Request(`http://x/api/incidents/${id}${name === "Markdown" ? "/markdown" : ""}`), {
      params: Promise.resolve({ id }),
    });

    const control = await get();
    assert.equal(control.status, 200);
    const controlText = await control.text();
    assert.ok(controlText.includes(humanText));
    assert.ok(!controlText.includes(marker), "в успешной выгрузке blind уже применяется");
    assert.deepEqual(logs, []);

    failAfterRow = true;
    const response = await get();
    assert.equal(response.status, 503, "ошибка хранилища не выдаётся за успешную выгрузку");
    assert.ok(!(await response.text()).includes(marker));
    assert.ok(!logs.join("\n").includes(marker), "сырые строки до исключения содержат скрытый вердикт и не должны логироваться");
  });
}
