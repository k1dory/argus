// PR #13: общий журнал не должен обходить слепой разбор карточки.
import { beforeEach, test } from "node:test";
import assert from "node:assert/strict";
import { installNextMocks, loadAuth } from "./_next-mock";
import { pageText } from "./_render";
import { hideVerdicts } from "../src/lib/blind";

const mocks = installNextMocks();
const auth = loadAuth();
/* eslint-disable @typescript-eslint/no-require-imports -- настоящая страница после Next/auth mocks */
const settings = require("../src/app/(console)/settings/page") as { default: () => Promise<unknown> };
/* eslint-enable @typescript-eslint/no-require-imports */

const id = "INC-4";
const ts = "2026-11-01 10:00:00.123";
const decision = "вердикт true_positive (high, человек: да) от fixture-bot, сессия fixture-session";
const observation = "IndependentHumanAuditEntry";
let status = "in_progress";

beforeEach(() => {
  process.env.ARGUS_INTEGRATION_WAZUH = "0";
  status = "in_progress";
  mocks.queries.incidentGet = async () => ({ incident_id: id, status });
  mocks.queries.auditTail = async () => [
    { ts, user: "triage:fixture-session", action: "triage.verdict", target: id, detail: decision },
    { ts, user: "analyst", action: "incident.comment", target: id, detail: observation },
  ];
});

for (const role of ["viewer", "analyst", "admin"] as const) {
  test(`blind: /settings не раскрывает вердикт через общий аудит роли ${role}`, async () => {
    await auth.createSession(`sso:blind-audit-${role}`, role, true);
    assert.equal(hideVerdicts({ incident_id: id, status }), true);
    const node = await settings.default();
    const text = await pageText(node);
    assert.ok(text.includes(observation), "обычные действия по инциденту остаются видны");
    assert.ok(!JSON.stringify(node).includes(decision), "решение агента не должно попасть в props дерева страницы");
    assert.ok(!text.includes(decision), "журнал настроек должен соблюдать тот же blind, что и карточка");
  });
}

test("blind: после закрытия запись вердикта в общем аудите доступна", async () => {
  status = "closed";
  await auth.createSession("sso:blind-audit-closed", "analyst", true);
  assert.equal(hideVerdicts({ incident_id: id, status }), false);
  const text = await pageText(await settings.default());
  assert.ok(text.includes(decision));
  assert.ok(text.includes(observation));
});
