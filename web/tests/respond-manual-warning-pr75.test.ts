/* eslint-disable @typescript-eslint/no-require-imports -- install the existing Next mocks before loading the server action */
import { test } from "node:test";
import assert from "node:assert/strict";
import fs from "node:fs";
import path from "node:path";
import { formData, installNextMocks, loadAuth } from "./_next-mock";

const mocks = installNextMocks();
const auth = loadAuth();
const incidents = require("../src/lib/incident-actions") as typeof import("../src/lib/incident-actions");

test("PR75: a successful block with an unsaved journal decision must reach the operator as a warning", async (t) => {
  t.after(() => fs.rmSync(path.dirname(mocks.authFile), { recursive: true, force: true }));
  await auth.getAuthState();
  const initialPassword = fs.readFileSync(auth.ADMIN_PASSWORD_FILE, "utf8").trim();
  assert.equal(await auth.changePassword("admin", initialPassword, "ReviewPR75.Passw0rd!"), null);
  await auth.createSession("admin", "admin");

  mocks.queries.incidentGet = async () => ({
    incident_id: "INC-75", actor_name: "203.0.113.7", chain: ["attack from 203.0.113.7"],
  });
  const warning = "блок поставлен, но журнал реагирования недоступен: решение оператора не сохранится после рестарта движка — повторите, когда журнал вернётся";
  let engineCalls = 0;
  mocks.queries.requestBlockIp = async () => {
    engineCalls++;
    // engineRespond returns the parsed JSON unchanged on HTTP 200, including
    // the newly introduced warning field even though RespondResult omits it.
    return { warning, results: [{ executor: "ngfw.test", ok: true, detail: "blocked" }] };
  };
  const state = await incidents.blockIpAction({ error: null }, formData({
    incident_id: "INC-75", ip: "203.0.113.7", reason: "confirmed attack",
  }));
  assert.equal(engineCalls, 1, "fixture must reach the engine after successful authorization and strict audit");
  assert.ok(
    JSON.stringify(state).includes(warning),
    `the server action discarded the durability warning, leaving the client only ${JSON.stringify(state)}`,
  );
});
