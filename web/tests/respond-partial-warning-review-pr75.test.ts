/* eslint-disable @typescript-eslint/no-require-imports -- use the existing server-action harness */
import { test } from "node:test";
import assert from "node:assert/strict";
import fs from "node:fs";
import path from "node:path";
import { formData, installNextMocks, loadAuth } from "./_next-mock";

const mocks = installNextMocks();
const auth = loadAuth();
const actions = require("../src/lib/incident-actions") as typeof import("../src/lib/incident-actions");

test("PR75 review: partial executor failure must not hide the journal durability warning", async (t) => {
  t.after(() => fs.rmSync(path.dirname(mocks.authFile), { recursive: true, force: true }));
  await auth.getAuthState();
  const password = fs.readFileSync(auth.ADMIN_PASSWORD_FILE, "utf8").trim();
  assert.equal(await auth.changePassword("admin", password, "Review75.Partial!Passw0rd"), null);
  await auth.createSession("admin", "admin");
  mocks.queries.incidentGet = async () => ({
    incident_id: "INC-75", actor_name: "203.0.113.7", chain: ["attack from 203.0.113.7"],
  });

  for (const action of ["block", "unblock"] as const) {
    await t.test(action, async () => {
      const warning = "Решение оператора не сохранится после рестарта: повторите действие после восстановления журнала";
      let calls = 0;
      const respond = async () => {
        calls++;
        return {
          warning,
          results: [
            { executor: "ngfw.first", ok: true, detail: "applied" },
            { executor: "ngfw.second", ok: false, detail: "executor unavailable" },
          ],
        };
      };
      mocks.queries.requestBlockIp = respond;
      mocks.queries.requestUnblockIp = respond;
      const fd = formData({ incident_id: "INC-75", ip: "203.0.113.7", reason: "manual review" });
      const state = action === "block"
        ? await actions.blockIpAction({ error: null }, fd)
        : await actions.unblockIpAction({ error: null }, fd);
      assert.equal(calls, 1, "fixture must pass authorization, validation and strict audit");
      assert.ok(state.error?.includes("executor unavailable"), "executor failure must remain visible");
      // The clients display state.error on the failure path; the warning must
      // reach that path as well, rather than being discarded by the action.
      assert.ok(
        state.error?.includes(warning),
        `the partial failure hid the durability warning: ${JSON.stringify(state)}`,
      );
    });
  }
});
