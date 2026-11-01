/* eslint-disable @typescript-eslint/no-require-imports -- моки Next ставятся до загрузки server actions */
import { test } from "node:test";
import assert from "node:assert/strict";
import fs from "node:fs";
import path from "node:path";
import { formData, installNextMocks, loadAuth } from "./_next-mock";

const mocks = installNextMocks();
const auth = loadAuth();
const respond = require("../src/lib/respond-actions") as typeof import("../src/lib/respond-actions");

test("исключение адреса: только admin, срок из списка, причина, аудит строго до движка", async (t) => {
  t.after(() => fs.rmSync(path.dirname(mocks.authFile), { recursive: true, force: true }));
  await auth.getAuthState();
  const initialPassword = fs.readFileSync(auth.ADMIN_PASSWORD_FILE, "utf8").trim();
  assert.equal(await auth.changePassword("admin", initialPassword, "ExcludeUi.Passw0rd!"), null);
  assert.ok("password" in (await auth.createUser("analyst1", "analyst")));
  const calls: unknown[][] = [];
  mocks.queries.requestExcludeIp = async (...args) => { calls.push(["exclude", ...args]); return { until: "2026-11-02 10:00:00" }; };
  mocks.queries.requestRevokeExclusion = async (...args) => { calls.push(["revoke", ...args]); return {}; };

  await auth.createSession("analyst1", "analyst");
  let res = await respond.excludeIpAction(formData({ ip: "203.0.113.7", ttl: "24h", reason: "сканер партнёра" }));
  assert.ok(res.error, "аналитику исключение недоступно");
  assert.equal(calls.length, 0);

  mocks.jar.clear();
  await auth.createSession("admin", "admin");
  for (const bad of [
    { ip: "203.0.113.7", ttl: "5m", reason: "сканер партнёра" },  // срок не из списка
    { ip: "203.0.113.7", ttl: "24h", reason: "" },                // без причины
    { ip: "not-ip", ttl: "24h", reason: "сканер партнёра" },      // не адрес
  ]) {
    res = await respond.excludeIpAction(formData(bad));
    assert.ok(res.error, `отказ для ${JSON.stringify(bad)}`);
  }
  assert.equal(calls.length, 0, "неверный ввод не доходит до движка");

  const audit = mocks.queries.audit;
  mocks.queries.audit = async (_u, _a, _t, _d, opts) => { if (opts?.strict) throw new Error("журнал действий недоступен"); };
  res = await respond.excludeIpAction(formData({ ip: "203.0.113.7", ttl: "24h", reason: "сканер партнёра" }));
  mocks.queries.audit = audit;
  assert.match(res.error ?? "", /журнал действий/);
  assert.equal(calls.length, 0, "без аудита исключения нет");

  res = await respond.excludeIpAction(formData({ ip: "203.0.113.7", ttl: "168h", reason: "сканер партнёра" }));
  assert.deepEqual(res, { error: null, ok: true });
  assert.deepEqual(calls.at(-1), ["exclude", "203.0.113.7", "168h", "admin", "сканер партнёра"]);
  assert.ok(mocks.audit.some((a) => a.action === "respond.exclude_ip" && /до 2026-11-02/.test(a.detail)));

  res = await respond.revokeExclusionAction(formData({ ip: "203.0.113.7", reason: "" }));
  assert.ok(res.error, "отзыв без причины");
  res = await respond.revokeExclusionAction(formData({ ip: "203.0.113.7", reason: "окно закрыто" }));
  assert.deepEqual(res, { error: null, ok: true });
  assert.deepEqual(calls.at(-1), ["revoke", "203.0.113.7", "admin", "окно закрыто"]);

  mocks.queries.requestExcludeIp = async () => ({ error: "журнал реагирования недоступен — исключение не применено, повторите позже" });
  res = await respond.excludeIpAction(formData({ ip: "203.0.113.7", ttl: "24h", reason: "сканер партнёра" }));
  assert.match(res.error ?? "", /исключение не применено/);
});
