/* eslint-disable @typescript-eslint/no-require-imports -- моки кладутся в кэш CJS до загрузки модулей, статический import не подходит */
import { test } from "node:test";
import assert from "node:assert/strict";
import fs from "node:fs";
import { formData, installNextMocks, loadAuth } from "./_next-mock";

// Первый запуск: auth.json создан консолью, стартовый пароль не сменён —
// до смены заблокированы все действия, включая настройку и отключение 2FA.
installNextMocks();
const auth = loadAuth();
const actions = require("../src/lib/actions") as typeof import("../src/lib/actions");

test("до смены стартового пароля begin/confirm/disable TOTP отвечают «смените пароль»", async () => {
  await auth.getAuthState();
  const pwd = fs.readFileSync(auth.ADMIN_PASSWORD_FILE, "utf8").trim();
  assert.equal(await auth.verifyCredentials("admin", pwd), "admin");
  await auth.createSession("admin", "admin");
  assert.equal((await auth.getSession())?.mustChangePassword, true);
  const MSG = /Сначала смените стартовый пароль/;
  assert.match((await actions.beginTotpAction({ error: null }, new FormData())).error ?? "", MSG);
  assert.match((await actions.confirmTotpAction({ error: null }, formData({ code: "000000" }))).error ?? "", MSG);
  assert.match((await actions.disableTotpAction({ error: null }, formData({ password: pwd, code: "000000" }))).error ?? "", MSG);
  const state = await auth.getAuthState();
  assert.equal(state.totpPendingSecret ?? null, null, "секрет не создан");
  assert.equal(await auth.isTotpEnabled("admin"), false);

  // После смены пароля — путь открыт (confirm без pending-секрета даёт свою ошибку, не «смените пароль»)
  assert.equal(await auth.changePassword("admin", pwd, "AdminPassw0rd."), null);
  await auth.createSession("admin", "admin");
  assert.equal((await auth.getSession())?.mustChangePassword, false);
  assert.match((await actions.confirmTotpAction({ error: null }, formData({ code: "000000" }))).error ?? "", /сгенерируйте секрет/);
  assert.match((await actions.disableTotpAction({ error: null }, formData({ password: "AdminPassw0rd.", code: "000000" }))).error ?? "", /не включён/);
  assert.ok(!fs.existsSync(auth.ADMIN_PASSWORD_FILE), "файл стартового пароля удалён после смены");
});
