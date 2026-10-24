/* eslint-disable @typescript-eslint/no-require-imports -- моки Next ставятся до загрузки auth/actions */
import { before, test } from "node:test";
import assert from "node:assert/strict";
import crypto from "node:crypto";
import { formData, installNextMocks, isRedirect, loadAuth, type AuthModule } from "./_next-mock";

const mocks = installNextMocks();
let auth: AuthModule;
let actions: typeof import("../src/lib/actions");
let password: string;

function currentCode(secret: string): string {
  const alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";
  let bits = 0, value = 0;
  const bytes: number[] = [];
  for (const char of secret) {
    value = (value << 5) | alphabet.indexOf(char);
    bits += 5;
    if (bits >= 8) { bytes.push((value >>> (bits - 8)) & 255); bits -= 8; }
  }
  const counter = Buffer.alloc(8);
  counter.writeBigUInt64BE(BigInt(Math.floor(Date.now() / 30000)));
  const mac = crypto.createHmac("sha1", Buffer.from(bytes)).update(counter).digest();
  const offset = mac[19] & 15;
  return String(((((mac[offset] & 127) << 24) | (mac[offset + 1] << 16) | (mac[offset + 2] << 8) | mac[offset + 3]) % 1e6)).padStart(6, "0");
}

before(async () => {
  auth = loadAuth();
  actions = require("../src/lib/actions") as typeof import("../src/lib/actions");
  const created = await auth.createUser("analyst2fa", "analyst");
  assert.ok("password" in created);
  password = created.password;
});

test("неверный пароль не раскрывает наличие 2FA и не создаёт challenge", async () => {
  mocks.jar.clear();
  const result = await actions.loginAction({ error: null }, formData({ user: "analyst2fa", password: "wrong" }));
  assert.match(result.error ?? "", /Неверный логин или пароль/);
  assert.equal(result.requiresTotp, undefined);
  assert.equal(await auth.pendingLoginTotp(), null);
});

test("без 2FA верный пароль сразу даёт сессию", async () => {
  mocks.jar.clear();
  await assert.rejects(actions.loginAction({ error: null }, formData({ user: "analyst2fa", password })), isRedirect);
  assert.equal((await auth.getSession())?.user, "analyst2fa");
});

test("с 2FA пароль открывает только второй шаг; код завершает вход", async () => {
  const enrollment = await auth.beginTotpEnrollment("analyst2fa");
  assert.ok("secret" in enrollment);
  const secret = enrollment.secret;
  assert.equal(await auth.confirmTotpEnrollment("analyst2fa", currentCode(secret)), null);
  mocks.jar.clear();
  const first = await actions.loginAction({ error: null }, formData({ user: "analyst2fa", password }));
  assert.equal(first.error, null);
  assert.equal(first.requiresTotp, true);
  assert.equal(first.totpUser, "analyst2fa");
  assert.equal(await auth.getSession(), null);
  const challengeToken = mocks.jar.get("wazuh_console_login_totp");
  assert.ok(challengeToken);
  assert.equal(await auth.verifySessionToken(challengeToken), null, "2FA challenge не является сессией");

  const wrong = await actions.loginAction(first, formData({ step: "totp", totp: "invalid" }));
  assert.equal(wrong.requiresTotp, true);
  assert.match(wrong.error ?? "", /Неверный код/);
  assert.equal(await auth.getSession(), null);

  await assert.rejects(actions.loginAction(wrong, formData({ step: "totp", totp: currentCode(secret) })), isRedirect);
  assert.equal((await auth.getSession())?.user, "analyst2fa");
  assert.equal(await auth.pendingLoginTotp(), null);
});

test("второй шаг без challenge требует повторить пароль", async () => {
  mocks.jar.clear();
  const result = await actions.loginAction({ error: null, requiresTotp: true }, formData({ step: "totp", totp: "123456" }));
  assert.match(result.error ?? "", /истекла/);
  assert.equal(result.requiresTotp, undefined);
  assert.equal(await auth.getSession(), null);
});

test("завершение второго шага удаляет cookie именно с пути /login", async () => {
  mocks.responseHeaders.delete("set-cookie");
  await auth.clearLoginTotp();
  const header = mocks.responseHeaders.get("set-cookie") ?? "";
  assert.match(header, /Path=\/login(?:;|$)/i);
  assert.match(header, /Expires=Thu, 01 Jan 1970 00:00:00 GMT/i);
});
