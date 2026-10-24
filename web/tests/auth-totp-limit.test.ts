/* eslint-disable @typescript-eslint/no-require-imports -- моки кладутся в кэш CJS до загрузки модулей, статический import не подходит */
import { test } from "node:test";
import assert from "node:assert/strict";
import { installNextMocks, loadAuth } from "./_next-mock";

const auth = loadAuth();
const MIN = 60_000;

test("TOTP: 5 неудач подряд → блок 15 мин, следующий блок вдвое длиннее, успех сбрасывает", () => {
  const user = "limit-" + Date.now();
  let now = 1_000_000;
  for (let i = 0; i < 4; i++) {
    auth.recordTotpFailure(user, now);
    assert.equal(auth.totpLockRemainingMs(user, now), 0, `после ${i + 1} неудач блока нет`);
  }
  auth.recordTotpFailure(user, now);
  assert.equal(auth.totpLockRemainingMs(user, now), 15 * MIN, "пятая неудача — блок 15 мин");
  assert.equal(auth.totpLockRemainingMs(user, now + 14 * MIN), 1 * MIN);
  assert.equal(auth.totpLockRemainingMs(user, now + 15 * MIN), 0, "по истечении — снято");

  // Второй раунд после снятия: блок 30 мин (экспоненциально)
  now += 16 * MIN;
  for (let i = 0; i < 5; i++) auth.recordTotpFailure(user, now);
  assert.equal(auth.totpLockRemainingMs(user, now), 30 * MIN);
  now += 31 * MIN;
  for (let i = 0; i < 5; i++) auth.recordTotpFailure(user, now);
  assert.equal(auth.totpLockRemainingMs(user, now), 60 * MIN);

  auth.clearTotpFailures(user);
  assert.equal(auth.totpLockRemainingMs(user, now), 0);
  for (let i = 0; i < 5; i++) auth.recordTotpFailure(user, now);
  assert.equal(auth.totpLockRemainingMs(user, now), 15 * MIN, "после сброса — снова с 15 мин");
});

test("TOTP-лимит — по имени пользователя, соседа не задевает", () => {
  const now = 5_000_000;
  for (let i = 0; i < 5; i++) auth.recordTotpFailure("alice", now);
  assert.ok(auth.totpLockRemainingMs("alice", now) > 0);
  assert.equal(auth.totpLockRemainingMs("bob", now), 0);
});

test("verifyLoginTotp: заблокированный пользователь получает locked даже с верным кодом-заглушкой", async () => {
  const r = await auth.createUser("lockme", "viewer");
  assert.ok("password" in r);
  const b = await auth.beginTotpEnrollment("lockme");
  assert.ok("secret" in b);
  // Подтверждаем секрет напрямую через состояние: код считаем по RFC 6238
  const code = currentCode(b.secret);
  assert.equal(await auth.confirmTotpEnrollment("lockme", code), null);
  const mocks = installNextMocks();
  mocks.audit.length = 0;
  // Все пять неудач — «invalid» (пятая включает блок), и только шестая попытка — «locked»
  for (let i = 0; i < 5; i++) assert.equal(await auth.verifyLoginTotp("lockme", "000000"), "invalid", `попытка ${i + 1}`);
  assert.equal(await auth.verifyLoginTotp("lockme", code), "locked");
  const lock = mocks.audit.filter((e) => e.action === "session.totp.lock");
  assert.equal(lock.length, 1, "первый блок — одна запись в журнале");
  assert.equal(lock[0].user, "lockme");
  assert.match(lock[0].detail, /5 неверных кодов подряд · блок 15 мин/);
});

test("TOTP: счётчик блоков затухает — после паузы больше двух длин последнего блока снова 15 мин", () => {
  const user = "decay-" + Date.now();
  let now = 9_000_000;
  for (let i = 0; i < 5; i++) auth.recordTotpFailure(user, now);
  assert.equal(auth.totpLockRemainingMs(user, now), 15 * MIN);
  now += 16 * MIN;
  for (let i = 0; i < 5; i++) auth.recordTotpFailure(user, now);
  assert.equal(auth.totpLockRemainingMs(user, now), 30 * MIN, "второй блок — 30 мин");
  // Конец блока + 2×30 мин ровно — ещё не затухло (строго больше)
  now += 30 * MIN + 60 * MIN;
  for (let i = 0; i < 4; i++) auth.recordTotpFailure(user, now);
  const r = auth.recordTotpFailure(user, now);
  assert.deepEqual(r, { locked: true, locks: 3, lockMs: 60 * MIN });
  // Конец 60-минутного блока + 2×60 мин + 1 мс — история забыта: блок снова 15 мин, №1
  now += 60 * MIN + 120 * MIN + 1;
  for (let i = 0; i < 4; i++) assert.equal(auth.recordTotpFailure(user, now).locked, false);
  assert.deepEqual(auth.recordTotpFailure(user, now), { locked: true, locks: 1, lockMs: 15 * MIN });
  assert.equal(auth.totpLockRemainingMs(user, now), 15 * MIN);
});

test("recordTotpFailure: locked=true только на неудаче, включившей блок; повторный блок — locks=2", () => {
  const user = "flag-" + Date.now();
  const now = 1;
  for (let i = 0; i < 4; i++) assert.deepEqual(auth.recordTotpFailure(user, now), { locked: false, locks: 0, lockMs: 0 });
  assert.deepEqual(auth.recordTotpFailure(user, now), { locked: true, locks: 1, lockMs: 15 * MIN });
  for (let i = 0; i < 4; i++) assert.equal(auth.recordTotpFailure(user, now).locked, false);
  assert.deepEqual(auth.recordTotpFailure(user, now), { locked: true, locks: 2, lockMs: 30 * MIN });
});

function currentCode(secret: string): string {
  const crypto = require("node:crypto") as typeof import("node:crypto");
  const A = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";
  let bits = 0, v = 0; const out: number[] = [];
  for (const c of secret) { v = (v << 5) | A.indexOf(c); bits += 5; if (bits >= 8) { out.push((v >>> (bits - 8)) & 255); bits -= 8; } }
  const c = Math.floor(Date.now() / 30000);
  const m = Buffer.alloc(8); m.writeBigUInt64BE(BigInt(c));
  const mac = crypto.createHmac("sha1", Buffer.from(out)).update(m).digest();
  const o = mac[19] & 15;
  return String((((mac[o] & 127) << 24) | (mac[o + 1] << 16) | (mac[o + 2] << 8) | mac[o + 3]) % 1e6).padStart(6, "0");
}
