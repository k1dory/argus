import { test } from "node:test";
import assert from "node:assert/strict";
import { installNextMocks, loadAuth } from "./_next-mock";

const mocks = installNextMocks();
const auth = loadAuth();
const MIN = 60_000;
const setIp = (ip: string) => mocks.headers.set("x-real-ip", ip);

test("лимит логина: 10 неудач на пару адрес+имя → блок, другое имя с того же адреса — до 30 на адрес", async () => {
  const now = 1_000_000;
  setIp("198.51.100.1");
  for (let i = 0; i < 9; i++) await auth.recordLoginFailure("alice", now + i);
  assert.equal(await auth.loginThrottled("alice", now + 10), false);
  await auth.recordLoginFailure("alice", now + 10);
  assert.equal(await auth.loginThrottled("alice", now + 11), true, "десятая — блок");
  assert.equal(await auth.loginThrottled("bob", now + 11), false, "другое имя с того же адреса — не заблокировано");
  assert.equal(await auth.loginThrottled("alice", now + 5 * MIN + 11), false, "окно 5 минут прошло — снято");
  setIp("198.51.100.2");
  assert.equal(await auth.loginThrottled("alice", now + 11), false, "другой адрес — своё окно");
});

test("лимит логина: sweep каждые 100 записей убирает ключи со старыми метками, кап 50 000 ключей", { timeout: 60_000 }, async () => {
  const now = 50_000_000;
  const before = auth.loginFailureKeyCount();
  // 60 разных адресов × (ключ адрес|имя + ключ адрес) — 120 ключей за 60 записей
  for (let i = 0; i < 60; i++) {
    setIp(`10.9.${Math.floor(i / 250)}.${i % 250}`);
    await auth.recordLoginFailure("u", now);
  }
  assert.equal(auth.loginFailureKeyCount(), before + 120);
  // Спустя больше окна ещё записи: на сотой по счёту записи — sweep, старые ключи уходят
  const later = now + 6 * MIN;
  let n = 0;
  for (let i = 0; i < 60; i++) {
    setIp(`10.8.0.${i}`);
    await auth.recordLoginFailure("u", later);
    n++;
    if (auth.loginFailureKeyCount() < before + 120 + 2 * n) break;
  }
  assert.ok(n <= 100, `sweep сработал на записи №${n} (не позже сотой)`);
  assert.ok(auth.loginFailureKeyCount() <= 2 * n, "ключи с метками старше окна удалены");
});

test("лимит логина: при 50 000 ключах новые не растят карту бесконечно", { timeout: 120_000 }, async () => {
  const now = 90_000_000;
  const start = auth.loginFailureKeyCount();
  // Каждая запись создаёт два свежих ключа; 25 100 записей > кап
  for (let i = 0; i < 25_100; i++) {
    setIp(`172.20.${Math.floor(i / 256)}.${i % 256}`);
    await auth.recordLoginFailure(`n${i}`, now + i);
  }
  const count = auth.loginFailureKeyCount();
  assert.ok(count <= 50_000, `ключей ${count} — не больше капа`);
  assert.ok(count > start, "новые ключи всё же добавляются");
  // Самая старая запись вытеснена, свежая — на месте
  setIp("172.20.0.0");
  assert.equal(await auth.loginThrottled("n0", now + 30_000), false);
});
