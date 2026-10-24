import { test } from "node:test";
import assert from "node:assert/strict";
import fs from "node:fs";
import { decodeJwt } from "jose";
import { installNextMocks, loadAuth } from "./_next-mock";

const mocks = installNextMocks();
const auth = loadAuth();

test("стартовый пароль admin — в файле 0600 рядом с auth.json, не в логе", async () => {
  const logs: string[] = [];
  const orig = console.log;
  console.log = (...a: unknown[]) => void logs.push(a.join(" "));
  try {
    await auth.getAuthState();
  } finally {
    console.log = orig;
  }
  const pwd = fs.readFileSync(auth.ADMIN_PASSWORD_FILE, "utf8").trim();
  assert.match(pwd, /^.{16}$/);
  assert.equal(fs.statSync(auth.ADMIN_PASSWORD_FILE).mode & 0o777, 0o600);
  assert.ok(logs.some((l) => l.includes("admin-password.txt")), "в логе — путь к файлу");
  assert.ok(!logs.some((l) => l.includes(pwd)), "самого пароля в логе нет");
  assert.equal(await auth.verifyCredentials("admin", pwd), "admin");
});

test("tokenVersion: смена пароля отзывает сессию пользователя, чужие — нет", async () => {
  const bob = await auth.createUser("bob", "analyst");
  const kate = await auth.createUser("kate", "viewer");
  assert.ok("password" in bob && "password" in kate);
  await auth.createSession("bob", "analyst");
  const bobToken = mocks.jar.get("wazuh_console_session")!;
  await auth.createSession("kate", "viewer");
  const kateToken = mocks.jar.get("wazuh_console_session")!;
  assert.equal((await auth.verifySessionToken(bobToken))?.user, "bob");

  assert.equal(await auth.changePassword("bob", (bob as { password: string }).password, "NewPassw0rd."), null);
  assert.equal(await auth.verifySessionToken(bobToken), null, "старый JWT bob отозван");
  assert.equal((await auth.verifySessionToken(kateToken))?.user, "kate", "сессия kate живёт");
  assert.equal(await auth.verifyCredentials("bob", "NewPassw0rd."), "analyst");
  // Новая сессия bob после смены пароля работает.
  await auth.createSession("bob", "analyst");
  assert.equal((await auth.getSession())?.user, "bob");
});

test("сброс пароля админом тоже отзывает сессии; себе и встроенному — нельзя", async () => {
  await auth.createSession("kate", "viewer");
  const token = mocks.jar.get("wazuh_console_session")!;
  const r = await auth.resetUserPassword("kate", "admin");
  assert.ok("password" in r);
  assert.equal(await auth.verifySessionToken(token), null);
  assert.equal(await auth.verifyCredentials("kate", (r as { password: string }).password), "viewer");
  assert.match((await auth.resetUserPassword("kate", "kate") as { error: string }).error, /Свой пароль/);
  assert.match((await auth.resetUserPassword("admin", "bob") as { error: string }).error, /встроенного/);
});

test("mustChangePassword: admin со стартовым паролем блокирует действия до смены", async () => {
  await auth.createSession("admin", "admin");
  const s = await auth.getSession();
  assert.equal(s?.mustChangePassword, true);
  const a = await auth.authorize("viewer");
  assert.equal(a.ok, false);
  assert.match((a as { error: string }).error, /смените/i);
  await assert.rejects(auth.requireRole("viewer"), (e: Error & { digest?: string }) => e.digest === "FORBIDDEN");
  // API тоже не пускает такую сессию
  assert.equal(await auth.apiSession(new Request("http://x/api/sources")), null);

  const pwd = fs.readFileSync(auth.ADMIN_PASSWORD_FILE, "utf8").trim();
  assert.equal(await auth.changePassword("admin", pwd, "AdminPassw0rd."), null);
  assert.ok(!fs.existsSync(auth.ADMIN_PASSWORD_FILE), "файл со стартовым паролем удалён");
  await auth.createSession("admin", "admin");
  assert.equal((await auth.getSession())?.mustChangePassword, false);
  assert.equal((await auth.authorize("admin")).ok, true);
});

test("SSO: имя изолировано префиксом sso:, TTL сессии 1 ч, локальная — 12 ч", async () => {
  await assert.rejects(auth.signSessionToken("admin", "admin", true), /sso:/);
  const t = await auth.signSessionToken("sso:admin", "admin", true);
  const p = decodeJwt(t);
  assert.equal(p.exp! - p.iat!, 3600);
  const s = await auth.verifySessionToken(t);
  assert.deepEqual(s, { kind: "console", user: "sso:admin", role: "admin", sso: true, mustChangePassword: false });
  // sso:admin — не встроенный admin: локальный пароль/2FA у него не существуют
  assert.equal(await auth.verifyCredentials("sso:admin", "AdminPassw0rd."), null);
  assert.match((await auth.createUser("sso:x", "viewer") as { error: string }).error, /Имя/);
  // Локальный JWT для имени с префиксом не выдаётся, а sso-токен без флага sso не принимается
  await assert.rejects(auth.signSessionToken("sso:admin", "admin", false));
  const local = await auth.signSessionToken("bob", "analyst", false);
  const lp = decodeJwt(local);
  assert.equal(lp.exp! - lp.iat!, 12 * 3600);
  assert.equal(lp.sso, false);
});

test("сессия удалённого пользователя перестаёт действовать сразу", async () => {
  await auth.createSession("kate", "viewer");
  assert.equal((await auth.getSession())?.user, "kate");
  assert.equal(await auth.deleteUser("kate", "admin"), null);
  assert.equal(await auth.getSession(), null);
});
