/* eslint-disable @typescript-eslint/no-require-imports -- моки кладутся в кэш CJS до загрузки модулей, статический import не подходит */
import { test, before } from "node:test";
import assert from "node:assert/strict";
import fs from "node:fs";
import bcrypt from "bcryptjs";
import { SignJWT } from "jose";
import { formData, installNextMocks, isRedirect, loadAuth, type AuthModule } from "./_next-mock";

// auth.json первых версий: только встроенный admin на корне — без users[],
// tokenVersion и полей TOTP. Консоль обязана читать его как есть, а не
// пересоздавать (и не сбрасывать пароль администратора).
const mocks = installNextMocks();
const SECRET = "legacy-secret-0123456789abcdef0123456789abcdef";
const PASSWORD = "LegacyPassw0rd.";
let auth: AuthModule;
let actions: typeof import("../src/lib/actions");

before(async () => {
  fs.writeFileSync(mocks.authFile, JSON.stringify({
    user: "admin",
    passwordHash: await bcrypt.hash(PASSWORD, 4),
    sessionSecret: SECRET,
    generatedAt: "2025-01-01T00:00:00.000Z",
    passwordChanged: true,
  }), { mode: 0o600 });
  auth = loadAuth();
  actions = require("../src/lib/actions") as typeof import("../src/lib/actions");
});

test("старый auth.json читается без миграции: файл не перезаписан, пароль admin действует", async () => {
  const state = await auth.getAuthState();
  assert.equal(state.user, "admin");
  assert.equal(state.users, undefined, "users[] не дописывается при чтении");
  assert.equal(state.tokenVersion, undefined);
  assert.equal(await auth.verifyCredentials("admin", PASSWORD), "admin");
  assert.equal(await auth.verifyCredentials("admin", "wrong"), null);
  assert.equal(await auth.verifyCredentials("nobody", PASSWORD), null);
  assert.deepEqual((await auth.listUsers()).map((u) => [u.name, u.role, u.totp, u.builtin]), [["admin", "admin", false, true]]);
  assert.equal(await auth.isTotpEnabled("admin"), false);
  assert.equal(await auth.verifyLoginTotp("admin", ""), "ok", "TOTP не включён — код не нужен");
  assert.ok(!fs.existsSync(auth.ADMIN_PASSWORD_FILE), "стартовый пароль не генерируется заново");
});

test("логин через loginAction по старому файлу: сессия создаётся, mustChangePassword=false", async () => {
  mocks.jar.clear();
  await assert.rejects(actions.loginAction({ error: null }, formData({ user: "admin", password: PASSWORD })), isRedirect);
  const s = await auth.getSession();
  assert.ok(s);
  assert.equal(s.user, "admin");
  assert.equal(s.role, "admin");
  assert.equal(s.mustChangePassword, false, "passwordChanged: true из файла — смена не требуется");
  assert.ok(mocks.audit.some((e) => e.action === "session.login" && e.user === "admin"));
});

test("JWT без tv (выдан до появления tokenVersion) валиден; после смены пароля — отозван", async () => {
  const key = new TextEncoder().encode(SECRET);
  const legacyJwt = await new SignJWT({ role: "admin" }).setProtectedHeader({ alg: "HS256" }).setSubject("admin").setIssuedAt().setExpirationTime("1h").sign(key);
  const s = await auth.verifySessionToken(legacyJwt);
  assert.ok(s, "токен без tv принимается: tokenVersion по умолчанию 0");
  assert.equal(s.user, "admin");
  assert.equal(s.sso, false);

  // Чужой секрет — отказ; sso-флаг без префикса — отказ
  const forged = await new SignJWT({}).setProtectedHeader({ alg: "HS256" }).setSubject("admin").setExpirationTime("1h").sign(new TextEncoder().encode("other-secret-other-secret-other-secret"));
  assert.equal(await auth.verifySessionToken(forged), null);
  const ssoNoPrefix = await new SignJWT({ sso: true, role: "admin" }).setProtectedHeader({ alg: "HS256" }).setSubject("admin").setExpirationTime("1h").sign(key);
  assert.equal(await auth.verifySessionToken(ssoNoPrefix), null);

  // Смена пароля: tokenVersion 0 → 1, старый токен без tv больше не проходит
  assert.equal(await auth.changePassword("admin", PASSWORD, "NewPassw0rd."), null);
  assert.equal(await auth.verifySessionToken(legacyJwt), null, "после смены пароля старый токен отозван");
  const state = await auth.getAuthState();
  assert.equal(state.tokenVersion, 1);
  assert.equal(state.sessionSecret, SECRET, "секрет сессий сохранён");
  // Файл дописан новыми полями, но старые — на месте
  const raw = JSON.parse(fs.readFileSync(mocks.authFile, "utf8"));
  assert.equal(raw.user, "admin");
  assert.equal(raw.generatedAt, "2025-01-01T00:00:00.000Z");
  assert.equal(await auth.verifyCredentials("admin", "NewPassw0rd."), "admin");
});
