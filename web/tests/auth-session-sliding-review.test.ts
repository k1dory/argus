/* eslint-disable @typescript-eslint/no-require-imports */
import { test } from "node:test";
import assert from "node:assert/strict";
import Module from "node:module";
import { SignJWT, decodeJwt } from "jose";
import { installNextMocks, type AuthModule } from "./_next-mock";

installNextMocks();
const T0 = 1_800_000_000;
const H = 3600;
const envNames = [
  "ARGUS_SESSION_IDLE_HOURS",
  "ARGUS_SESSION_MAX_HOURS",
  "ARGUS_SSO_SESSION_MAX_HOURS",
] as const;

// Независимые экземпляры auth.ts моделируют Proxy и Server Actions: общий
// auth.json, но отдельные statePromise и writeQueue. Env сроков читается при
// каждом вызове — задаётся вокруг вызовов (withEnv), а не при загрузке модуля.
function freshAuth(): AuthModule {
  const cache = (Module as unknown as { _cache: Record<string, Module> })._cache;
  const file = require.resolve("../src/lib/auth");
  const previous = cache[file];
  delete cache[file];
  try {
    return require(file) as AuthModule;
  } finally {
    if (previous) cache[file] = previous;
    else delete cache[file];
  }
}

async function withEnv<T>(env: Record<string, string>, fn: () => Promise<T> | T): Promise<T> {
  const saved = envNames.map((name) => [name, process.env[name]] as const);
  for (const name of envNames) {
    if (env[name] === undefined) delete process.env[name];
    else process.env[name] = env[name];
  }
  try {
    return await fn();
  } finally {
    for (const [name, value] of saved) {
      if (value === undefined) delete process.env[name];
      else process.env[name] = value;
    }
  }
}

test("Proxy видит отзыв и новую сессию после смены пароля в другом runtime", async () => {
  const app = freshAuth();
  const user = await app.createUser("slide.cache", "viewer");
  assert.ok("password" in user);
  const oldToken = await app.signSessionToken("slide.cache", "viewer", false, T0, T0);
  const proxyAuth = freshAuth();
  assert.ok(await proxyAuth.verifySessionToken(oldToken, T0 + 600));

  assert.equal(await app.changePassword("slide.cache", user.password, "NewPassw0rd.slide"), null);
  assert.equal(await app.verifySessionToken(oldToken, T0 + 600), null);
  const currentToken = await app.signSessionToken("slide.cache", "viewer", false, T0, T0);
  const revoked = await proxyAuth.renewSessionToken(oldToken, T0 + 600);
  const current = await proxyAuth.renewSessionToken(currentToken, T0 + 600);
  assert.deepEqual(
    { revokedRejected: revoked === null, currentRenewed: current !== null },
    { revokedRejected: true, currentRenewed: true },
  );
});

test("Proxy не продлевает сессию удалённого в другом runtime пользователя", async () => {
  const app = freshAuth();
  assert.ok("password" in await app.createUser("slide.deleted", "viewer"));
  const token = await app.signSessionToken("slide.deleted", "viewer", false, T0, T0);
  const proxyAuth = freshAuth();
  assert.ok(await proxyAuth.verifySessionToken(token, T0 + 600));
  assert.equal(await app.deleteUser("slide.deleted", "admin"), null);
  assert.equal(await proxyAuth.renewSessionToken(token, T0 + 600), null);
});

for (const sso of [false, true]) {
  for (const legacy of [false, true]) {
    test("уменьшенный потолок проверяется при доступе: sso=" + sso + ", legacy=" + legacy, async () => {
      const before = freshAuth();
      const name = sso ? "sso:cap-review" : "admin";
      let token = await before.signSessionToken(name, "admin", sso, T0, T0);
      if (legacy) {
        const payload = decodeJwt(token);
        delete payload.auth;
        payload.exp = T0 + (sso ? H : 12 * H);
        token = await new SignJWT(payload)
          .setProtectedHeader({ alg: "HS256" })
          .sign(new TextEncoder().encode((await before.getAuthState()).sessionSecret));
      }
      const after = freshAuth();
      await withEnv({ ARGUS_SESSION_MAX_HOURS: "0.25", ARGUS_SSO_SESSION_MAX_HOURS: "0.25" }, async () => {
        assert.equal(await after.renewSessionToken(token, T0 + 1800), null);
        assert.equal(await after.verifySessionToken(token, T0 + 1800), null);
      });
    });
  }
}

test("idle 3 минуты: запрос перед exp продлевает активную сессию", async () => {
  const auth = freshAuth();
  await withEnv({ ARGUS_SESSION_IDLE_HOURS: "0.05" }, async () => {
    const token = await auth.signSessionToken("admin", "admin", false, T0, T0);
    assert.equal(decodeJwt(token).exp, T0 + 180);
    const renewed = await auth.renewSessionToken(token, T0 + 179);
    assert.ok(renewed);
    assert.ok(await auth.verifySessionToken(renewed.token, T0 + 181));
  });
});

for (const [name, sso, limit] of [
  ["ARGUS_SESSION_MAX_HOURS", false, 168 * H],
  ["ARGUS_SSO_SESSION_MAX_HOURS", true, 12 * H],
] as const) {
  test("переполнение " + name + " сохраняет дефолтный потолок", async () => {
    const auth = freshAuth();
    await withEnv({ [name]: "1e308" }, () => assert.equal(auth.sessionExp(T0 + limit, T0, sso), T0 + limit));
  });
}

for (const value of ["1e308", "0.00000001"]) {
  test("непредставимый idle=" + value + " использует дефолт 12 часов", async () => {
    const auth = freshAuth();
    await withEnv({ ARGUS_SESSION_IDLE_HOURS: value }, async () => {
      const token = await auth.signSessionToken("admin", "admin", false, T0, T0);
      assert.equal(decodeJwt(token).exp, T0 + 12 * H);
      assert.ok(await auth.verifySessionToken(token, T0 + 1));
    });
  });
}
