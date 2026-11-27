// Скользящая сессия: продление при активности, потолок от входа (локальный и
// SSO), отозванные токены не продлеваются, proxy ставит новую куку.
import { test } from "node:test";
import assert from "node:assert/strict";
import { decodeJwt } from "jose";
import { installNextMocks, loadAuth } from "./_next-mock";

installNextMocks();
const auth = loadAuth();
const H = 3600;

test("продление: через 5+ минут — новый exp = сейчас + простой, момент входа тот же", async () => {
  const t0 = 1_800_000_000;
  const tok = await auth.signSessionToken("admin", "admin", false, t0, t0);
  assert.equal(await auth.renewSessionToken(tok, t0 + 60), null, "раньше 5 минут не продлеваем");
  const r = await auth.renewSessionToken(tok, t0 + 2 * H);
  assert.ok(r);
  const p = decodeJwt(r.token);
  assert.equal(p.auth, t0);
  assert.equal(p.exp, t0 + 2 * H + auth.sessionIdleSec());
  assert.equal(r.maxAge, auth.sessionIdleSec());
  assert.equal((await auth.verifySessionToken(r.token, t0 + 2 * H))?.user, "admin");
});

test("простой: после exp сессия не продлевается и не действует", async () => {
  const t0 = 1_800_000_000;
  const tok = await auth.signSessionToken("admin", "admin", false, t0, t0);
  const after = t0 + auth.sessionIdleSec() + 1;
  assert.equal(await auth.renewSessionToken(tok, after), null);
  assert.equal(await auth.verifySessionToken(tok, after), null);
});

test("потолок от входа: локальный — 7 суток, продление его не сдвигает", async () => {
  const t0 = 1_800_000_000;
  let tok = await auth.signSessionToken("admin", "admin", false, t0, t0);
  let now = t0;
  // Активность каждые 10 часов — сессия живёт до потолка, не дольше.
  for (;;) {
    now += 10 * H;
    const r = await auth.renewSessionToken(tok, now);
    if (!r) break;
    tok = r.token;
  }
  const p = decodeJwt(tok);
  assert.equal(p.exp, t0 + auth.sessionMaxSec(false));
  assert.equal(p.auth, t0);
});

test("SSO: потолок 12 ч от входа — продление его не сдвигает, роль из токена", async () => {
  const t0 = 1_800_000_000;
  const tok = await auth.signSessionToken("sso:i.petrov", "analyst", true, t0, t0);
  assert.equal(decodeJwt(tok).exp, t0 + Math.min(auth.sessionIdleSec(), auth.sessionMaxSec(true)));
  assert.equal(decodeJwt(tok).role, "analyst");
  // По умолчанию простой = SSO-потолку: продлевать некуда, рабочий день — одна сессия.
  assert.equal(await auth.renewSessionToken(tok, t0 + 6 * H), null);
  assert.equal(await auth.verifySessionToken(tok, t0 + auth.sessionMaxSec(true) + 1), null, "после потолка — повторный вход через IdP");
});

test("отозванный токен (смена пароля) не продлевается", async () => {
  const u = await auth.createUser("slide.user", "viewer");
  assert.ok("password" in u);
  const t0 = Math.floor(Date.now() / 1000) - 3600;
  const tok = await auth.signSessionToken("slide.user", "viewer", false, t0, t0);
  assert.ok(await auth.renewSessionToken(tok));
  assert.equal(await auth.changePassword("slide.user", (u as { password: string }).password, "NewPassw0rd.slide"), null);
  assert.equal(await auth.renewSessionToken(tok), null);
});

test("старый токен без auth: момент входа = iat", async () => {
  const t0 = Math.floor(Date.now() / 1000) - 3600;
  const tok = await auth.signSessionToken("admin", "admin", false, t0, t0);
  // Эмуляция токена до скользящих сессий — тот же ключ, без claim auth.
  const { SignJWT } = await import("jose");
  const state = await auth.getAuthState();
  const legacy = await new SignJWT({ sub: "admin", role: "admin", sso: false, tv: decodeJwt(tok).tv })
    .setProtectedHeader({ alg: "HS256" }).setIssuedAt(t0).setExpirationTime(t0 + 12 * H)
    .sign(new TextEncoder().encode(state.sessionSecret));
  const r = await auth.renewSessionToken(legacy);
  assert.ok(r);
  assert.equal(decodeJwt(r.token).auth, t0);
});

test("proxy: кука сессии продлевается в ответе, без куки — нет", async () => {
  const { proxy } = await import("../src/proxy");
  const { NextRequest } = await import("next/server");
  const t0 = Math.floor(Date.now() / 1000) - 3600;
  const tok = await auth.signSessionToken("admin", "admin", false, t0, t0);
  const res = await proxy(new NextRequest("http://localhost/incidents", { headers: { cookie: `${auth.SESSION_COOKIE}=${tok}` } }));
  const set = res.cookies.get(auth.SESSION_COOKIE);
  assert.ok(set?.value && set.value !== tok);
  assert.equal(set.httpOnly, true);
  assert.equal(set.sameSite, "strict");
  const bare = await proxy(new NextRequest("http://localhost/incidents"));
  assert.equal(bare.cookies.get(auth.SESSION_COOKIE), undefined);
});
