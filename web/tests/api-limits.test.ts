import { test } from "node:test";
import assert from "node:assert/strict";
import { clampInt, clampLevel, clampPage, MAX_API_PAGE } from "../src/lib/shared/limits";
import { loadAuth } from "./_next-mock";

const auth = loadAuth();
const TOKEN = "t".repeat(40);

test("клампы page/level: одна функция, границы 1…1000 и 0…15", () => {
  assert.equal(clampPage(undefined), 1);
  assert.equal(clampPage("0"), 1);
  assert.equal(clampPage("-5"), 1);
  assert.equal(clampPage("abc"), 1);
  assert.equal(clampPage("7.9"), 7);
  assert.equal(clampPage("999999"), MAX_API_PAGE);
  assert.equal(clampPage(String(Number.MAX_SAFE_INTEGER)), 1000);
  assert.equal(clampLevel("99"), 15);
  assert.equal(clampLevel("-1"), 0);
  assert.equal(clampLevel("12"), 12);
  assert.equal(clampInt("NaN", 1, 10, 3), 3);
  assert.equal(clampInt(Infinity, 1, 10, 3), 3);
});

test("bearer короче 32 символов отвергается — и данный, и настроенный", () => {
  assert.equal(auth.bearerTokenValid("short", "short"), false);
  assert.equal(auth.bearerTokenValid("x".repeat(31), "x".repeat(31)), false);
  assert.equal(auth.bearerTokenValid(TOKEN, TOKEN), true);
  assert.equal(auth.bearerTokenValid(TOKEN, "u".repeat(40)), false);
  assert.equal(auth.bearerTokenValid(TOKEN, undefined), false);
});

test("apiSession: bearer даёт viewer, короткий токен — 401", async () => {
  process.env.ARGUS_API_TOKEN = TOKEN;
  const ok = await auth.apiSession(new Request("http://x/api/sources", { headers: { authorization: `Bearer ${TOKEN}` } }));
  assert.deepEqual(ok, { kind: "api-token", user: "api-token", role: "viewer", sso: false, mustChangePassword: false });
  assert.equal(await auth.apiSession(new Request("http://x/api/sources", { headers: { authorization: "Bearer short" } })), null);
  process.env.ARGUS_API_TOKEN = "short-configured";
  assert.equal(await auth.apiSession(new Request("http://x/api/sources", { headers: { authorization: "Bearer short-configured" } })), null);
  process.env.ARGUS_API_TOKEN = TOKEN;
});

test("token bucket: 5 экспортов в минуту, шестой — 429 с Retry-After; обычный лимит отдельный", async () => {
  process.env.ARGUS_API_TOKEN = TOKEN;
  const req = () => new Request("http://x/api/search?format=csv", { headers: { authorization: `Bearer ${TOKEN}` } });
  for (let i = 0; i < 5; i++) {
    const g = await auth.apiGuard(req(), "export");
    assert.ok(g.session, `экспорт ${i + 1} проходит`);
  }
  const denied = await auth.apiGuard(req(), "export");
  assert.ok(denied.response);
  assert.equal(denied.response.status, 429);
  assert.match(denied.response.headers.get("Retry-After") ?? "", /^\d+$/);
  assert.deepEqual(await denied.response.json(), { error: "слишком много запросов" });
  // Обычные запросы — свой бакет (60/мин), не задет экспортом
  const normal = await auth.apiGuard(req(), "default");
  assert.ok(normal.session);
  // Без токена — 401 раньше лимита
  const anon = await auth.apiGuard(new Request("http://x/api/search"));
  assert.equal(anon.response?.status, 401);
});

test("rateLimit: пополнение бакета со временем", () => {
  const key = "rl-" + Date.now();
  let now = 0;
  for (let i = 0; i < 60; i++) assert.equal(auth.rateLimit(key, 60, 60_000, now).ok, true);
  const r = auth.rateLimit(key, 60, 60_000, now);
  assert.equal(r.ok, false);
  assert.equal(r.retryAfterSec, 1);
  now += 1000; // +1 токен
  assert.equal(auth.rateLimit(key, 60, 60_000, now).ok, true);
  assert.equal(auth.rateLimit(key, 60, 60_000, now).ok, false);
  now += 60_000;
  for (let i = 0; i < 60; i++) assert.equal(auth.rateLimit(key, 60, 60_000, now).ok, true, "полный бакет через минуту");
});
