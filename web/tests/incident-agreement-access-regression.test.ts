// PR #51: настоящий GET и серверная страница, реальные подписи cookie/JWT.
// В отличие от проверки agreementApiForbidden с готовым Session, проверяем
// apiGuard, в том числе при одновременно присланной cookie администратора.
import { beforeEach, test } from "node:test";
import assert from "node:assert/strict";
import { installNextMocks, isRedirect, loadAuth } from "./_next-mock";
import { assertOpenAPIResponse } from "./_openapi-response";

const mocks = installNextMocks();
const auth = loadAuth();
const API = "agreement-review-api-" + "a".repeat(40);
const ISSUER = "agreement-review-issuer-" + "i".repeat(40);
process.env.ARGUS_API_TOKEN = API;
process.env.ARGUS_TRIAGE_ISSUER_TOKEN = ISSUER;

/* eslint-disable @typescript-eslint/no-require-imports -- Next/auth mocks до маршрутов */
const { GET } = require("../src/app/api/incidents/agreement/route") as typeof import("../src/app/api/incidents/agreement/route");
const page = require("../src/app/(console)/rules/agreement/page") as {
  default: (props: { searchParams: Promise<Record<string, string>> }) => Promise<unknown>;
};
/* eslint-enable @typescript-eslint/no-require-imports */

let seq = 0;
beforeEach(() => {
  seq++;
  mocks.jar.clear();
  mocks.headers.clear();
  auth.forgetTriageMemory();
});

const request = (token?: string) => new Request("http://x/api/incidents/agreement?window=7d", {
  headers: token === undefined ? {} : { authorization: `Bearer ${token}` },
});

test("agreement: без сессии API даёт 401, страница перенаправляет до чтения хранилища", async (t) => {
  const fetch = t.mock.method(globalThis, "fetch", async () => new Response(""));
  assert.equal((await GET(request())).status, 401);
  await assert.rejects(page.default({ searchParams: Promise.resolve({}) }), isRedirect);
  assert.equal(fetch.mock.callCount(), 0);
});

test("agreement: роли analyst/admin получают метрики, viewer не читает их даже через страницу", async (t) => {
  const fetch = t.mock.method(globalThis, "fetch", async () => new Response(""));
  for (const role of ["viewer", "analyst", "admin"] as const) {
    await auth.createSession(`sso:agreement-review-${role}-${seq}`, role, true);
    const before = fetch.mock.callCount();
    const response = await GET(request());
    assert.equal(response.status, role === "viewer" ? 403 : 200, role);
    await assertOpenAPIResponse("/api/incidents/agreement", response);
    if (role === "viewer") {
      await assert.rejects(page.default({ searchParams: Promise.resolve({}) }), auth.ForbiddenError);
      assert.equal(fetch.mock.callCount(), before);
    } else {
      await page.default({ searchParams: Promise.resolve({ window: "30d" }) });
      assert.equal(fetch.mock.callCount(), before + 2);
    }
  }
});

test("agreement: API-токен разрешён; issuer и подписанная triage-session получают 403 до запроса метрик", async (t) => {
  const fetch = t.mock.method(globalThis, "fetch", async () => new Response(""));
  const issued = await auth.signTriageToken({
    incidentId: "INC-7", related: {}, entities: [], bind: { actors: [], nodes: [] },
    searchFrom: new Date(Date.now() - 3_600_000).toISOString(), ttlSec: 300,
  });
  // Администраторская cookie не должна подменить предъявленный bearer.
  await auth.createSession(`sso:agreement-review-bearer-${seq}`, "admin", true);
  for (const token of [ISSUER, issued.token]) {
    const before = fetch.mock.callCount();
    const response = await GET(request(token));
    assert.equal(response.status, 403);
    await assertOpenAPIResponse("/api/incidents/agreement", response);
    assert.equal(fetch.mock.callCount(), before);
  }
  assert.equal((await GET(request("invalid-review-token"))).status, 401);
  mocks.jar.clear();
  const response = await GET(request(API));
  assert.equal(response.status, 200);
  await assertOpenAPIResponse("/api/incidents/agreement", response);
});
