// Маршруты входа через IdP: /api/auth/oidc/login (state, nonce, PKCE в cookie,
// 302 на authorize-endpoint из discovery) и /callback (проверка state, обмен кода
// с code_verifier, подпись id_token по JWKS, nonce, группы → роль, сессия sso:,
// журнал). IdP целиком подменён на уровне fetch: discovery, JWKS, token, userinfo.
import { test, before } from "node:test";
import assert from "node:assert/strict";
import crypto from "node:crypto";
import { exportJWK, generateKeyPair, SignJWT, type CryptoKey } from "jose";
import { installNextMocks, loadAuth } from "./_next-mock";

const ISSUER = "https://idp.example/application/o/argus";
const REDIRECT = "https://argus.example:8443/api/auth/oidc/callback";
process.env.OIDC_ISSUER = ISSUER + "/"; // хвостовой слэш срезается
process.env.OIDC_CLIENT_ID = "argus-console";
process.env.OIDC_CLIENT_SECRET = "client-secret-for-test";
process.env.OIDC_REDIRECT_URL = REDIRECT;
process.env.OIDC_GROUP_ADMIN = "argus-admins";
process.env.OIDC_GROUP_ANALYST = "argus-analysts, soc";
process.env.OIDC_GROUP_VIEWER = "";
delete process.env.OIDC_DEFAULT_ROLE;

const auth = loadAuth();
const mocks = installNextMocks();

/* eslint-disable @typescript-eslint/no-require-imports -- маршруты грузятся после моков */
const loginRoute = require("../src/app/api/auth/oidc/login/route") as { GET: () => Promise<Response> };
const callbackRoute = require("../src/app/api/auth/oidc/callback/route") as { GET: (req: Request) => Promise<Response> };
/* eslint-enable @typescript-eslint/no-require-imports */

const DISCOVERY = {
  authorization_endpoint: ISSUER + "/authorize/",
  token_endpoint: ISSUER + "/token/",
  jwks_uri: ISSUER + "/jwks/",
  userinfo_endpoint: ISSUER + "/userinfo/",
};

type Keys = { privateKey: CryptoKey; jwk: Record<string, unknown> };
let keys: Keys;
/** Что IdP вернёт на следующий обмен кода и запрос userinfo. */
const idp = {
  discoveryStatus: 200,
  tokenStatus: 200,
  tokenBody: null as Record<string, unknown> | null,
  userinfoGroups: null as string[] | null,
  tokenRequests: [] as { url: string; body: URLSearchParams }[],
};

async function idToken(claims: Record<string, unknown>, opts: { issuer?: string; audience?: string; key?: Keys } = {}): Promise<string> {
  const k = opts.key ?? keys;
  return new SignJWT(claims)
    .setProtectedHeader({ alg: "RS256", kid: String(k.jwk.kid) })
    .setIssuer(opts.issuer ?? ISSUER)
    .setAudience(opts.audience ?? "argus-console")
    .setSubject("u-1")
    .setIssuedAt()
    .setExpirationTime("5m")
    .sign(k.privateKey);
}

globalThis.fetch = (async (input: URL | string | Request, init?: RequestInit) => {
  const url = String(input instanceof Request ? input.url : input);
  if (url === ISSUER + "/.well-known/openid-configuration") {
    return idp.discoveryStatus === 200 ? Response.json(DISCOVERY) : new Response("down", { status: idp.discoveryStatus });
  }
  if (url === DISCOVERY.jwks_uri) return Response.json({ keys: [keys.jwk] });
  if (url === DISCOVERY.token_endpoint) {
    idp.tokenRequests.push({ url, body: new URLSearchParams(String(init?.body)) });
    if (idp.tokenStatus !== 200) return new Response("invalid_grant", { status: idp.tokenStatus });
    return Response.json(idp.tokenBody ?? {});
  }
  if (url === DISCOVERY.userinfo_endpoint) {
    const authz = new Headers(init?.headers).get("authorization");
    return idp.userinfoGroups && authz === "Bearer at-1" ? Response.json({ groups: idp.userinfoGroups }) : new Response("", { status: 401 });
  }
  throw new Error("неожиданный fetch: " + url);
}) as typeof fetch;

before(async () => {
  const pair = await generateKeyPair("RS256");
  const jwk = await exportJWK(pair.publicKey);
  keys = { privateKey: pair.privateKey, jwk: { ...jwk, kid: "k1", alg: "RS256", use: "sig" } };
  await auth.getAuthState();
  console.error = () => undefined;
});

/** Начать вход: cookie state/nonce/verifier в банке, как после /login. */
async function startLogin(): Promise<{ state: string; nonce: string; verifier: string; location: URL }> {
  mocks.jar.clear();
  const r = await loginRoute.GET();
  assert.equal(r.status, 302);
  return { state: mocks.jar.get("oidc_state")!, nonce: mocks.jar.get("oidc_nonce")!, verifier: mocks.jar.get("oidc_verifier")!, location: new URL(r.headers.get("location")!) };
}

const callback = (qs: string) => callbackRoute.GET(new Request(`http://0.0.0.0:3000/api/auth/oidc/callback?${qs}`));
const lastAudit = () => mocks.audit.at(-1)!;

test("без OIDC_ISSUER/OIDC_CLIENT_ID оба маршрута — 501, cookie не ставятся", async () => {
  const saved = process.env.OIDC_ISSUER;
  delete process.env.OIDC_ISSUER;
  try {
    const r = await loginRoute.GET();
    assert.equal(r.status, 501);
    assert.match(((await r.json()) as { error: string }).error, /OIDC не настроен/);
    assert.equal(mocks.jar.size, 0);
    assert.equal((await callback("code=x&state=y")).status, 501);
  } finally {
    process.env.OIDC_ISSUER = saved;
  }
});

test("discovery недоступен — 502 с причиной (первый вызов: кэш discovery ещё пуст)", async () => {
  idp.discoveryStatus = 503;
  try {
    const r = await loginRoute.GET();
    assert.equal(r.status, 502);
    assert.match(((await r.json()) as { error: string }).error, /OIDC discovery 503/);
  } finally {
    idp.discoveryStatus = 200;
  }
});

test("login: 302 на authorize с client_id, redirect_uri, scope с claim групп, PKCE S256; state/nonce/verifier — в cookie", async () => {
  const { state, nonce, verifier, location } = await startLogin();
  assert.equal(location.origin + location.pathname, DISCOVERY.authorization_endpoint);
  const q = location.searchParams;
  assert.equal(q.get("response_type"), "code");
  assert.equal(q.get("client_id"), "argus-console");
  assert.equal(q.get("redirect_uri"), REDIRECT);
  assert.equal(q.get("scope"), "openid profile email groups");
  assert.equal(q.get("code_challenge_method"), "S256");
  assert.equal(q.get("state"), state);
  assert.equal(q.get("nonce"), nonce);
  assert.ok(state.length >= 16 && nonce.length >= 16 && verifier.length >= 43, "случайные значения достаточной длины");
  assert.equal(q.get("code_challenge"), crypto.createHash("sha256").update(verifier).digest("base64url"), "challenge = sha256(verifier)");
  // Два входа — разные state/nonce/verifier.
  const second = await startLogin();
  assert.notEqual(second.state, state);
  assert.notEqual(second.verifier, verifier);
});

test("callback: нет cookie state / нет code / state не совпал — 302 на /login?sso=state от OIDC_REDIRECT_URL, запись в журнал, cookie стёрты", async () => {
  mocks.jar.clear();
  let r = await callback("code=abc&state=xyz");
  assert.equal(r.status, 302);
  assert.equal(r.headers.get("location"), "https://argus.example:8443/login?sso=state", "origin — из OIDC_REDIRECT_URL, не из адреса прослушивания");
  assert.equal(lastAudit().action, "session.login.failed");
  assert.match(lastAudit().detail, /cookie oidc_state нет: вход начат не с https:\/\/argus\.example:8443/);

  const { state } = await startLogin();
  r = await callback(`state=${state}`);
  assert.equal(r.headers.get("location"), "https://argus.example:8443/login?sso=state");
  assert.match(lastAudit().detail, /без code\/state/);
  assert.ok(!mocks.jar.has("oidc_state") && !mocks.jar.has("oidc_nonce") && !mocks.jar.has("oidc_verifier"), "одноразовые cookie стёрты даже при отказе");

  await startLogin();
  r = await callback("code=abc&state=other");
  assert.equal(r.headers.get("location"), "https://argus.example:8443/login?sso=state");
  assert.match(lastAudit().detail, /state не совпал/);
  assert.equal(idp.tokenRequests.length, 0, "код в IdP не отправлялся");
});

test("callback: успешный вход — обмен кода с verifier и секретом, роль по группам, сессия sso:имя, журнал", async () => {
  const { state, nonce, verifier } = await startLogin();
  idp.tokenBody = { id_token: await idToken({ nonce, preferred_username: "Ivan.Petrov", groups: ["staff", "argus-admins"] }), access_token: "at-1" };
  const r = await callback(`code=code-1&state=${state}`);
  assert.equal(r.status, 302);
  assert.equal(r.headers.get("location"), "https://argus.example:8443/");
  const tr = idp.tokenRequests.at(-1)!;
  assert.equal(tr.body.get("grant_type"), "authorization_code");
  assert.equal(tr.body.get("code"), "code-1");
  assert.equal(tr.body.get("redirect_uri"), REDIRECT);
  assert.equal(tr.body.get("client_id"), "argus-console");
  assert.equal(tr.body.get("code_verifier"), verifier, "PKCE: verifier из cookie");
  assert.equal(tr.body.get("client_secret"), "client-secret-for-test");

  const session = await auth.getSession();
  assert.ok(session, "сессия консоли выдана");
  assert.equal(session!.user, "sso:ivan.petrov", "имя — нижний регистр с префиксом sso:");
  assert.equal(session!.role, "admin", "самая сильная из совпавших групп");
  assert.equal(session!.sso, true);
  assert.ok(!mocks.jar.has("oidc_state"), "одноразовые cookie стёрты");
  const rec = lastAudit();
  assert.equal(rec.action, "session.login");
  assert.equal(rec.user, "sso:ivan.petrov");
  assert.equal(rec.detail, "sso · admin · groups: staff,argus-admins");
  const users = await auth.listUsers();
  const sso = users.find((u) => u.name === "sso:ivan.petrov");
  assert.ok(sso?.sso && sso.role === "admin", "SSO-пользователь появился в списке");
});

test("callback: повторный вход с другой группой меняет роль; группы из userinfo, когда id_token без них; имя из email", async () => {
  let { state, nonce } = await startLogin();
  idp.tokenBody = { id_token: await idToken({ nonce, preferred_username: "ivan.petrov", groups: ["soc"] }) };
  await callback(`code=c&state=${state}`);
  assert.equal((await auth.getSession())!.role, "analyst", "роль пересчитывается на каждом входе");
  assert.equal((await auth.listUsers()).find((u) => u.name === "sso:ivan.petrov")!.role, "analyst");

  ({ state, nonce } = await startLogin());
  idp.tokenBody = { id_token: await idToken({ nonce, email: "Olga@Example.org" }), access_token: "at-1" };
  idp.userinfoGroups = ["argus-analysts"];
  const r = await callback(`code=c&state=${state}`);
  assert.equal(r.headers.get("location"), "https://argus.example:8443/");
  const s = await auth.getSession();
  assert.equal(s!.user, "sso:olga@example.org");
  assert.equal(s!.role, "analyst");
  assert.equal(lastAudit().detail, "sso · analyst · groups: argus-analysts");
  idp.userinfoGroups = null;
});

test("callback: отказ — нет групп для роли, nonce не совпал, чужой issuer/audience, подпись чужим ключом, IdP отверг код, нет id_token", async () => {
  const other = await generateKeyPair("RS256");
  const otherKeys: Keys = { privateKey: other.privateKey, jwk: { ...(await exportJWK(other.publicKey)), kid: "k1", alg: "RS256", use: "sig" } };
  const cases: { name: string; token: (nonce: string) => Promise<Record<string, unknown>>; status?: number; why: RegExp }[] = [
    { name: "группы не сопоставлены", token: async (nonce) => ({ id_token: await idToken({ nonce, preferred_username: "x", groups: ["guests"] }) }), why: /ни одна группа/ },
    { name: "нет групп и нет access_token для userinfo", token: async (nonce) => ({ id_token: await idToken({ nonce, preferred_username: "x" }) }), why: /ни одна группа/ },
    { name: "nonce", token: async () => ({ id_token: await idToken({ nonce: "stale", preferred_username: "x", groups: ["argus-admins"] }) }), why: /nonce не совпал/ },
    { name: "issuer", token: async (nonce) => ({ id_token: await idToken({ nonce, groups: ["argus-admins"] }, { issuer: "https://evil.example" }) }), why: /iss/ },
    { name: "audience", token: async (nonce) => ({ id_token: await idToken({ nonce, groups: ["argus-admins"] }, { audience: "other-client" }) }), why: /aud/ },
    { name: "чужой ключ", token: async (nonce) => ({ id_token: await idToken({ nonce, groups: ["argus-admins"] }, { key: otherKeys }) }), why: /signature|подпис/i },
    { name: "нет id_token", token: async () => ({ access_token: "at-1" }), why: /нет id_token/ },
    { name: "IdP отверг код", token: async () => ({}), status: 400, why: /OIDC token 400/ },
  ];
  for (const c of cases) {
    const { state, nonce } = await startLogin();
    idp.tokenBody = await c.token(nonce);
    idp.tokenStatus = c.status ?? 200;
    const r = await callback(`code=c&state=${state}`);
    assert.equal(r.status, 302, c.name);
    assert.equal(r.headers.get("location"), "https://argus.example:8443/login?sso=denied", c.name);
    assert.equal(await auth.getSession(), null, `${c.name}: сессии нет`);
    assert.equal(lastAudit().action, "session.login.failed", c.name);
    assert.equal(lastAudit().user, "sso", c.name);
    assert.match(lastAudit().detail, c.why, c.name);
  }
  idp.tokenStatus = 200;
});

test("callback: имена с префиксом sso: и локальные логины не пересекаются; слишком длинное имя обрезается", async () => {
  const { state, nonce } = await startLogin();
  idp.tokenBody = { id_token: await idToken({ nonce, preferred_username: "SSO:" + "a".repeat(300), groups: ["argus-admins"] }) };
  await callback(`code=c&state=${state}`);
  const s = await auth.getSession();
  assert.ok(s!.user.startsWith("sso:") && !s!.user.startsWith("sso:sso:"), s!.user);
  assert.ok(s!.user.length <= 4 + 120);
  assert.ok((await auth.listUsers()).every((u) => !u.sso || u.name.startsWith("sso:")), "все SSO-записи — в своём пространстве имён");
});
