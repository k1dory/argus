// Вход через IdP по OIDC (Authentik, Keycloak, любой OpenID Connect) с
// маппингом групп IdP на роли консоли. Синхронизация групп — на каждом входе:
// роль вычисляется из claim groups, локальная запись пользователя не нужна.
// Имя SSO-пользователя получает префикс sso: — отдельное пространство имён,
// в котором нельзя столкнуться со встроенным admin или локальным пользователем.
import crypto from "crypto";
import { createRemoteJWKSet, jwtVerify } from "jose";
import type { Role } from "./shared/incidents";

export const SSO_PREFIX = "sso:";

export type OidcConfig = {
  issuer: string;
  clientId: string;
  clientSecret: string;
  redirectUrl: string;
  groupsClaim: string;
  groups: { admin: string[]; analyst: string[]; viewer: string[] };
  defaultRole: Role | null;
};

function list(v: string | undefined): string[] {
  return (v ?? "").split(",").map((s) => s.trim()).filter(Boolean);
}

export function oidcConfig(): OidcConfig | null {
  const issuer = process.env.OIDC_ISSUER?.replace(/\/$/, "");
  if (!issuer || !process.env.OIDC_CLIENT_ID) return null;
  const dr = process.env.OIDC_DEFAULT_ROLE as Role | undefined;
  return {
    issuer,
    clientId: process.env.OIDC_CLIENT_ID,
    clientSecret: process.env.OIDC_CLIENT_SECRET ?? "",
    redirectUrl: process.env.OIDC_REDIRECT_URL ?? "https://localhost:8443/api/auth/oidc/callback",
    groupsClaim: process.env.OIDC_GROUPS_CLAIM ?? "groups",
    groups: { admin: list(process.env.OIDC_GROUP_ADMIN), analyst: list(process.env.OIDC_GROUP_ANALYST), viewer: list(process.env.OIDC_GROUP_VIEWER) },
    defaultRole: dr === "admin" || dr === "analyst" || dr === "viewer" ? dr : null,
  };
}

/** Роль по группам IdP: самая сильная из совпавших; без совпадений — default или отказ. */
export function mapRole(groups: string[], cfg: Pick<OidcConfig, "groups" | "defaultRole">): Role | null {
  const has = (names: string[]) => names.some((g) => groups.includes(g));
  if (has(cfg.groups.admin)) return "admin";
  if (has(cfg.groups.analyst)) return "analyst";
  if (has(cfg.groups.viewer)) return "viewer";
  return cfg.defaultRole;
}

/** Имя SSO-пользователя консоли: нижний регистр, обрезка, префикс sso:.
 *  Уже префиксованное имя второй раз не префиксуется; пустое имя (в том
 *  числе «sso:» без остатка) → sso:user. */
export function ssoUserName(raw: string): string {
  let base = raw.trim().toLowerCase().slice(0, 120);
  if (base.startsWith(SSO_PREFIX)) base = base.slice(SSO_PREFIX.length).trim();
  return SSO_PREFIX + (base || "user");
}

type Discovery = { authorization_endpoint: string; token_endpoint: string; jwks_uri: string; userinfo_endpoint?: string };
let discovery: { at: number; doc: Discovery } | null = null;

const FETCH_TIMEOUT_MS = 30_000;

export async function discover(cfg: OidcConfig): Promise<Discovery> {
  if (discovery && Date.now() - discovery.at < 3600_000) return discovery.doc;
  const r = await fetch(cfg.issuer + "/.well-known/openid-configuration", { cache: "no-store", signal: AbortSignal.timeout(FETCH_TIMEOUT_MS) });
  if (!r.ok) throw new Error(`OIDC discovery ${r.status}`);
  const doc = (await r.json()) as Discovery;
  discovery = { at: Date.now(), doc };
  return doc;
}

// JWKS — один набор ключей на issuer: createRemoteJWKSet сам кэширует ключи
// и обновляет их при неизвестном kid; новый экземпляр на каждый вход
// означал бы поход за ключами на каждый логин.
const jwksByIssuer = new Map<string, ReturnType<typeof createRemoteJWKSet>>();

export function jwksFor(issuer: string, jwksUri: string): ReturnType<typeof createRemoteJWKSet> {
  let set = jwksByIssuer.get(issuer);
  if (!set) {
    set = createRemoteJWKSet(new URL(jwksUri));
    jwksByIssuer.set(issuer, set);
  }
  return set;
}

export function pkce(): { verifier: string; challenge: string } {
  const verifier = crypto.randomBytes(48).toString("base64url");
  const challenge = crypto.createHash("sha256").update(verifier).digest("base64url");
  return { verifier, challenge };
}

export async function authUrl(cfg: OidcConfig, state: string, nonce: string, challenge: string): Promise<string> {
  const d = await discover(cfg);
  const u = new URL(d.authorization_endpoint);
  u.searchParams.set("response_type", "code");
  u.searchParams.set("client_id", cfg.clientId);
  u.searchParams.set("redirect_uri", cfg.redirectUrl);
  u.searchParams.set("scope", "openid profile email " + cfg.groupsClaim);
  u.searchParams.set("state", state);
  u.searchParams.set("nonce", nonce);
  u.searchParams.set("code_challenge", challenge);
  u.searchParams.set("code_challenge_method", "S256");
  return u.toString();
}

export type OidcUser = { name: string; role: Role; groups: string[] };

export async function exchange(cfg: OidcConfig, code: string, verifier: string, nonce: string): Promise<OidcUser> {
  const d = await discover(cfg);
  const body = new URLSearchParams({ grant_type: "authorization_code", code, redirect_uri: cfg.redirectUrl, client_id: cfg.clientId, code_verifier: verifier });
  if (cfg.clientSecret) body.set("client_secret", cfg.clientSecret);
  const r = await fetch(d.token_endpoint, { method: "POST", headers: { "Content-Type": "application/x-www-form-urlencoded" }, body, cache: "no-store", signal: AbortSignal.timeout(FETCH_TIMEOUT_MS) });
  if (!r.ok) throw new Error(`OIDC token ${r.status}: ${(await r.text()).slice(0, 200)}`);
  const tokens = (await r.json()) as { id_token?: string; access_token?: string };
  if (!tokens.id_token) throw new Error("OIDC: нет id_token");
  const jwks = jwksFor(cfg.issuer, d.jwks_uri);
  const { payload } = await jwtVerify(tokens.id_token, jwks, { issuer: [cfg.issuer, cfg.issuer + "/"], audience: cfg.clientId });
  if (payload.nonce !== nonce) throw new Error("OIDC: nonce не совпал");
  let groups = Array.isArray(payload[cfg.groupsClaim]) ? (payload[cfg.groupsClaim] as string[]) : [];
  // Authentik кладёт groups в id_token; если их нет — добираем из userinfo
  if (groups.length === 0 && d.userinfo_endpoint && tokens.access_token) {
    const ui = await fetch(d.userinfo_endpoint, { headers: { Authorization: "Bearer " + tokens.access_token }, cache: "no-store", signal: AbortSignal.timeout(FETCH_TIMEOUT_MS) });
    if (ui.ok) {
      const info = (await ui.json()) as Record<string, unknown>;
      if (Array.isArray(info[cfg.groupsClaim])) groups = info[cfg.groupsClaim] as string[];
    }
  }
  const role = mapRole(groups, cfg);
  if (!role) throw new Error("OIDC: ни одна группа не сопоставлена роли ARGUS");
  const name = ssoUserName(String(payload.preferred_username ?? payload.email ?? payload.sub ?? "sso-user"));
  return { name, role, groups };
}
