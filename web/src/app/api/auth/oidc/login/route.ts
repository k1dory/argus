import crypto from "crypto";
import { cookieSecure } from "@/lib/auth";
import { cookies } from "next/headers";
import { authUrl, oidcConfig, pkce } from "@/lib/oidc";

export async function GET(): Promise<Response> {
  const cfg = oidcConfig();
  if (!cfg) return Response.json({ error: "OIDC не настроен (OIDC_ISSUER, OIDC_CLIENT_ID)" }, { status: 501 });
  const state = crypto.randomBytes(16).toString("base64url");
  const nonce = crypto.randomBytes(16).toString("base64url");
  const { verifier, challenge } = pkce();
  const jar = await cookies();
  const opts = { httpOnly: true, sameSite: "lax" as const, secure: cookieSecure(), path: "/api/auth/oidc", maxAge: 600 };
  jar.set("oidc_state", state, opts);
  jar.set("oidc_nonce", nonce, opts);
  jar.set("oidc_verifier", verifier, opts);
  try {
    return Response.redirect(await authUrl(cfg, state, nonce, challenge), 302);
  } catch (e) {
    return Response.json({ error: e instanceof Error ? e.message : String(e) }, { status: 502 });
  }
}
