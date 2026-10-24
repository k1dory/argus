import { cookies } from "next/headers";
import { createSession, recordLoginFailure } from "@/lib/auth";
import { audit } from "@/lib/argus-queries";
import { exchange, oidcConfig } from "@/lib/oidc";

export async function GET(req: Request): Promise<Response> {
  const cfg = oidcConfig();
  if (!cfg) return Response.json({ error: "OIDC не настроен" }, { status: 501 });
  const url = new URL(req.url);
  const code = url.searchParams.get("code") ?? "";
  const state = url.searchParams.get("state") ?? "";
  const jar = await cookies();
  const expected = jar.get("oidc_state")?.value;
  const nonce = jar.get("oidc_nonce")?.value ?? "";
  const verifier = jar.get("oidc_verifier")?.value ?? "";
  for (const c of ["oidc_state", "oidc_nonce", "oidc_verifier"]) jar.delete({ name: c, path: "/api/auth/oidc" });
  if (!code || !state || state !== expected) {
    await audit("sso", "session.login.failed", "sso", "state не совпал");
    return Response.redirect(new URL("/login?sso=state", url.origin), 302);
  }
  try {
    // user.name уже с префиксом sso: — отдельное пространство имён (см. oidc.ts)
    const user = await exchange(cfg, code, verifier, nonce);
    await createSession(user.name, user.role, true);
    await audit(user.name, "session.login", user.name, `sso · ${user.role} · groups: ${user.groups.join(",")}`);
    return Response.redirect(new URL("/", url.origin), 302);
  } catch (e) {
    await recordLoginFailure("sso");
    await audit("sso", "session.login.failed", "sso", e instanceof Error ? e.message.slice(0, 200) : "ошибка обмена кода");
    console.error("oidc callback:", e instanceof Error ? e.message : e);
    return Response.redirect(new URL("/login?sso=denied", url.origin), 302);
  }
}
