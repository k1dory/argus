import { cookies } from "next/headers";
import { createSession, recordLoginFailure, recordSsoLogin } from "@/lib/auth";
import { audit } from "@/lib/argus-queries";
import { consoleUrl, exchange, oidcConfig, OidcNoRoleError } from "@/lib/oidc";
import { ssoInterstitialHtml } from "@/lib/shared/sso-interstitial";

/**
 * Возврат с IdP — в два шага, чтобы вход не «подвисал»:
 * GET (redirect_uri из IdP) сразу отдаёт экран «Входим в ARGUS…», который сам
 * отправляет code/state POST-ом сюда же; POST меняет код на токены, создаёт
 * сессию, пишет журнал и уводит в консоль. Пока идут обмен и первая загрузка
 * консоли, браузер показывает экран загрузки, а не застывшую страницу IdP.
 * Cookie oidc_* читаются и удаляются только в POST.
 */
export async function GET(req: Request): Promise<Response> {
  const cfg = oidcConfig();
  if (!cfg) return Response.json({ error: "OIDC не настроен" }, { status: 501 });
  const url = new URL(req.url);
  const code = url.searchParams.get("code") ?? "";
  const state = url.searchParams.get("state") ?? "";
  // IdP вернул отказ (error=access_denied …) или пустой ответ — сразу на вход, без экрана загрузки.
  if (url.searchParams.has("error")) return finish(cfg, "", "", url.searchParams.get("error") ?? "error");
  if (!code || !state) return finish(cfg, code, state);
  return new Response(ssoInterstitialHtml({ code, state, nonce: req.headers.get("x-nonce") ?? undefined }), {
    status: 200,
    headers: {
      "Content-Type": "text/html; charset=utf-8",
      "Cache-Control": "no-store",
      // В адресе — одноразовый code: не отдавать его в Referer.
      "Referrer-Policy": "no-referrer",
    },
  });
}

export async function POST(req: Request): Promise<Response> {
  const cfg = oidcConfig();
  if (!cfg) return Response.json({ error: "OIDC не настроен" }, { status: 501 });
  let code = "";
  let state = "";
  try {
    const form = await req.formData();
    code = String(form.get("code") ?? "");
    state = String(form.get("state") ?? "");
  } catch {
    /* не форма — пустые code/state, ниже уйдёт в ошибку state */
  }
  return finish(cfg, code, state);
}

async function finish(cfg: NonNullable<ReturnType<typeof oidcConfig>>, code: string, state: string, idpError?: string): Promise<Response> {
  const jar = await cookies();
  const expected = jar.get("oidc_state")?.value;
  const nonce = jar.get("oidc_nonce")?.value ?? "";
  const verifier = jar.get("oidc_verifier")?.value ?? "";
  for (const c of ["oidc_state", "oidc_nonce", "oidc_verifier"]) jar.delete({ name: c, path: "/api/auth/oidc" });
  // 303 — после POST браузер идёт по адресу GET-ом.
  const go = (path: string) => Response.redirect(consoleUrl(cfg, path), 303);
  if (idpError) {
    // Отказ на стороне IdP (пользователь нажал «Отмена», нет доступа к приложению).
    await audit("sso", "session.login.failed", "sso", `IdP: ${idpError.slice(0, 100)}`);
    return go("/login?sso=denied");
  }
  if (!code || !state || state !== expected) {
    // Нет cookie — вход начат с другого адреса, чем OIDC_REDIRECT_URL (cookie привязана
    // к хосту), или истёк срок (OIDC_STATE_TTL); не совпал — параллельный вход в другой вкладке.
    const why = !expected
      ? `cookie oidc_state нет: вход начат не с ${new URL(cfg.redirectUrl).origin} или истёк`
      : !code || !state ? "IdP вернул ответ без code/state" : "state не совпал (параллельный вход?)";
    await audit("sso", "session.login.failed", "sso", why);
    return go("/login?sso=state");
  }
  try {
    // user.name уже с префиксом sso: — отдельное пространство имён (см. oidc.ts)
    const user = await exchange(cfg, code, verifier, nonce);
    await createSession(user.name, user.role, true);
    await recordSsoLogin(user.name, user.role);
    await audit(user.name, "session.login", user.name, `sso · ${user.role} · groups: ${user.groups.join(",")}`);
    return go("/");
  } catch (e) {
    await recordLoginFailure("sso");
    await audit("sso", "session.login.failed", "sso", e instanceof Error ? e.message.slice(0, 200) : "ошибка обмена кода");
    console.warn("oidc callback:", e instanceof Error ? e.message : e);
    // no_role — вход в IdP прошёл, но группы не дают доступа: пользователю нужен администратор, а не повторная попытка.
    return go(e instanceof OidcNoRoleError ? "/login?sso=no_role" : "/login?sso=denied");
  }
}
