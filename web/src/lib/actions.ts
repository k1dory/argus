"use server";

import { redirect } from "next/navigation";
import { safeNextPath } from "./shared/next-path";
import { revalidatePath } from "next/cache";
import QRCode from "qrcode";
import {
  beginTotpEnrollment,
  beginLoginTotp,
  changePassword,
  clearLoginTotp,
  confirmTotpEnrollment,
  createSession,
  destroySession,
  disableTotp,
  getSession,
  loginThrottled,
  isTotpEnabled,
  pendingLoginTotp,
  recordLoginFailure,
  requireRole,
  totpLockRemainingMs,
  verifyCredentials,
  verifyLoginTotp,
  type Session,
} from "./auth";
import { otpauthUri } from "./totp";
import { setRuleMuted } from "./queries";
import { audit } from "./argus-queries";

export type FormState = { error: string | null; ok?: boolean; requiresTotp?: boolean; totpUser?: string };

export async function loginAction(_prev: FormState, formData: FormData): Promise<FormState> {
  if (formData.get("step") === "totp") {
    const challenge = await pendingLoginTotp();
    if (!challenge) {
      await clearLoginTotp();
      return { error: "Проверка истекла — введите логин и пароль снова" };
    }
    const { user, role } = challenge;
    if (await loginThrottled(user)) {
      return { error: "Слишком много неудачных попыток — подождите несколько минут", requiresTotp: true, totpUser: user };
    }
    const totpResult = await verifyLoginTotp(user, String(formData.get("totp") ?? ""));
    if (totpResult === "locked") {
      const min = Math.ceil(totpLockRemainingMs(user) / 60000);
      await audit(user, "session.login.failed", user, "TOTP заблокирован");
      return { error: `Слишком много неверных кодов — вход по TOTP заблокирован на ${min} мин`, requiresTotp: true, totpUser: user };
    }
    if (totpResult !== "ok") {
      if (totpResult === "invalid") await recordLoginFailure(user);
      await audit(user, "session.login.failed", user, "неверный код TOTP");
      return { error: totpResult === "required" ? "Введите код из приложения" : "Неверный код TOTP", requiresTotp: true, totpUser: user };
    }
    await clearLoginTotp();
    await createSession(user, role);
    await audit(user, "session.login", user, role);
    const s = await getSession();
    redirect(s?.mustChangePassword ? "/settings?force=1" : safeNextPath(formData.get("next")));
  }
  await clearLoginTotp();
  const user = String(formData.get("user") ?? "").trim().toLowerCase().slice(0, 64);
  if (await loginThrottled(user)) {
    return { error: "Слишком много неудачных попыток — подождите несколько минут" };
  }
  const password = String(formData.get("password") ?? "");
  const role = await verifyCredentials(user, password);
  if (!role) {
    await recordLoginFailure(user);
    await audit(user || "-", "session.login.failed", user || "-", "неверный логин или пароль");
    return { error: "Неверный логин или пароль" };
  }
  if (await isTotpEnabled(user)) {
    await beginLoginTotp(user);
    return { error: null, requiresTotp: true, totpUser: user };
  }
  await createSession(user, role);
  await audit(user, "session.login", user, role);
  const s = await getSession();
  redirect(s?.mustChangePassword ? "/settings?force=1" : safeNextPath(formData.get("next")));
}

export async function logoutAction(): Promise<void> {
  await destroySession();
  redirect("/login");
}

/** Локальная сессия для операций с паролем/2FA: SSO-пользователь их не имеет. */
async function requireLocalSession(): Promise<{ session: Session } | { error: string }> {
  const s = await getSession();
  if (!s) redirect("/login");
  if (s.sso) return { error: "Пароль и 2FA SSO-пользователя управляются в IdP" };
  return { session: s };
}

export async function changePasswordAction(
  _prev: FormState,
  formData: FormData,
): Promise<FormState> {
  const r = await requireLocalSession();
  if ("error" in r) return { error: r.error };
  const current = String(formData.get("current") ?? "");
  const next = String(formData.get("next") ?? "");
  const confirm = String(formData.get("confirm") ?? "");
  if (next !== confirm) {
    return { error: "Новый пароль и подтверждение не совпадают" };
  }
  const error = await changePassword(r.session.user, current, next);
  if (error) return { error };
  // Смена пароля инкрементирует tokenVersion (отзыв сессий пользователя) —
  // переоформляем текущую, чтобы не выкинуло.
  await createSession(r.session.user, r.session.role);
  await audit(r.session.user, "user.password", r.session.user, "смена пароля");
  revalidatePath("/settings");
  return { error: null, ok: true };
}

/* ===== TOTP ===== */

export type TotpEnrollState = FormState & { secret?: string; qrDataUrl?: string };

// Сигнатура (prev, formData) нужна useActionState; аргументы не используются.
// eslint-disable-next-line @typescript-eslint/no-unused-vars
export async function beginTotpAction(_prev: TotpEnrollState, _formData: FormData): Promise<TotpEnrollState> {
  const r = await requireLocalSession();
  if ("error" in r) return { error: r.error };
  if (r.session.mustChangePassword) return { error: "Сначала смените стартовый пароль" };
  const res = await beginTotpEnrollment(r.session.user);
  if ("error" in res) return { error: res.error };
  const uri = otpauthUri(r.session.user, "ARGUS SIEM", res.secret);
  const qrDataUrl = await QRCode.toDataURL(uri, { margin: 1, width: 220 });
  return { error: null, secret: res.secret, qrDataUrl };
}

export async function confirmTotpAction(
  _prev: FormState,
  formData: FormData,
): Promise<FormState> {
  const r = await requireLocalSession();
  if ("error" in r) return { error: r.error };
  if (r.session.mustChangePassword) return { error: "Сначала смените стартовый пароль" };
  const error = await confirmTotpEnrollment(r.session.user, String(formData.get("code") ?? ""));
  if (error) return { error };
  await audit(r.session.user, "user.totp", r.session.user, "включён");
  revalidatePath("/settings");
  return { error: null, ok: true };
}

export async function disableTotpAction(
  _prev: FormState,
  formData: FormData,
): Promise<FormState> {
  const r = await requireLocalSession();
  if ("error" in r) return { error: r.error };
  if (r.session.mustChangePassword) return { error: "Сначала смените стартовый пароль" };
  const error = await disableTotp(r.session.user, String(formData.get("password") ?? ""), String(formData.get("code") ?? ""));
  if (error) return { error };
  await audit(r.session.user, "user.totp", r.session.user, "отключён");
  revalidatePath("/settings");
  return { error: null, ok: true };
}

/* ===== Мьюты правил (борьба с шумом) ===== */

export async function muteRuleAction(formData: FormData): Promise<void> {
  const s = await requireRole("analyst");
  const ruleId = Number(formData.get("rule_id"));
  const muted = formData.get("muted") === "1";
  if (!Number.isInteger(ruleId) || ruleId < 0) return;
  await setRuleMuted(ruleId, muted);
  await audit(s.user, "rule.mute", String(ruleId), muted ? "muted" : "unmuted");
  revalidatePath("/wazuh/alerts");
  revalidatePath("/settings");
  revalidatePath("/");
}
