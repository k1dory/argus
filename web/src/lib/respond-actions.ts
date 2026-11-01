"use server";

import net from "node:net";
import { revalidatePath } from "next/cache";
import { authorize } from "./auth";
import { audit, requestExcludeIp, requestRevokeExclusion, setRespondMode } from "./argus-queries";
import { EXCLUDE_TTLS, isRespondMode } from "./shared/respond";
import type { FormState } from "./actions";

/** Режим реагирования переключает только администратор. Аудит пишется ДО
 *  переключения: включение автоблокировки без записи «кто» недопустимо. */
export async function setRespondModeAction(_prev: FormState, formData: FormData): Promise<FormState> {
  const a = await authorize("admin");
  if (!a.ok) return { error: a.error };
  const s = a.session;
  // Кнопка «Вернуть» — отдельное поле: submitter вставляется после радио, get("mode") вернул бы отмеченный режим
  const mode = formData.get("reset") === "1" ? "" : String(formData.get("mode") ?? "");
  if (mode !== "" && !isRespondMode(mode)) return { error: "Неизвестный режим" };
  try {
    await audit(s.user, "respond.mode", mode || "config", mode === "ips" ? "включена автоблокировка" : mode || "вернуть режим из конфига движка", { strict: true });
    await setRespondMode(mode, s.user);
  } catch (err) {
    console.error("respond.mode:", err instanceof Error ? err.message : err);
    return { error: err instanceof Error && /журнал/.test(err.message) ? err.message : "хранилище недоступно — режим не изменён" };
  }
  revalidatePath("/settings");
  return { error: null, ok: true };
}

/** Исключить адрес из автоблокировки на срок — только администратор, со сроком из
 *  EXCLUDE_TTLS и причиной. В отличие от снятия блока, действует на все инциденты
 *  адреса, в том числе будущие; поэтому аудит — строго ДО вызова движка. */
export async function excludeIpAction(formData: FormData): Promise<FormState> {
  const a = await authorize("admin");
  if (!a.ok) return { error: a.error };
  const s = a.session;
  const ip = String(formData.get("ip") ?? "").trim();
  const ttl = String(formData.get("ttl") ?? "");
  const reason = String(formData.get("reason") ?? "").trim().slice(0, 500);
  if (net.isIP(ip) === 0) return { error: "Некорректный адрес" };
  if (!EXCLUDE_TTLS.some((t) => t.value === ttl)) return { error: "Выберите срок исключения" };
  if (reason.length < 3) return { error: "Укажите причину исключения — она попадёт в журнал реагирования" };
  try {
    await audit(s.user, "respond.exclude_ip", ip, `запрос · ${ttl} · ${reason}`, { strict: true });
  } catch (err) {
    return { error: err instanceof Error ? err.message : "журнал действий недоступен" };
  }
  const res = await requestExcludeIp(ip, ttl, s.user, reason);
  await audit(s.user, "respond.exclude_ip", ip, res.error ?? `до ${String((res as { until?: string }).until ?? "?")}`);
  revalidatePath("/settings");
  if (res.error) return { error: res.error };
  return { error: null, ok: true };
}

/** Отозвать исключение адреса — только администратор, с причиной. */
export async function revokeExclusionAction(formData: FormData): Promise<FormState> {
  const a = await authorize("admin");
  if (!a.ok) return { error: a.error };
  const s = a.session;
  const ip = String(formData.get("ip") ?? "").trim();
  const reason = String(formData.get("reason") ?? "").trim().slice(0, 500);
  if (net.isIP(ip) === 0) return { error: "Некорректный адрес" };
  if (reason.length < 3) return { error: "Укажите причину отзыва" };
  try {
    await audit(s.user, "respond.exclude_revoke", ip, `запрос · ${reason}`, { strict: true });
  } catch (err) {
    return { error: err instanceof Error ? err.message : "журнал действий недоступен" };
  }
  const res = await requestRevokeExclusion(ip, s.user, reason);
  await audit(s.user, "respond.exclude_revoke", ip, res.error ?? "ok");
  revalidatePath("/settings");
  if (res.error) return { error: res.error };
  return { error: null, ok: true };
}
