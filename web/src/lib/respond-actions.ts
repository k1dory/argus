"use server";

import { revalidatePath } from "next/cache";
import { authorize } from "./auth";
import { audit, setRespondMode } from "./argus-queries";
import { isRespondMode } from "./shared/respond";
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
