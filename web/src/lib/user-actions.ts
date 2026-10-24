"use server";

import { revalidatePath } from "next/cache";
import { authorize, createUser, deleteUser, resetUserPassword, type Role } from "./auth";
import type { FormState } from "./actions";
import { audit } from "./argus-queries";

export type CreateUserState = FormState & { password?: string; name?: string };

export async function createUserAction(_prev: CreateUserState, formData: FormData): Promise<CreateUserState> {
  const a = await authorize("admin");
  if (!a.ok) return { error: a.error };
  const name = String(formData.get("name") ?? "").trim().toLowerCase();
  const role = String(formData.get("role") ?? "viewer") as Role;
  const res = await createUser(name, role);
  if ("error" in res) return { error: res.error };
  await audit(a.session.user, "user.create", name, role);
  revalidatePath("/settings");
  // Пароль показывается один раз — как у installation assistant Wazuh.
  return { error: null, ok: true, password: res.password, name };
}

/** Удаление: не себя и не последнего администратора — проверяет deleteUser. */
export async function deleteUserAction(formData: FormData): Promise<FormState> {
  const a = await authorize("admin");
  if (!a.ok) return { error: a.error };
  const name = String(formData.get("name") ?? "");
  const err = await deleteUser(name, a.session.user);
  if (err) return { error: err };
  await audit(a.session.user, "user.delete", name);
  revalidatePath("/settings");
  return { error: null, ok: true };
}

/** Сброс пароля другому пользователю: новый пароль показывается один раз,
 *  его сессии отзываются (tokenVersion). */
export async function resetUserPasswordAction(_prev: CreateUserState, formData: FormData): Promise<CreateUserState> {
  const a = await authorize("admin");
  if (!a.ok) return { error: a.error };
  const name = String(formData.get("name") ?? "");
  const res = await resetUserPassword(name, a.session.user);
  if ("error" in res) return { error: res.error };
  await audit(a.session.user, "user.password.reset", name);
  revalidatePath("/settings");
  return { error: null, ok: true, password: res.password, name };
}
