"use server";

// Server actions паспорта субъекта (только admin): привязать алиас к
// персоне — существующей или новой — и закрыть алиас (valid_to = сейчас).
// Запись идёт в argus.identities / argus.identity_aliases с source=api.
// Журнал console_audit обязателен и пишется ДО изменения (strict): нет
// журнала — нет изменения; провал записи — вторая запись *.failed.
import { revalidatePath } from "next/cache";
import { authorize } from "./auth";
import type { FormState } from "./actions";
import { audit } from "./argus-queries";
import { bindAlias, closeAlias, getPerson } from "./actors";
import { isAliasKind, parseAliasInput, PERSON_ID_RE, TEXT_MAX, type Person } from "./shared/actors";

export type BindAliasState = FormState & { person_id?: string };

function refreshActors(personId: string): void {
  revalidatePath("/actors");
  revalidatePath(`/actors/${personId}`);
  revalidatePath("/actors/by-alias");
  revalidatePath("/settings");
}

function shortError(scope: string, err: unknown): string {
  console.error(`${scope}:`, err instanceof Error ? err.message : err);
  return "хранилище недоступно — повторите позже";
}

/**
 * Поля: person_id (существующая персона) ИЛИ new_person_id + display (новая);
 * kind, value, from (YYYY-MM-DD или RFC 3339; пусто — сейчас), note.
 */
export async function bindAliasAction(_prev: BindAliasState, formData: FormData): Promise<BindAliasState> {
  const a = await authorize("admin");
  if (!a.ok) return { error: a.error };
  const existing = String(formData.get("person_id") ?? "").trim();
  const newId = String(formData.get("new_person_id") ?? "").trim().toLowerCase();
  const display = String(formData.get("display") ?? "").trim();
  const team = String(formData.get("team") ?? "").trim();
  const kind = String(formData.get("kind") ?? "");
  const parsed = parseAliasInput({ kind, value: formData.get("value"), from: formData.get("from") || undefined, note: formData.get("note") ?? "" });
  if (!parsed.ok) return { error: `Алиас: ${parsed.field ? parsed.field + " — " : ""}${parsed.error}` };
  if (!isAliasKind(kind)) return { error: "Неизвестный вид алиаса" };
  if (display.length > TEXT_MAX || team.length > TEXT_MAX) return { error: `Имя и команда — до ${TEXT_MAX} символов` };
  let person: Person;
  let create = false;
  try {
    if (existing) {
      if (!PERSON_ID_RE.test(existing)) return { error: "Некорректный идентификатор персоны" };
      const p = await getPerson(existing);
      if (!p) return { error: "Персона не найдена" };
      person = p;
    } else {
      if (!PERSON_ID_RE.test(newId)) return { error: "Идентификатор новой персоны: латиница в нижнем регистре, цифры, . _ -, до 64 символов" };
      if (await getPerson(newId)) return { error: "Персона с таким идентификатором уже есть — выберите её в списке" };
      person = { person_id: newId, display: display || newId, kind: formData.get("person_kind") === "service" ? "service" : "person", team, note: "" };
      create = true;
    }
  } catch (err) {
    return { error: shortError("identity.alias", err) };
  }
  // Журнал — до изменения: нет записи — нет привязки.
  try {
    await audit(a.session.user, "identity.alias", person.person_id, `${parsed.alias.kind} = ${parsed.alias.value} · с ${parsed.alias.valid_from ?? "начала истории"}${create ? " · персона создана" : ""}`, { strict: true });
  } catch (err) {
    return { error: err instanceof Error ? err.message : "журнал действий недоступен" };
  }
  try {
    await bindAlias(person, parsed.alias, "api", create);
  } catch (err) {
    await audit(a.session.user, "identity.alias.failed", person.person_id, `${parsed.alias.kind} = ${parsed.alias.value}: ${err instanceof Error ? err.message : "ошибка"}`);
    return { error: shortError("identity.alias", err) };
  }
  refreshActors(person.person_id);
  return { error: null, ok: true, person_id: person.person_id };
}

/** Закрыть алиас: person_id, kind, value → valid_to = сейчас новой версией строки. */
export async function closeAliasAction(formData: FormData): Promise<FormState> {
  const a = await authorize("admin");
  if (!a.ok) return { error: a.error };
  const personId = String(formData.get("person_id") ?? "");
  const kind = String(formData.get("kind") ?? "");
  const value = String(formData.get("value") ?? "").trim();
  if (!PERSON_ID_RE.test(personId)) return { error: "Некорректный идентификатор персоны" };
  if (!isAliasKind(kind) || !value) return { error: "Укажите вид и значение алиаса" };
  try {
    await audit(a.session.user, "identity.alias.close", personId, `${kind} = ${value}`, { strict: true });
  } catch (err) {
    return { error: err instanceof Error ? err.message : "журнал действий недоступен" };
  }
  try {
    const n = await closeAlias(personId, kind, value);
    if (n === 0) {
      await audit(a.session.user, "identity.alias.close.failed", personId, `${kind} = ${value}: действующего алиаса нет`);
      return { error: "Действующего алиаса с таким значением нет" };
    }
  } catch (err) {
    await audit(a.session.user, "identity.alias.close.failed", personId, `${kind} = ${value}: ${err instanceof Error ? err.message : "ошибка"}`);
    return { error: shortError("identity.alias.close", err) };
  }
  refreshActors(personId);
  return { error: null, ok: true };
}
