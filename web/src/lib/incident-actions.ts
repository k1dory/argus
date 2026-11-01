"use server";

import net from "node:net";
import { revalidatePath } from "next/cache";
import { authorize, listUsers } from "./auth";
import type { FormState } from "./actions";
import {
  EXCEPTION_FIELDS,
  addException,
  addIncidentComment,
  audit,
  deactivateException,
  incidentGet,
  incidentTransition,
  IncidentWorkflowError,
  requestReanalyze,
  requestBlockIp,
  requestUnblockIp,
  blockCandidatesFor,
  saveTriageVerdict,
  triageVerdictClaim,
} from "./argus-queries";
import { isIncidentStatus } from "./shared/incidents";
import { closureLabelText, isOpsIncident, parseClosureLabel, type ClosureLabel } from "./shared/closure-label";

const INCIDENT_ID_RE = /^INC-\d{1,9}$/;
const FINAL_STATUSES = new Set(["closed", "false_positive"]);

function refreshIncident(id: string): void {
  revalidatePath("/incidents");
  revalidatePath(`/incidents/${id}`);
  revalidatePath("/settings");
}

/** Ошибки движка/ClickHouse пользователю — коротко; полный текст — в лог сервера. */
function shortError(scope: string, err: unknown): string {
  console.error(`${scope}:`, err instanceof Error ? err.message : err);
  return "хранилище недоступно — повторите позже";
}

export async function setIncidentStatusAction(
  _prev: FormState,
  formData: FormData,
): Promise<FormState> {
  const a = await authorize("analyst");
  if (!a.ok) return { error: a.error };
  const s = a.session;
  const id = String(formData.get("incident_id") ?? "");
  const status = String(formData.get("status") ?? "");
  const reason = String(formData.get("reason") ?? "").trim();
  if (!INCIDENT_ID_RE.test(id)) return { error: "Некорректный идентификатор инцидента" };
  if (!isIncidentStatus(status) || status === "new" || status === "waiting_owner") return { error: "Неизвестный статус" };
  try {
    const inc = await incidentGet(id);
    if (!inc) return { error: "Инцидент не найден" };
    if (inc.owner !== s.user || inc.status === "new" || inc.status === "waiting_owner") {
      return { error: "Сначала возьмите инцидент на себя" };
    }
    if (FINAL_STATUSES.has(inc.status)) return { error: "Инцидент уже завершён" };
    if (FINAL_STATUSES.has(status) && (reason.length < 10 || reason.length > 2000)) return { error: "Для завершения укажите причину от 10 до 2000 символов" };
    // Метка ответа обязательна при завершении: по свободной причине не обучить и
    // не посчитать долю ложных срабатываний. Набор полей — по типу правила.
    let label: ClosureLabel | undefined;
    if (FINAL_STATUSES.has(status)) {
      const parsed = parseClosureLabel((name) => String(formData.get(name) ?? ""), { ops: isOpsIncident(inc.tags), status });
      if (typeof parsed === "string") return { error: parsed };
      label = parsed;
    }
    // Сначала исключения, потом статус: если статус записался, а исключения
    // нет, движок заведёт тот же инцидент снова. Обратный порядок безопасен —
    // исключение без статуса лишь подавит правило, а статус можно поставить ещё раз.
    if (status === "false_positive") {
      const values: Record<string, string> = { "actor.name": inc.actor_name, node: inc.node };
      for (const field of EXCEPTION_FIELDS) {
        if (formData.get(`exc_${field}`) !== "1") continue;
        const value = String(formData.get(`excv_${field}`) ?? values[field] ?? "").trim();
        if (!value) continue;
        await addException({ rule_id: inc.rule_id, field, value, reason: "ложное срабатывание", incident_id: id, created_by: s.user });
        await audit(s.user, "rule.exception", inc.rule_id, `${field} = ${value} (из ${id})`);
      }
    }
    await incidentTransition({ id, kind: "status", status, reason, actor: s.user, role: s.role, label });
    const labelText = label ? closureLabelText(label) : "";
    await audit(s.user, "incident.status", id, `${inc.status} → ${status} · ${s.user}${labelText ? ` · ${labelText}` : ""}${reason ? ` · ${reason}` : ""}`);
  } catch (err) {
	if (err instanceof IncidentWorkflowError) return { error: err.message };
    return { error: shortError("incident.status", err) };
  }
  refreshIncident(id);
  return { error: null, ok: true };
}

export async function takeIncidentAction(_prev: FormState, formData: FormData): Promise<FormState> {
  const a = await authorize("analyst");
  if (!a.ok) return { error: a.error };
  const id = String(formData.get("incident_id") ?? "");
  if (!INCIDENT_ID_RE.test(id)) return { error: "Некорректный идентификатор инцидента" };
  try {
    const inc = await incidentGet(id);
    if (!inc) return { error: "Инцидент не найден" };
    if (FINAL_STATUSES.has(inc.status)) return { error: "Инцидент уже завершён" };
    if (inc.owner && inc.owner !== a.session.user) return { error: `Уже назначен: ${inc.owner}` };
    await incidentTransition({ id, kind: "take", actor: a.session.user, role: a.session.role });
    await audit(a.session.user, "incident.take", id, "взял в работу");
  } catch (err) {
	if (err instanceof IncidentWorkflowError) return { error: err.message };
    return { error: shortError("incident.take", err) };
  }
  refreshIncident(id);
  return { error: null, ok: true };
}

export async function assignIncidentAction(_prev: FormState, formData: FormData): Promise<FormState> {
  const a = await authorize("admin");
  if (!a.ok) return { error: a.error };
  const id = String(formData.get("incident_id") ?? "");
  const owner = String(formData.get("owner") ?? "").trim();
  if (!INCIDENT_ID_RE.test(id)) return { error: "Некорректный идентификатор инцидента" };
  if (!owner || owner.length > 120) return { error: "Выберите ответственного" };
  try {
    const users = await listUsers();
    // Ответственный — аналитик или администратор (в маленькой команде разбирают и
    // они), локальный или вошедший через SSO; наблюдателю инцидент не отдаётся.
    if (!users.some((u) => u.name === owner && (u.role === "analyst" || u.role === "admin"))) return { error: "Выберите аналитика или администратора из списка" };
    const inc = await incidentGet(id);
    if (!inc) return { error: "Инцидент не найден" };
    if (FINAL_STATUSES.has(inc.status)) return { error: "Инцидент уже завершён" };
    if (inc.owner === owner) return { error: "Этот сотрудник уже назначен" };
    // Первое назначение не является реакцией: срок продолжает идти, пока
    // аналитик сам не нажмёт «Взять в работу». Передача после реакции ждёт
    // принятия новым ответственным, но не обнуляет первичный SLA.
    await incidentTransition({ id, kind: "assign", owner, actor: a.session.user, role: a.session.role });
    await audit(a.session.user, "incident.assign", id, `${inc.owner || "без ответственного"} → ${owner}`);
  } catch (err) {
	if (err instanceof IncidentWorkflowError) return { error: err.message };
    return { error: shortError("incident.assign", err) };
  }
  refreshIncident(id);
  return { error: null, ok: true };
}

export async function addIncidentCommentAction(_prev: FormState, formData: FormData): Promise<FormState> {
  const a = await authorize("analyst");
  if (!a.ok) return { error: a.error };
  const id = String(formData.get("incident_id") ?? "");
  const body = String(formData.get("body") ?? "").trim();
  if (!INCIDENT_ID_RE.test(id)) return { error: "Некорректный идентификатор инцидента" };
  if (!body || body.length > 8000) return { error: "Запись Markdown должна быть от 1 до 8000 символов" };
  try {
    if (!await incidentGet(id)) return { error: "Инцидент не найден" };
    await addIncidentComment(id, a.session.user, body);
    await audit(a.session.user, "incident.comment", id, `добавлен комментарий (${body.length} символов)`);
  } catch (err) {
    return { error: shortError("incident.comment", err) };
  }
  revalidatePath(`/incidents/${id}`);
  return { error: null, ok: true };
}

export async function reanalyzeAction(_prev: FormState, formData: FormData): Promise<FormState> {
  const a = await authorize("analyst");
  if (!a.ok) return { error: a.error };
  const id = String(formData.get("incident_id") ?? "");
  if (!INCIDENT_ID_RE.test(id)) return { error: "Некорректный идентификатор" };
  const err = await requestReanalyze(id);
  if (err) return { error: "Переразбор не запущен: " + err };
  await audit(a.session.user, "incident.reanalyze", id);
  return { error: null, ok: true };
}

export async function removeExceptionAction(formData: FormData): Promise<FormState> {
  const a = await authorize("analyst");
  if (!a.ok) return { error: a.error };
  const rule = String(formData.get("rule_id") ?? "");
  const field = String(formData.get("field") ?? "");
  const value = String(formData.get("value") ?? "");
  if (!rule || !field || !value) return { error: "Не указано исключение" };
  try {
    await deactivateException(rule, field, value, a.session.user);
  } catch (err) {
    return { error: shortError("exception.remove", err) };
  }
  await audit(a.session.user, "rule.exception.remove", rule, `${field} = ${value}`);
  revalidatePath("/settings");
  return { error: null, ok: true };
}

/** Блокировка адреса оператором. Адрес не берётся из формы как есть — он
 *  должен быть среди публичных адресов цепочки инцидента (карточка предлагает
 *  только их); причина обязательна и уходит в журнал реагирования движка. */
export async function blockIpAction(_prev: FormState, formData: FormData): Promise<FormState> {
  const a = await authorize("analyst");
  if (!a.ok) return { error: a.error };
  const s = a.session;
  const id = String(formData.get("incident_id") ?? "");
  const ip = String(formData.get("ip") ?? "").trim();
  const reason = String(formData.get("reason") ?? "").trim().slice(0, 500);
  if (!INCIDENT_ID_RE.test(id) || net.isIP(ip) === 0) return { error: "Некорректный инцидент или адрес" };
  if (!reason) return { error: "Укажите причину блокировки — она попадёт в журнал реагирования" };
  let inc;
  try {
    inc = await incidentGet(id);
  } catch (err) {
    return { error: shortError("block_ip.incident", err) };
  }
  if (!inc) return { error: "Инцидент не найден" };
  const candidates = blockCandidatesFor(inc);
  if (!candidates.includes(ip)) return { error: "Адрес не относится к этому инциденту — блокировать можно только адреса из его цепочки" };
  // Аудит строго ДО вызова движка (как в unblock): блокировка без записи
  // «кто и почему» недопустима; результат — второй записью.
  try {
    await audit(s.user, "respond.block_ip", ip, `запрос · ${id} · ${reason}`, { strict: true });
  } catch (err) {
    return { error: err instanceof Error ? err.message : "журнал действий недоступен" };
  }
  const res = await requestBlockIp(id, ip, `${reason} (оператор ${s.user})`, s.user);
  // Some executors may have succeeded even when another one failed.
  refreshIncident(id);
  const detail = (res.results ?? []).map((r) => `${r.executor}: ${r.ok ? "ok" : "ошибка"} · ${r.detail}`).join("; ");
  await audit(s.user, "respond.block_ip", ip, `${id} · ${res.error ?? (detail || "ok")}`);
  if (res.error) return { error: res.error };
  const failed = (res.results ?? []).filter((r) => !r.ok);
  if (failed.length > 0) return { error: failed.map((r) => `${r.executor}: ${r.detail}`).join("; ") };
  return { error: null, ok: true };
}

/** Снятие блокировки: POST ${ENGINE_URL}/respond/unblock {ip, user, reason}.
 *  Аудит пишется строго ДО вызова движка — разблокировка без записи «кто и
 *  почему» недопустима; результат — второй записью. */
export async function unblockIpAction(_prev: FormState, formData: FormData): Promise<FormState> {
  const a = await authorize("analyst");
  if (!a.ok) return { error: a.error };
  const s = a.session;
  const ip = String(formData.get("ip") ?? "").trim();
  const reason = String(formData.get("reason") ?? "").trim().slice(0, 500);
  if (net.isIP(ip) === 0) return { error: "Некорректный адрес" };
  if (!reason) return { error: "Укажите причину снятия блокировки" };
  try {
    await audit(s.user, "respond.unblock_ip", ip, `запрос · ${reason}`, { strict: true });
  } catch (err) {
    return { error: err instanceof Error ? err.message : "журнал действий недоступен" };
  }
  const res = await requestUnblockIp(ip, s.user, reason);
  revalidatePath("/settings");
  const id = String(formData.get("incident_id") ?? "");
  if (INCIDENT_ID_RE.test(id)) revalidatePath(`/incidents/${id}`);
  const detail = (res.results ?? []).map((r) => `${r.executor}: ${r.ok ? "ok" : "ошибка"} · ${r.detail}`).join("; ");
  await audit(s.user, "respond.unblock_ip", ip, res.error ?? (detail || "ok"));
  if (res.error) return { error: res.error };
  const failed = (res.results ?? []).filter((r) => !r.ok);
  if (failed.length > 0) return { error: failed.map((r) => `${r.executor}: ${r.detail}`).join("; ") };
  return { error: null, ok: true };
}

/** Та же разблокировка для форм без useActionState (ConfirmForm). */
export async function unblockIpFormAction(formData: FormData): Promise<FormState> {
  return unblockIpAction({ error: null }, formData);
}

/** Разрешить повторный разбор агентом: снять отметку «вердикт записан» с
 *  инцидента (новое поколение — reopened в журнале triage_verdicts). Только
 *  человек с ролью аналитика: агент и его токен снять отметку не могут. */
export async function reopenTriageAction(_prev: FormState, formData: FormData): Promise<FormState> {
  const a = await authorize("analyst");
  if (!a.ok) return { error: a.error };
  const id = String(formData.get("incident_id") ?? "");
  if (!INCIDENT_ID_RE.test(id)) return { error: "Некорректный идентификатор инцидента" };
  try {
    const claim = await triageVerdictClaim(id);
    if (!claim) return { error: "Записанного вердикта агента нет" };
    await saveTriageVerdict({ incidentId: id, state: "reopened", sessionId: claim.session_id, actor: a.session.user });
    await audit(a.session.user, "triage.reopen", id, `повторный разбор разрешён: отметка сессии ${claim.session_id} снята`);
  } catch (err) {
    return { error: shortError("triage.reopen", err) };
  }
  refreshIncident(id);
  return { error: null, ok: true };
}
