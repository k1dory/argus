"use server";

// Управляющий контур: все действия ходят в Wazuh manager API от имени
// сервисного пользователя (env WAZUH_API_*). Роли: рестарт менеджера, правка
// agent.conf/правил и удаление групп — только admin; агенты и создание групп —
// analyst. Каждое действие — запись в журнал console_audit; для XML в detail
// идут первые 8 hex sha256 содержимого, чтобы сверять версии по журналу.
import crypto from "crypto";
import { revalidatePath } from "next/cache";
import { authorize } from "./auth";
import type { FormState } from "./actions";
import { audit } from "./argus-queries";
import { checkXmlRoots, formatXmlError, validateXml } from "./shared/xml";
import { GROUP_NAME_RE, RULE_FILE_RE } from "./shared/wazuh-names";
import {
  addAgentToGroup,
  createGroup,
  deleteGroup,
  managerConfigValidation,
  putGroupConf,
  putRuleFile,
  removeAgentFromGroup,
  restartAgent,
  restartManager,
  WazuhApiError,
} from "./wazuh-api";

/** Ошибки TLS-рукопожатия node: коды OpenSSL и текст ошибок сертификата. */
const TLS_ERR_RE = /CERT_|SELF_SIGNED|SELF SIGNED|self.signed|certificate|ERR_TLS_|UNABLE_TO_VERIFY|wrong version number|ssl3_|tls_|handshake/i;

/** Текст ошибки пользователю. Известные случаи (ответ API, нет соединения,
 *  TLS, таймаут) — понятной строкой; всё прочее — только в лог сервера,
 *  пользователю общая фраза: сырой текст исключения может содержать URL
 *  и внутренности транспорта. */
function message(err: unknown): string {
  if (err instanceof WazuhApiError) return err.message;
  const text = err instanceof Error ? err.message : String(err);
  const code = (err as { code?: string } | null)?.code ?? "";
  if (/ECONNREFUSED|ENOTFOUND|EAI_AGAIN|ECONNRESET|EHOSTUNREACH/.test(text + " " + code)) {
    return "Wazuh API недоступен — проверьте WAZUH_API_URL";
  }
  if (TLS_ERR_RE.test(text + " " + code)) {
    return "Wazuh API: ошибка TLS — сертификат менеджера не прошёл проверку (WAZUH_INSECURE_TLS=true для самоподписанного)";
  }
  if (/^Wazuh API: /.test(text)) return text; // свои таймауты из wazuh-api.ts
  console.error("wazuh api:", err instanceof Error ? `${err.name}: ${err.message}` : err);
  return "Wazuh API: ошибка запроса — подробности в логе консоли";
}

const AGENT_ID_RE = /^\d{1,10}$/;
const MAX_XML_BYTES = 1_000_000;

const sha8 = (s: string): string => crypto.createHash("sha256").update(s).digest("hex").slice(0, 8);

function checkXml(xml: string): string | null {
  if (Buffer.byteLength(xml) > MAX_XML_BYTES) return "Файл больше 1 МБ";
  const err = validateXml(xml);
  return err ? `XML некорректен — ${formatXmlError(err)}` : null;
}

/* ===== Менеджер ===== */

export async function restartManagerAction(): Promise<FormState> {
  const a = await authorize("admin");
  if (!a.ok) return { error: a.error };
  try {
    await restartManager();
  } catch (err) {
    const m = message(err);
    await audit(a.session.user, "wazuh.manager.restart", "manager", "ошибка: " + m);
    return { error: m };
  } finally {
    revalidatePath("/wazuh/manage");
  }
  await audit(a.session.user, "wazuh.manager.restart", "manager");
  return { error: null, ok: true };
}

/* ===== Агенты ===== */

export async function restartAgentAction(formData: FormData): Promise<FormState> {
  const a = await authorize("analyst");
  if (!a.ok) return { error: a.error };
  const agentId = String(formData.get("agent_id") ?? "");
  if (!AGENT_ID_RE.test(agentId) || agentId === "000") return { error: "Некорректный id агента" };
  try {
    await restartAgent(agentId);
  } catch (err) {
    const m = message(err);
    await audit(a.session.user, "wazuh.agent.restart", agentId, "ошибка: " + m);
    return { error: m };
  } finally {
    revalidatePath("/wazuh/manage");
  }
  await audit(a.session.user, "wazuh.agent.restart", agentId);
  return { error: null, ok: true };
}

export async function agentGroupAction(formData: FormData): Promise<FormState> {
  const a = await authorize("analyst");
  if (!a.ok) return { error: a.error };
  const agentId = String(formData.get("agent_id") ?? "");
  const group = String(formData.get("group_id") ?? "");
  const op = formData.get("op") === "remove" ? "remove" : "add";
  if (!AGENT_ID_RE.test(agentId) || !GROUP_NAME_RE.test(group)) return { error: "Некорректный агент или группа" };
  try {
    if (op === "remove") await removeAgentFromGroup(agentId, group);
    else await addAgentToGroup(agentId, group);
  } catch (err) {
    const m = message(err);
    await audit(a.session.user, `wazuh.agent.group.${op}`, agentId, `${group} · ошибка: ${m}`);
    return { error: m };
  } finally {
    revalidatePath("/wazuh/manage");
    revalidatePath(`/wazuh/manage/groups/${group}`);
  }
  await audit(a.session.user, `wazuh.agent.group.${op}`, agentId, group);
  return { error: null, ok: true };
}

/* ===== Группы ===== */

export async function createGroupAction(
  _prev: FormState,
  formData: FormData,
): Promise<FormState> {
  const a = await authorize("analyst");
  if (!a.ok) return { error: a.error };
  const name = String(formData.get("name") ?? "").trim();
  if (!GROUP_NAME_RE.test(name)) {
    return { error: "Имя группы: латиница, цифры, точка, дефис, подчёркивание" };
  }
  try {
    await createGroup(name);
  } catch (err) {
    const m = message(err);
    await audit(a.session.user, "wazuh.group.create", name, "ошибка: " + m);
    return { error: m };
  }
  await audit(a.session.user, "wazuh.group.create", name);
  revalidatePath("/wazuh/manage/groups");
  return { error: null, ok: true };
}

export async function deleteGroupAction(formData: FormData): Promise<FormState> {
  const a = await authorize("admin");
  if (!a.ok) return { error: a.error };
  const name = String(formData.get("name") ?? "");
  if (!GROUP_NAME_RE.test(name)) return { error: "Некорректное имя группы" };
  if (name === "default") return { error: "Группу default удалить нельзя" };
  try {
    await deleteGroup(name);
  } catch (err) {
    const m = message(err);
    await audit(a.session.user, "wazuh.group.delete", name, "ошибка: " + m);
    return { error: m };
  } finally {
    revalidatePath("/wazuh/manage/groups");
    revalidatePath("/wazuh/manage");
  }
  await audit(a.session.user, "wazuh.group.delete", name);
  return { error: null, ok: true };
}

export async function saveGroupConfAction(
  _prev: FormState,
  formData: FormData,
): Promise<FormState> {
  const a = await authorize("admin");
  if (!a.ok) return { error: a.error };
  const group = String(formData.get("group") ?? "");
  const xml = String(formData.get("xml") ?? "");
  if (!GROUP_NAME_RE.test(group)) return { error: "Некорректное имя группы" };
  const xmlErr = checkXml(xml);
  if (xmlErr) return { error: xmlErr };
  const rootErr = checkXmlRoots(xml, "agent_config");
  if (rootErr) return { error: `agent.conf: ${rootErr}` };
  try {
    await putGroupConf(group, xml);
  } catch (err) {
    const m = message(err);
    await audit(a.session.user, "wazuh.group.conf", group, `ошибка: ${m} · sha256:${sha8(xml)}`);
    return { error: m };
  }
  await audit(a.session.user, "wazuh.group.conf", group, `sha256:${sha8(xml)}`);
  revalidatePath(`/wazuh/manage/groups/${group}`);
  return { error: null, ok: true };
}

/* ===== Правила ===== */

/** Результат сохранения правил: после записи менеджер проверяет конфигурацию
 *  целиком — рестарт с битым правилом положил бы analysisd. */
export type SaveRuleState = FormState & { validation?: { ok: boolean; detail: string } };

export async function saveRuleFileAction(
  _prev: SaveRuleState,
  formData: FormData,
): Promise<SaveRuleState> {
  const a = await authorize("admin");
  if (!a.ok) return { error: a.error };
  const filename = String(formData.get("filename") ?? "").trim();
  const xml = String(formData.get("xml") ?? "");
  if (!RULE_FILE_RE.test(filename)) {
    return { error: "Имя файла: латиница/цифры/._- и расширение .xml" };
  }
  const xmlErr = checkXml(xml);
  if (xmlErr) return { error: xmlErr };
  const rootErr = checkXmlRoots(xml, "group");
  if (rootErr) return { error: `файл правил: ${rootErr}` };
  try {
    await putRuleFile(filename, xml);
  } catch (err) {
    const m = message(err);
    await audit(a.session.user, "wazuh.rules.save", filename, `ошибка: ${m} · sha256:${sha8(xml)}`);
    return { error: m };
  }
  await audit(a.session.user, "wazuh.rules.save", filename, `sha256:${sha8(xml)}`);
  revalidatePath("/wazuh/manage/rules");
  revalidatePath(`/wazuh/manage/rules/${filename}`);
  const validation = await managerConfigValidation();
  await audit(a.session.user, "wazuh.rules.validate", filename, validation.ok ? "OK" : "ошибка: " + validation.detail.slice(0, 300));
  return { error: null, ok: true, validation };
}
