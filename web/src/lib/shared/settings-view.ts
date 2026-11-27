// Страница «Настройки»: вкладки, человеческие подписи журнала действий и
// заголовки строк журнала реагирования. Чистые функции — их проверяют тесты.
import type { Tone } from "@/components/console/tone";

export const SETTINGS_TABS = [
  { key: "account", label: "Учётная запись" },
  { key: "users", label: "Пользователи" },
  { key: "respond", label: "Реагирование" },
  { key: "exceptions", label: "Исключения" },
  { key: "audit", label: "Журнал действий" },
  { key: "system", label: "Система" },
] as const;
export type SettingsTab = (typeof SETTINGS_TABS)[number]["key"];

export function parseSettingsTab(v: unknown): SettingsTab {
  return SETTINGS_TABS.some((t) => t.key === v) ? (v as SettingsTab) : "account";
}

const AUDIT_LABELS: Record<string, string> = {
  "actor.lookup": "искал субъекта",
  "actor.view": "открыл карточку субъекта",
  "dashboard.create": "создал дашборд",
  "dashboard.delete": "удалил дашборд",
  "dashboard.save": "сохранил дашборд",
  "identity.alias": "связал учётные записи",
  "identity.alias.close": "закрыл связь учётных записей",
  "identity.alias.confirm": "подтвердил связь учётных записей",
  "identity.import": "импортировал справочник сотрудников",
  "incident.assign": "назначил инцидент",
  "incident.comment": "прокомментировал инцидент",
  "incident.group": "сгруппировал инциденты",
  "incident.reanalyze": "запросил повторный разбор",
  "incident.status": "сменил статус инцидента",
  "incident.take": "взял инцидент в работу",
  "respond.block_ip": "заблокировал адрес",
  "respond.exclude_ip": "исключил адрес из автоблокировки",
  "respond.exclude_revoke": "отозвал исключение адреса",
  "respond.mode": "сменил режим реагирования",
  "respond.unblock_ip": "снял блокировку адреса",
  "rule.exception": "добавил исключение из правила",
  "rule.exception.remove": "снял исключение из правила",
  "rule.mute": "заглушил или вернул правило Wazuh",
  "session.login": "вошёл в консоль",
  "session.login.failed": "неудачный вход",
  "session.totp.lock": "вход заблокирован: много неверных кодов 2FA",
  "triage.reopen": "переоткрыл разбор",
  "triage.session": "агент начал сессию разбора",
  "triage.session.revoke": "отозвал сессию агента",
  "triage.verdict": "вердикт агента",
  "triage.verdict_conflict": "вердикт агента расходится с человеком",
  "user.create": "создал пользователя",
  "user.delete": "удалил пользователя",
  "user.password": "сменил пароль",
  "user.password.reset": "сбросил пароль пользователю",
  "user.totp": "настроил 2FA",
  "wazuh.agent.restart": "перезапустил агента Wazuh",
  "wazuh.group.conf": "изменил конфигурацию группы Wazuh",
  "wazuh.group.create": "создал группу Wazuh",
  "wazuh.group.delete": "удалил группу Wazuh",
  "wazuh.manager.restart": "перезапустил менеджер Wazuh",
  "wazuh.rules.save": "сохранил правила Wazuh",
  "wazuh.rules.validate": "проверил правила Wazuh",
};

/** Подпись действия журнала; неизвестное — как есть. failed-вариант — «не удалось: …». */
export function auditActionLabel(action: string): { label: string; failed: boolean } {
  const failed = action.endsWith(".failed") && action !== "session.login.failed";
  const base = failed ? action.slice(0, -".failed".length) : action;
  const label = AUDIT_LABELS[action] ?? AUDIT_LABELS[base];
  if (!label) return { label: action, failed: failed || action === "session.login.failed" };
  return { label: failed ? `не удалось: ${label}` : label, failed: failed || action === "session.login.failed" };
}

export type ResponseRowLike = { ip: string; mode: string; executor: string; dry_run: number; ok: number; detail: string };

export type ResponseView = {
  /** Заголовок строки ленты. */
  title: string;
  /** Тон иконки и подсветки. */
  tone: Tone;
  /** Отказ — строка выделяется. */
  flagged: boolean;
  /** Пояснение во второй строке (технический detail без «POST»); пусто, если ушёл в заголовок. */
  note: string;
  kind: "block" | "unblock" | "engine" | "simulate";
};

const HTTP_VERB = /^(GET|POST|PUT|DELETE|PATCH)$/;

/** Строка журнала реагирования человеческим языком: «Заблокирован 203.0.113.7 на ngfw.edge». */
export function responseView(r: ResponseRowLike): ResponseView {
  const ip = r.ip || "адрес";
  const note = HTTP_VERB.test(r.detail.trim()) ? "" : r.detail;
  const simulated = Boolean(r.dry_run) || r.mode === "simulate";
  if (r.executor === "argus" || r.executor === "") {
    // Решение самого движка: ожидание, повтор, «уже заблокирован» — заголовок коротко, подробности строкой ниже.
    const d = r.detail.trim();
    if (/^ожидание/.test(d)) return { title: r.ip ? `Блокировка ${r.ip} отложена` : "Блокировка отложена", tone: "warn", flagged: false, note: d, kind: "engine" };
    if (/^уже заблокирован/.test(d)) return { title: `${ip} уже заблокирован`, tone: "neutral", flagged: false, note: d.replace(/^уже заблокирован\s*/, ""), kind: "engine" };
    if (!r.ok) return { title: r.ip ? `Не удалось заблокировать ${r.ip}` : "Не удалось заблокировать адрес", tone: "err", flagged: true, note: d, kind: "engine" };
    return { title: r.ip ? `Решение движка по ${r.ip}` : "Решение движка", tone: "neutral", flagged: false, note: d, kind: "engine" };
  }
  if (r.executor.endsWith(".unblock")) {
    const where = r.executor.slice(0, -".unblock".length);
    return r.ok
      ? { title: `Разблокирован ${ip} на ${where}`, tone: "ok", flagged: false, note: /^разблокирован/.test(note) ? "" : note, kind: "unblock" }
      : { title: `Не удалось разблокировать ${ip} на ${where}`, tone: "err", flagged: true, note, kind: "unblock" };
  }
  if (simulated) return { title: `Симуляция: заблокировал бы ${ip} на ${r.executor}`, tone: "neutral", flagged: false, note, kind: "simulate" };
  return r.ok
    ? { title: `Заблокирован ${ip} на ${r.executor}`, tone: "ok", flagged: false, note, kind: "block" }
    : { title: `Не удалось заблокировать ${ip} на ${r.executor}`, tone: "err", flagged: true, note, kind: "block" };
}
