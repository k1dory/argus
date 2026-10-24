// Единый словарь подписей консоли на русском: серьёзность, статусы, агенты,
// вердикты политик. Ни один экран не показывает сырые «Level ≥ 7» / «OK» /
// «active» — только через эти таблицы.

/** Уровни инцидентов движка ARGUS. */
export const INCIDENT_LEVEL_LABELS: Record<string, string> = {
  critical: "критический",
  high: "высокий",
  medium: "средний",
  low: "низкий",
};

/** Серьёзность CVE (vulnerability-detector). */
export const VULN_SEVERITY_LABELS: Record<string, string> = {
  Critical: "критическая",
  High: "высокая",
  Medium: "средняя",
  Low: "низкая",
  Untriaged: "не оценена",
};

export const VULN_STATUS_LABELS: Record<string, string> = {
  Active: "активна",
  Solved: "устранена",
  Pending: "ожидает",
};

/** Статус агента Wazuh (API менеджера). */
export const AGENT_STATUS_LABELS: Record<string, string> = {
  active: "активен",
  disconnected: "отключён",
  never_connected: "не подключался",
  pending: "ожидает",
};

/** Вердикт Policy-as-Code: pass/fail и «неизвестно» (проверка не выполнена — SCA/API недоступны). */
export const COMPLIANCE_LABELS: Record<"pass" | "fail" | "unknown", string> = {
  pass: "соблюдено",
  fail: "нарушение",
  unknown: "неизвестно",
};

/** Источник дашборда. */
export const DASHBOARD_ORIGIN_LABELS: Record<"provisioned" | "console", string> = {
  provisioned: "из каталога",
  console: "создан в консоли",
};

/** Живость источника событий. */
export const SOURCE_ALIVE_LABELS: Record<"alive" | "silent", string> = {
  alive: "жив",
  silent: "молчит",
};

/** Итог действия (реагирование, проверка). */
export const OUTCOME_LABELS: Record<"ok" | "error", string> = { ok: "выполнено", error: "ошибка" };

/** Фильтр уровня правил Wazuh в журнале алертов. */
export const ALERT_LEVEL_FILTERS: { value: string; label: string }[] = [
  { value: "0", label: "Любой уровень" },
  { value: "7", label: "Уровень 7 и выше" },
  { value: "12", label: "Уровень 12 и выше" },
];

/** Подпись уровня правила Wazuh: «уровень 12». */
export function ruleLevelLabel(level: number): string {
  return `уровень ${level}`;
}

export function incidentLevelLabel(level: string): string {
  return INCIDENT_LEVEL_LABELS[level.toLowerCase()] ?? level;
}

export function vulnSeverityLabel(sev: string): string {
  return VULN_SEVERITY_LABELS[sev] ?? (sev || "—");
}

export function vulnStatusLabel(status: string): string {
  return VULN_STATUS_LABELS[status] ?? (status || "—");
}

export function agentStatusLabel(status: string): string {
  return AGENT_STATUS_LABELS[status] ?? status;
}
