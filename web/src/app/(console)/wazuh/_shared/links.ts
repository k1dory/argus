// Ссылки внутри модуля Wazuh. Агент из любой строки (алерт, CVE, сводка)
// ведёт на его алерты — фильтр журнала алертов, а не общий список агентов.
// Кандидат в общий searchHref как wazuhAgent, когда модуль станет постоянным.

/**
 * Алерты одного агента: /wazuh/alerts?agent=…. С current (фильтры текущей
 * страницы алертов) окно, уровень и прочее сохраняются — меняется только
 * агент, страница сбрасывается на первую.
 */
export function wazuhAgentHref(name: string, current?: URLSearchParams): string {
  const next = new URLSearchParams(current);
  next.set("agent", name);
  next.delete("page");
  return `/wazuh/alerts?${next.toString()}`;
}

/** Страница списка политик: раздел живёт под /wazuh, а не в корне (прежний /policies давал 404). */
export function policiesPageHref(page: number): string {
  return page > 1 ? `/wazuh/policies?page=${page}` : "/wazuh/policies";
}
