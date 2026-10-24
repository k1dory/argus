// Необязательные модули консоли. Флаг читается из окружения при каждом вызове:
// тесты переключают его без перезагрузки модулей.

/** Модуль Wazuh (страницы алертов, уязвимостей, MITRE, политик, агентов и
 *  управления менеджером, индекс поиска alerts, дашборды wazuh-*):
 *  ARGUS_INTEGRATION_WAZUH=1|true. По умолчанию выключен. */
export function wazuhEnabled(): boolean {
  const v = (process.env.ARGUS_INTEGRATION_WAZUH ?? "").trim().toLowerCase();
  return v === "1" || v === "true";
}
