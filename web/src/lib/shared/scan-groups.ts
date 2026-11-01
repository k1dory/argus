/**
 * Группировка открытых инцидентов сканов снаружи по подсети источника — только
 * в консоли: движок, инциденты и автоответ не меняются (инцидент на адрес, блок
 * как обычно). Свёрнутая строка «подсеть: N адресов» вместо десятков строк ленты.
 */

/** Правила группы inbound-scan: скан портов, обход хостов, долбёжка сервиса. */
export const SCAN_GROUP_RULES = ["a41c-net-070", "a41c-net-071", "a41c-net-072"] as const;

// Канонический адрес в SQL (ClickHouse 24.8). Пробелы по краям не в счёт; IPv6 —
// в каноническом виде; IPv4 в любой записи IPv6 (::ffff:a.b.c.d, ::ffff:cb00:7107,
// полная форма) — IPv4. Конверсии *OrDefault: ClickHouse может вычислить ветку
// заранее, и toIPv6 на «exporter-1» уронил бы запрос.
const trimmed = (col: string) => `trimBoth(${col})`;
const v6SQL = (col: string) => `if(isIPv6String(${trimmed(col)}), IPv6NumToString(toIPv6OrDefault(${trimmed(col)})), '')`;
const v4SQL = (col: string) => {
  const v6 = v6SQL(col);
  return `multiIf(isIPv4String(${trimmed(col)}), IPv4NumToString(toIPv4OrDefault(${trimmed(col)})),`
    + ` startsWith(${v6}, '::ffff:') AND isIPv4String(substring(${v6}, 8)), substring(${v6}, 8), '')`;
};

/** Канонический адрес источника в SQL: IPv4 или IPv6, "" — не адрес. */
export function addrSQL(col: string): string {
  return `if(${v4SQL(col)} != '', ${v4SQL(col)}, ${v6SQL(col)})`;
}

/**
 * Подсеть адреса источника в SQL: /24 у IPv4 (в любой записи), /48 у IPv6, не
 * адрес — "". Адрес источника у правил сканов — субъект инцидента (group_by: src.ip).
 */
export function subnetSQL(col: string): string {
  const v4 = v4SQL(col), v6 = v6SQL(col);
  return `multiIf(${v4} != '', concat(IPv4NumToString(tupleElement(IPv4CIDRToRange(toIPv4OrDefault(${v4}), 24), 1)), '/24'),`
    + ` ${v6} != '', concat(IPv6NumToString(tupleElement(IPv6CIDRToRange(toIPv6OrDefault(${v6}), 48), 1)), '/48'), '')`;
}

/** Подсеть, как её считает subnetSQL: проверка параметра URL и тесты. */
export function isSubnetKey(s: string): boolean {
  return /^(\d{1,3}\.){3}0\/24$/.test(s) || /^[0-9a-f:]+\/48$/.test(s);
}

export type BlockRow = { executor: string; mode: string; dry_run: number; ok: number; detail: string };

export type BlockState = "blocked" | "unblock_failed" | "released" | "simulated" | "ids" | "waiting" | "refused" | "failed" | "none";

export const BLOCK_LABEL: Record<BlockState, string> = {
  blocked: "заблокирован",
  unblock_failed: "заблокирован — снять не удалось",
  released: "блок снят (TTL или оператор)",
  simulated: "симуляция блока",
  ids: "IDS: автоответ выключен",
  waiting: "ожидание доверенных событий",
  refused: "не блокируется (allowlist / адрес)",
  failed: "блокировка не выполнена",
  none: "—",
};

/**
 * Статус блока по последней записи response_log инцидента. Только категория из
 * собственного списка: текст исполнителя (ответ NGFW) в таблицу не идёт — он есть
 * в журнале реагирования карточки.
 */
export function blockState(row: BlockRow | undefined): BlockState {
  if (!row) return "none";
  // Неудачное снятие оставляет блок активным (респондер держит адрес в active).
  if (row.executor.endsWith(".unblock")) return row.ok ? "released" : "unblock_failed";
  if (row.executor !== "argus") {
    if (!row.ok) return "failed";
    return row.dry_run || row.mode === "simulate" ? "simulated" : "blocked";
  }
  if (row.detail.startsWith("режим IDS")) return "ids";
  if (row.detail.startsWith("ожидание:")) return "waiting";
  if (row.detail.startsWith("уже заблокирован")) return "blocked";
  if (row.detail.startsWith("все исполнители отказали")) return "failed";
  return "refused";
}

const LEVEL_RANK: Record<string, number> = { low: 1, medium: 2, high: 3, critical: 4 };
export const levelOfRank = (n: number): string => Object.keys(LEVEL_RANK).find((k) => LEVEL_RANK[k] === n) ?? "low";

/** Групп на страницу и инцидентов на страницу раскрытия. */
export const GROUPS_PAGE = 100;
export const GROUP_ROWS_PAGE = 500;
/**
 * Групповое действие — над группой не больше страницы раскрытия: сервер читает до
 * GROUP_ACTION_MAX + 1 строки и сверяет весь состав с подтверждённым; лишняя строка
 * значит, что группа больше и целиком не подтверждена.
 */
export const GROUP_ACTION_MAX = GROUP_ROWS_PAGE;

/** Список инцидентов из формы группового действия; null — не тот формат. */
export function parseIncidentIds(raw: string): string[] | null {
  const ids = raw.split(",").map((x) => x.trim()).filter(Boolean);
  if (ids.length === 0 || ids.length > GROUP_ACTION_MAX || ids.some((x) => !/^INC-\d{1,9}$/.test(x))) return null;
  return [...new Set(ids)].sort();
}
