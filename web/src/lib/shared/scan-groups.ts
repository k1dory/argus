/**
 * Группировка открытых инцидентов сканов снаружи по подсети источника — только
 * в консоли: движок, инциденты и автоответ не меняются (инцидент на адрес, блок
 * как обычно). Свёрнутая строка «подсеть: N адресов» вместо десятков строк ленты.
 */

/** Правила группы inbound-scan: скан портов, обход хостов, долбёжка сервиса. */
export const SCAN_GROUP_RULES = ["a41c-net-070", "a41c-net-071", "a41c-net-072"] as const;

/**
 * Подсеть адреса источника в SQL (ClickHouse 24.8): /24 у IPv4, /48 у IPv6, IPv4 в
 * записи IPv6 (::ffff:) — IPv4, пробелы по краям не в счёт, не адрес — "".
 * Адрес источника у этих правил — субъект инцидента (group_by: src.ip).
 */
export function subnetSQL(col: string): string {
  const t = `trimBoth(${col})`;
  const v = `if(startsWith(lower(${t}), '::ffff:') AND isIPv4String(substring(${t}, 8)), substring(${t}, 8), ${t})`;
  return `multiIf(isIPv4String(${v}), concat(IPv4NumToString(tupleElement(IPv4CIDRToRange(toIPv4(${v}), 24), 1)), '/24'),`
    + ` isIPv6String(${v}), concat(IPv6NumToString(tupleElement(IPv6CIDRToRange(toIPv6(${v}), 48), 1)), '/48'), '')`;
}

/** Подсеть, как её считает subnetSQL: проверка параметра URL и тесты. */
export function isSubnetKey(s: string): boolean {
  return /^(\d{1,3}\.){3}0\/24$/.test(s) || /^[0-9a-f:]+\/48$/.test(s);
}

export type BlockRow = { executor: string; mode: string; dry_run: number; ok: number; detail: string };

export type BlockState = "blocked" | "released" | "simulated" | "ids" | "waiting" | "refused" | "failed" | "none";

export const BLOCK_LABEL: Record<BlockState, string> = {
  blocked: "заблокирован",
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
  if (row.executor.endsWith(".unblock")) return row.ok ? "released" : "failed";
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
