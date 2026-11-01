/**
 * Адреса инцидента, склеенного по подсети (правила с collapse: сканы снаружи).
 * Движок пишет их в incidents.members строкой JSON (миграция 0035); статус
 * блокировки по адресу — последняя запись response_log этого инцидента и адреса.
 */

export type IncidentMember = { ip: string; first: string; last: string; events: number; rules: string[] };

export type MemberBlockRow = { ip: string; executor: string; mode: string; dry_run: number; ok: number; detail: string };

export type MemberBlockState = "blocked" | "simulated" | "capped" | "ids" | "waiting" | "refused" | "failed" | "none";

export const MEMBER_BLOCK_LABEL: Record<MemberBlockState, string> = {
  blocked: "заблокирован",
  simulated: "симуляция блока",
  capped: "потолок блокировок — решение за аналитиком",
  ids: "IDS: автоответ выключен",
  waiting: "ожидание доверенных событий",
  refused: "не блокируется (allowlist / адрес)",
  failed: "блокировка не выполнена",
  none: "—",
};

const MAX_MEMBERS = 256;

/** Список адресов из колонки members; всё, что не той формы, отбрасывается целиком. */
export function parseMembers(raw: unknown): IncidentMember[] {
  if (typeof raw !== "string" || raw.trim() === "") return [];
  let v: unknown;
  try {
    v = JSON.parse(raw);
  } catch {
    return [];
  }
  if (!Array.isArray(v)) return [];
  const out: IncidentMember[] = [];
  for (const m of v.slice(0, MAX_MEMBERS)) {
    if (!m || typeof m !== "object") return [];
    const { ip, first, last, events, rules } = m as Record<string, unknown>;
    if (typeof ip !== "string" || typeof first !== "string" || typeof last !== "string" || typeof events !== "number"
      || !Array.isArray(rules) || rules.some((r) => typeof r !== "string")) return [];
    out.push({ ip, first, last, events, rules: rules as string[] });
  }
  return out;
}

/**
 * Статус блокировки адреса по последней записи журнала. Только категория из
 * собственного списка: текст исполнителя (ответ NGFW) в таблицу адресов не идёт,
 * он есть в журнале реагирования ниже.
 */
export function memberBlockState(row: MemberBlockRow | undefined): MemberBlockState {
  if (!row) return "none";
  if (row.executor !== "argus") {
    if (!row.ok) return "failed";
    return row.dry_run || row.mode === "simulate" ? "simulated" : "blocked";
  }
  if (row.detail.startsWith("потолок блокировок инцидента")) return "capped";
  if (row.detail.startsWith("режим IDS")) return "ids";
  if (row.detail.startsWith("ожидание:")) return "waiting";
  return "refused";
}
