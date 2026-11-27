// Сводка агентов Wazuh: регистрация и связь — из API менеджера, активность —
// из алертов в хранилище. Объединение по имени агента: агент, который молчит
// (или отключён), виден, даже если за период у него нет ни одного алерта.
import type { NumRange } from "@/lib/shared/filters";

export type AlertActivity = { agent_name: string; alerts: number; critical: number; rules: number; last_alert: string };
export type ApiAgent = { id: string; name: string; status: string; lastKeepAlive?: string; ip?: string };

export type AgentRow = {
  name: string;
  id?: string;
  ip?: string;
  /** Статус из API менеджера; undefined — API недоступен или агент не зарегистрирован. */
  status?: string;
  keepalive?: string;
  alerts: number;
  critical: number;
  rules: number;
  lastAlert?: string;
};

/** Порядок «сначала проблемы»: отключённые, не подключавшиеся, ожидающие, активные, неизвестные. */
export const AGENT_STATUS_RANK: Record<string, number> = { disconnected: 0, never_connected: 1, pending: 2, active: 3 };
const rankOf = (s?: string) => (s ? AGENT_STATUS_RANK[s] ?? 4 : 4);

export type AgentSort = "status" | "alerts" | "critical" | "last";
export const parseAgentSort = (v: unknown): AgentSort => (v === "alerts" || v === "critical" || v === "last" ? v : "status");

const within = (r: NumRange | undefined, v: number) => !r || ((r.min === undefined || v >= r.min) && (r.max === undefined || v <= r.max));

/** Keepalive у менеджера — «9999-…» (сам себе не шлёт); такое время не показываем. */
export const realKeepalive = (ts?: string) => (ts && !ts.startsWith("9999") ? ts : undefined);

/**
 * Объединяет активность по алертам со списком агентов API. Агент без алертов
 * попадает в таблицу, если ноль проходит пороги алертов/критичных (иначе фильтр
 * «алертов ≥ 10» показывал бы молчащих). api = null — API недоступен: только
 * алертная часть, статус неизвестен.
 */
export function mergeAgents(
  activity: AlertActivity[],
  api: ApiAgent[] | null,
  f: { alerts?: NumRange; critical?: NumRange } = {},
): AgentRow[] {
  const byName = new Map<string, AgentRow>();
  for (const a of activity) {
    byName.set(a.agent_name, { name: a.agent_name, alerts: a.alerts, critical: a.critical, rules: a.rules, lastAlert: a.last_alert });
  }
  const zeroPasses = within(f.alerts, 0) && within(f.critical, 0);
  for (const g of api ?? []) {
    const row = byName.get(g.name);
    const reg = { id: g.id, ip: g.ip, status: g.status, keepalive: realKeepalive(g.lastKeepAlive) };
    if (row) Object.assign(row, reg);
    else if (zeroPasses) byName.set(g.name, { name: g.name, alerts: 0, critical: 0, rules: 0, ...reg });
  }
  return [...byName.values()];
}

const time = (ts?: string) => (ts ? Date.parse(ts.includes("T") ? ts : `${ts.replace(" ", "T")}Z`) || 0 : 0);

/** Сортировка таблицы: status (по умолчанию) — проблемы сверху, затем критичные и объём. */
export function sortAgents(rows: AgentRow[], sort: AgentSort, dir: "asc" | "desc"): AgentRow[] {
  const sign = dir === "asc" ? 1 : -1;
  const byName = (a: AgentRow, b: AgentRow) => a.name.localeCompare(b.name);
  const cmp: Record<AgentSort, (a: AgentRow, b: AgentRow) => number> = {
    status: (a, b) => rankOf(a.status) - rankOf(b.status) || b.critical - a.critical || b.alerts - a.alerts || byName(a, b),
    alerts: (a, b) => sign * (a.alerts - b.alerts) || byName(a, b),
    critical: (a, b) => sign * (a.critical - b.critical) || b.alerts - a.alerts || byName(a, b),
    last: (a, b) => sign * (time(a.lastAlert) - time(b.lastAlert)) || byName(a, b),
  };
  return [...rows].sort(cmp[sort]);
}

/** Порядок таблицы управления: отключённые и проблемные сверху, внутри — по ID. */
export function sortByStatus<T extends { id: string; status: string }>(agents: T[]): T[] {
  return [...agents].sort((a, b) => rankOf(a.status) - rankOf(b.status) || a.id.localeCompare(b.id));
}
