// Простой API журнала для агентов: GET /api/v1/log над argus.events. Разбор
// параметров и сборка параметризованного SQL — чистые функции, без БД и Next.
import { appendTerm } from "./search-query";
import type { TriageBinding } from "./triage";

export const LOG_LEVELS = ["info", "low", "medium", "high", "critical"] as const;
export type LogLevel = (typeof LOG_LEVELS)[number];
/** Нижняя граница severity (0..10) для каждого уровня: info 0–2, low 3–4,
 *  medium 5–6, high 7–8, critical 9–10. Фильтр level — «не ниже». */
export const LEVEL_MIN: Record<LogLevel, number> = { info: 0, low: 3, medium: 5, high: 7, critical: 9 };

export function levelOf(severity: number): LogLevel {
  if (severity >= 9) return "critical";
  if (severity >= 7) return "high";
  if (severity >= 5) return "medium";
  if (severity >= 3) return "low";
  return "info";
}

export const LOG_LIMIT_DEFAULT = 200;
export const LOG_LIMIT_MAX = 1000;
export const LOG_SINCE_DEFAULT_MS = 24 * 3600_000;
export const LOG_SINCE_MAX_MS = 30 * 86_400_000;
const FILTER_MAX_LEN = 256;
const Q_MAX_LEN = 500;

/** Длительность вида 30s, 15m, 24h, 7d → мс; иначе null. */
export function parseDuration(s: string): number | null {
  const m = /^(\d{1,6})(s|m|h|d)$/.exec(s.trim());
  if (!m) return null;
  const n = Number(m[1]);
  const unit = { s: 1000, m: 60_000, h: 3600_000, d: 86_400_000 }[m[2] as "s" | "m" | "h" | "d"];
  return n > 0 ? n * unit : null;
}

export type LogFormat = "json" | "ndjson";
export type LogParams = {
  log?: string;
  level?: LogLevel;
  actor?: string;
  node?: string;
  src_ip?: string;
  action?: string;
  q?: string;
  /** Начало окна, мс (now − since). */
  fromMs: number;
  /** Конец окна, мс (until); без него — «сейчас». */
  toMs?: number;
  limit: number;
  format: LogFormat;
};

export type LogParse = { ok: true; params: LogParams } | { ok: false; error: string };

const STRING_FILTERS = ["log", "actor", "node", "src_ip", "action"] as const;

export function parseLogParams(sp: URLSearchParams, now = Date.now()): LogParse {
  const bad = (error: string): LogParse => ({ ok: false, error });
  const out: LogParams = { fromMs: now - LOG_SINCE_DEFAULT_MS, limit: LOG_LIMIT_DEFAULT, format: "json" };
  for (const k of STRING_FILTERS) {
    const v = sp.get(k);
    if (v === null || v === "") continue;
    if (v.length > FILTER_MAX_LEN || /[\u0000-\u001f\u007f]/.test(v)) return bad(`${k}: до ${FILTER_MAX_LEN} символов без управляющих`);
    out[k] = v;
  }
  const level = sp.get("level");
  if (level) {
    if (!(LOG_LEVELS as readonly string[]).includes(level)) return bad(`level: ожидается ${LOG_LEVELS.join("|")}`);
    out.level = level as LogLevel;
  }
  const q = sp.get("q");
  if (q) {
    if (q.length > Q_MAX_LEN) return bad(`q: до ${Q_MAX_LEN} символов`);
    out.q = q;
  }
  const since = sp.get("since");
  if (since) {
    const ms = parseDuration(since);
    if (ms === null) return bad("since: ожидается длительность вида 15m, 24h, 7d");
    if (ms > LOG_SINCE_MAX_MS) return bad("since: не больше 30d");
    out.fromMs = now - ms;
  }
  const until = sp.get("until");
  if (until) {
    const ms = Date.parse(until);
    if (!/^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}(:\d{2}(\.\d{1,3})?)?(Z|[+-]\d{2}:\d{2})$/.test(until) || !Number.isFinite(ms)) return bad("until: ожидается RFC 3339, например 2026-10-24T12:00:00Z");
    if (ms < out.fromMs) return bad("until: раньше начала окна (since)");
    out.toMs = Math.min(ms, now);
  }
  const limit = sp.get("limit");
  if (limit !== null && limit !== "") {
    const n = Number(limit);
    if (!Number.isInteger(n) || n < 1 || n > LOG_LIMIT_MAX) return bad(`limit: целое от 1 до ${LOG_LIMIT_MAX}`);
    out.limit = n;
  }
  const format = sp.get("format");
  if (format) {
    if (format !== "json" && format !== "ndjson") return bad("format: json|ndjson");
    out.format = format;
  }
  return { ok: true, params: out };
}

/** Строка запроса поиска из фильтров-сущностей: ею проверяется область сессии
 *  разбора (checkTriageSearch) — те же правила, что у /api/search. */
export function logScopeQuery(p: LogParams): string {
  let q = "";
  if (p.actor) q = appendTerm(q, "actor", p.actor, { literal: true });
  if (p.node) q = appendTerm(q, "node", p.node, { literal: true });
  if (p.src_ip) q = appendTerm(q, "src", p.src_ip, { literal: true });
  if (p.action) q = appendTerm(q, "action", p.action, { literal: true });
  if (p.log) q = appendTerm(q, "source", p.log, { literal: true });
  return q;
}

/** 'YYYY-MM-DD HH:MM:SS.mmm' (UTC) для parseDateTime64BestEffort. */
export const chTs = (ms: number): string => new Date(ms).toISOString().replace("T", " ").replace("Z", "");

export type LogSql = { sql: string; params: Record<string, string | number> };

// ts — без toString(...) AS ts: при включённом анализаторе (ClickHouse 24.8)
// алиас затенял бы колонку в WHERE/ORDER BY (String против DateTime64), а
// JSONEachRow и так отдаёт DateTime64 строкой 'YYYY-MM-DD HH:MM:SS.mmm'.
// pii — признак ПДн в строке: по нему MCP скрывает свободный текст (object, attrs) в профиле triage.
export const LOG_COLUMNS = `ts, source, source_class, action, outcome, severity, actor_name, actor_kind, object, node, session_id, src_ip, dst_ip, value, unit, attrs, pii`;

/** Параметризованный SQL: значения только через {name:Type}. bind — привязка
 *  строк сессии разбора (обязательный предикат; пусто — ни одной строки). */
export function buildLogSql(p: LogParams, window: { fromMs: number; toMs?: number }, bind?: TriageBinding): LogSql {
  const params: Record<string, string | number> = { from: chTs(window.fromMs), limit: p.limit };
  const conds = [`ts >= parseDateTime64BestEffort({from:String}, 3, 'UTC')`];
  if (window.toMs !== undefined) {
    params.to = chTs(window.toMs);
    conds.push(`ts <= parseDateTime64BestEffort({to:String}, 3, 'UTC')`);
  }
  if (p.log) {
    params.log = p.log;
    conds.push(`(source = {log:String} OR source_class = {log:String})`);
  }
  if (p.level && LEVEL_MIN[p.level] > 0) {
    params.sev = LEVEL_MIN[p.level];
    conds.push(`severity >= {sev:UInt8}`);
  }
  for (const [k, col] of [["actor", "actor_name"], ["node", "node"], ["src_ip", "src_ip"], ["action", "action"]] as const) {
    const v = p[k];
    if (!v) continue;
    params[k] = v;
    conds.push(`${col} = {${k}:String}`);
  }
  if (p.q) {
    params.q = p.q;
    conds.push(`positionCaseInsensitiveUTF8(concat(object, ' ', raw), {q:String}) > 0`);
  }
  if (bind) {
    const parts: string[] = [];
    if (bind.actors.length) {
      bind.actors.forEach((a, i) => (params[`ba${i}`] = a));
      parts.push(`actor_name IN (${bind.actors.map((_, i) => `{ba${i}:String}`).join(", ")})`);
    }
    if (bind.nodes.length) {
      bind.nodes.forEach((n, i) => (params[`bn${i}`] = n));
      parts.push(`node IN (${bind.nodes.map((_, i) => `{bn${i}:String}`).join(", ")})`);
    }
    conds.push(parts.length ? `(${parts.join(" OR ")})` : "0");
  }
  return { sql: `SELECT ${LOG_COLUMNS} FROM events WHERE ${conds.join(" AND ")} ORDER BY ts DESC LIMIT {limit:UInt32}`, params };
}

export type LogItem = {
  ts: string; source: string; source_class: string; action: string; outcome: string; severity: number; level: LogLevel;
  actor_name: string; actor_kind: string; object: string; node: string; session_id: string; src_ip: string; dst_ip: string;
  value: number; unit: string; attrs: Record<string, string>;
  /** 1 — строка содержит ПДн (источник или детектор). */
  pii: 0 | 1;
};

export function toLogItem(r: Record<string, unknown>): LogItem {
  const severity = Number(r.severity ?? 0);
  const attrs = r.attrs && typeof r.attrs === "object" && !Array.isArray(r.attrs) ? (r.attrs as Record<string, string>) : {};
  const s = (k: string) => String(r[k] ?? "");
  return {
    ts: s("ts"), source: s("source"), source_class: s("source_class"), action: s("action"), outcome: s("outcome"), severity, level: levelOf(severity),
    actor_name: s("actor_name"), actor_kind: s("actor_kind"), object: s("object"), node: s("node"), session_id: s("session_id"), src_ip: s("src_ip"), dst_ip: s("dst_ip"),
    value: Number(r.value ?? 0), unit: s("unit"), attrs, pii: Number(r.pii ?? 0) === 1 ? 1 : 0,
  };
}
