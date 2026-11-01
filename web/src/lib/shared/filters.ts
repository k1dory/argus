// Диапазонные фильтры списков консоли: период (пресет или точный интервал
// UTC), пороги «не ниже / не выше» по уровню и числовым полям. Одно место для
// разбора URL, условий ClickHouse (только параметры {name:Type}) и подписей
// активных фильтров — общее для сервера, клиента и тестов.
//
// Имена параметров одинаковы на всех страницах:
//   range=1h|24h|7d|30d (period= — синоним), from=, to= (YYYY-MM-DDTHH:MM, UTC);
//   <поле>_min / <поле>_max — число или значение порядковой шкалы (level_min=high);
//   <поле>_from / <поле>_to — второй интервал по своей дате (seen_from на «Источниках»).
// Мусор не роняет страницу: невалидное значение молча отбрасывается.
import { RANGES, type RangeKey } from "./ranges";

export type SearchParamsLike = Record<string, string | string[] | undefined> | URLSearchParams;

export function getParam(sp: SearchParamsLike, key: string): string | undefined {
  const v = sp instanceof URLSearchParams ? sp.get(key) ?? undefined : sp[key];
  const s = Array.isArray(v) ? v[0] : v;
  return typeof s === "string" && s.trim() !== "" ? s.trim() : undefined;
}

/* ===== Время ===== */

/** Значение datetime-local: 'YYYY-MM-DDTHH:MM[:SS]', трактуется как UTC. */
export const DT_PARAM_RE = /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}(:\d{2})?$/;
/** Самый широкий точный интервал: дальше хранение всё равно не держит. */
export const MAX_WINDOW_DAYS = 400;
const DAY_MS = 86_400_000;

const pad = (n: number) => String(n).padStart(2, "0");

/** 'YYYY-MM-DDTHH:MM[:SS]' → ms UTC; несуществующая дата (02-31, 25:00) — null. */
export function parseDtParam(v: string | undefined): number | null {
  if (!v || !DT_PARAM_RE.test(v)) return null;
  const ms = Date.parse(v + "Z");
  if (!Number.isFinite(ms)) return null;
  // Date.parse переносит 2026-02-31 на 3 марта — такие даты не принимаем.
  return toDtParam(ms, v.length > 16) === v ? ms : null;
}

/** ms → 'YYYY-MM-DDTHH:MM' (или с секундами) в UTC — формат параметров from/to. */
export function toDtParam(ms: number, seconds = false): string {
  const d = new Date(ms);
  const base = `${d.getUTCFullYear()}-${pad(d.getUTCMonth() + 1)}-${pad(d.getUTCDate())}T${pad(d.getUTCHours())}:${pad(d.getUTCMinutes())}`;
  return seconds ? `${base}:${pad(d.getUTCSeconds())}` : base;
}

/** ms → 'YYYY-MM-DD HH:MM:SS' — строка для toDateTime({p:String}, 'UTC'). */
export function toChParam(ms: number): string {
  return new Date(ms).toISOString().slice(0, 19).replace("T", " ");
}

/**
 * Окно времени списка. range — пресет относительно «сейчас»; from/to — точный
 * интервал, он главнее пресета. Без range и from/to — без ограничения по
 * времени (только там, где у страницы нет окна по умолчанию).
 */
export type TimeFilter = { range?: RangeKey; from?: string; to?: string };

export type TimeOptions = {
  /** Пресет, если в URL его нет; undefined — без окна по умолчанию. */
  defaultRange?: RangeKey;
  /** Разрешённые пресеты (по умолчанию все из RANGES). */
  ranges?: readonly RangeKey[];
  /** Потолок ширины точного интервала, дней. */
  maxDays?: number;
  /** Префикс параметров второго интервала: seen → seen_from/seen_to. */
  prefix?: string;
};

export function parseTimeFilter(sp: SearchParamsLike, opts: TimeOptions = {}, now = Date.now()): TimeFilter {
  const allowed = opts.ranges ?? (Object.keys(RANGES) as RangeKey[]);
  const fromKey = opts.prefix ? `${opts.prefix}_from` : "from";
  const toKey = opts.prefix ? `${opts.prefix}_to` : "to";
  const out: TimeFilter = {};
  if (!opts.prefix) {
    const r = getParam(sp, "range") ?? getParam(sp, "period");
    const range = r && (allowed as readonly string[]).includes(r) ? (r as RangeKey) : opts.defaultRange;
    if (range) out.range = range;
  }
  let a = parseDtParam(getParam(sp, fromKey));
  let b = parseDtParam(getParam(sp, toKey));
  if (a == null && b == null) return out;
  if (a != null && b != null && a > b) [a, b] = [b, a];
  const maxMs = (opts.maxDays ?? MAX_WINDOW_DAYS) * DAY_MS;
  const end = b ?? now;
  // Только конец — окно пресета (или суток) до него; слишком широкое — подтягиваем начало к концу.
  if (a == null) a = end - (out.range ? RANGES[out.range].hours : 24) * 3_600_000;
  if (end - a > maxMs) a = end - maxMs;
  out.from = toDtParam(a, a % 60_000 !== 0);
  if (b != null) out.to = toDtParam(b, b % 60_000 !== 0);
  return out;
}

export const isExactTime = (t: TimeFilter): boolean => Boolean(t.from || t.to);
export const hasTimeFilter = (t: TimeFilter): boolean => Boolean(t.range || t.from || t.to);

/** Границы окна в ms; null — окна нет. */
export function timeBounds(t: TimeFilter, now = Date.now()): { startMs: number; endMs: number } | null {
  if (t.from) {
    const startMs = parseDtParam(t.from)!;
    return { startMs, endMs: t.to ? parseDtParam(t.to)! : now };
  }
  if (t.range) return { startMs: now - RANGES[t.range].hours * 3_600_000, endMs: now };
  return null;
}

export type Params = Record<string, string | number>;

/**
 * Условие окна по колонке времени. Колонка сравнивается с константой напрямую —
 * так условие попадает в отбор партиций toYYYYMM(ts) и первичного ключа по ts.
 * name — префикс параметров (свои у каждого окна запроса).
 */
export function timeCondition(col: string, t: TimeFilter, params: Params, name = "tf"): string[] {
  if (t.from) {
    params[`${name}_from`] = toChParam(parseDtParam(t.from)!);
    const conds = [`${col} >= toDateTime({${name}_from:String}, 'UTC')`];
    if (t.to) {
      params[`${name}_to`] = toChParam(parseDtParam(t.to)!);
      conds.push(`${col} <= toDateTime({${name}_to:String}, 'UTC')`);
    }
    return conds;
  }
  if (t.range) {
    params[`${name}_hours`] = RANGES[t.range].hours;
    return [`${col} >= now() - INTERVAL {${name}_hours:UInt32} HOUR`];
  }
  return [];
}

/** Попадает ли момент (строка ClickHouse или ISO) в окно — для фильтра в памяти. */
export function inTime(value: string | null | undefined, t: TimeFilter, now = Date.now()): boolean {
  const b = timeBounds(t, now);
  if (!b) return true;
  if (!value) return false;
  const ms = Date.parse(/[zZ]|[+-]\d{2}:?\d{2}$/.test(value) ? value : value.replace(" ", "T") + "Z");
  return Number.isFinite(ms) && ms >= b.startMs && ms <= b.endMs;
}

/* ===== Числа ===== */

export type NumSpec = { min: number; max: number; int?: boolean };
export type NumRange = { min?: number; max?: number };

function num(v: string | undefined, spec: NumSpec): number | undefined {
  if (v === undefined || !/^-?\d+(\.\d+)?$/.test(v)) return undefined;
  let n = Number(v);
  if (!Number.isFinite(n)) return undefined;
  if (spec.int) n = Math.round(n);
  return Math.min(spec.max, Math.max(spec.min, n));
}

/** key_min / key_max: клампы в [spec.min; spec.max], перепутанные меняются местами, крайние значения — не фильтр. */
export function parseNumRange(sp: SearchParamsLike, key: string, spec: NumSpec): NumRange {
  let lo = num(getParam(sp, `${key}_min`), spec);
  let hi = num(getParam(sp, `${key}_max`), spec);
  if (lo !== undefined && hi !== undefined && lo > hi) [lo, hi] = [hi, lo];
  const out: NumRange = {};
  if (lo !== undefined && lo > spec.min) out.min = lo;
  if (hi !== undefined && hi < spec.max) out.max = hi;
  return out;
}

export const hasRange = (r: NumRange): boolean => r.min !== undefined || r.max !== undefined;

/** Условия expr >= {name_min:Type} AND expr <= {name_max:Type}. */
export function numConditions(expr: string, r: NumRange, params: Params, name: string, type: "UInt8" | "UInt32" | "UInt64" | "Float64" = "UInt32"): string[] {
  const conds: string[] = [];
  if (r.min !== undefined) {
    params[`${name}_min`] = r.min;
    conds.push(`${expr} >= {${name}_min:${type}}`);
  }
  if (r.max !== undefined) {
    params[`${name}_max`] = r.max;
    conds.push(`${expr} <= {${name}_max:${type}}`);
  }
  return conds;
}

export function inRange(value: number | null | undefined, r: NumRange): boolean {
  if (!hasRange(r)) return true;
  if (value == null || !Number.isFinite(value)) return false;
  return (r.min === undefined || value >= r.min) && (r.max === undefined || value <= r.max);
}

/* ===== Порядковые шкалы (уровень инцидента, серьёзность CVE) ===== */

/** Значения шкалы по возрастанию: ранг = индекс + 1. */
export type Ordinal = readonly string[];
export type OrdinalRange = { min?: string; max?: string };

export const INCIDENT_LEVELS: Ordinal = ["low", "medium", "high", "critical"];
/** Серьёзность vulnerability-detector Wazuh (как пишет менеджер). */
export const VULN_SEVERITIES: Ordinal = ["Low", "Medium", "High", "Critical"];

function ordinal(v: string | undefined, scale: Ordinal): string | undefined {
  if (!v) return undefined;
  return scale.find((s) => s.toLowerCase() === v.toLowerCase());
}

export const rankOf = (v: string, scale: Ordinal): number => scale.findIndex((s) => s.toLowerCase() === v.toLowerCase()) + 1;

/**
 * key_min / key_max по шкале. legacyExact — старый параметр точного значения
 * (level=high на «Инцидентах»): даёт min = max, если новых нет.
 */
export function parseOrdinalRange(sp: SearchParamsLike, key: string, scale: Ordinal, legacyExact?: string): OrdinalRange {
  let lo = ordinal(getParam(sp, `${key}_min`), scale);
  let hi = ordinal(getParam(sp, `${key}_max`), scale);
  if (lo === undefined && hi === undefined && legacyExact) {
    const exact = ordinal(getParam(sp, legacyExact), scale);
    if (exact) lo = hi = exact;
  }
  if (lo && hi && rankOf(lo, scale) > rankOf(hi, scale)) [lo, hi] = [hi, lo];
  const out: OrdinalRange = {};
  if (lo && rankOf(lo, scale) > 1) out.min = lo;
  if (hi && rankOf(hi, scale) < scale.length) out.max = hi;
  return out;
}

/** Выражение ранга колонки: multiIf(lower(col) = {name_r1:String}, 1, …, 0) — значения тоже параметрами. */
export function ordinalRankSQL(col: string, scale: Ordinal, params: Params, name: string): string {
  const parts = scale.map((s, i) => {
    params[`${name}_r${i + 1}`] = s.toLowerCase();
    return `lower(${col}) = {${name}_r${i + 1}:String}, ${i + 1}`;
  });
  return `multiIf(${parts.join(", ")}, 0)`;
}

export function ordinalConditions(col: string, r: OrdinalRange, scale: Ordinal, params: Params, name: string): string[] {
  if (!r.min && !r.max) return [];
  const rank = ordinalRankSQL(col, scale, params, name);
  // Нижняя граница всегда не меньше 1: значение вне шкалы (пусто, Untriaged, info) даёт ранг 0
  // и не должно проходить «не выше» — так же, как его отвергает inOrdinal.
  return numConditions(rank, { min: r.min ? rankOf(r.min, scale) : 1, max: r.max ? rankOf(r.max, scale) : undefined }, params, name, "UInt8");
}

export function inOrdinal(value: string, r: OrdinalRange, scale: Ordinal): boolean {
  if (!r.min && !r.max) return true;
  const rank = rankOf(value, scale);
  if (rank === 0) return false;
  return (!r.min || rank >= rankOf(r.min, scale)) && (!r.max || rank <= rankOf(r.max, scale));
}

/* ===== Подписи и ссылки ===== */

export type FilterChip = { key: string; label: string; value: string };

const dtLabel = (s: string) => s.replace("T", " ");

/** Подпись окна: «24 часа» или «2026-10-01 00:00 — сейчас UTC». */
export function timeLabel(t: TimeFilter): string | null {
  if (t.from) return `${dtLabel(t.from)} — ${t.to ? dtLabel(t.to) : "сейчас"} UTC`;
  if (t.range) return RANGES[t.range].label;
  return null;
}

/** «≥ 7», «≤ 3», «7–10». */
export function rangeLabel(lo: string | undefined, hi: string | undefined): string | null {
  if (lo !== undefined && hi !== undefined) return lo === hi ? lo : `${lo} – ${hi}`;
  if (lo !== undefined) return `≥ ${lo}`;
  if (hi !== undefined) return `≤ ${hi}`;
  return null;
}

export function numChip(key: string, label: string, r: NumRange, fmt: (n: number) => string = String): FilterChip | null {
  const v = rangeLabel(r.min !== undefined ? fmt(r.min) : undefined, r.max !== undefined ? fmt(r.max) : undefined);
  return v ? { key, label, value: v } : null;
}

export function ordinalChip(key: string, label: string, r: OrdinalRange, names: Record<string, string> = {}): FilterChip | null {
  const n = (s: string | undefined) => (s ? names[s] ?? names[s.toLowerCase()] ?? s : undefined);
  const v = rangeLabel(n(r.min), n(r.max));
  return v ? { key, label, value: v } : null;
}

export function timeChip(t: TimeFilter, label = "период", onlyExact = false): FilterChip | null {
  if (onlyExact && !isExactTime(t)) return null;
  const v = timeLabel(t);
  return v ? { key: "time", label, value: v } : null;
}

/** Текст пустого списка: «… по фильтрам: уровень ≥ высокий, период 7 дней — ослабьте их». */
export function describeChips(chips: (FilterChip | null | undefined)[]): string {
  return chips.filter((c): c is FilterChip => Boolean(c)).map((c) => `${c.label} ${c.value}`).join(", ");
}

/** Ссылка со сменой параметров: undefined/"" — убрать; page сбрасывается, если не задан явно. */
export function patchHref(path: string, current: SearchParamsLike, patch: Record<string, string | undefined>): string {
  const next = new URLSearchParams();
  if (current instanceof URLSearchParams) current.forEach((v, k) => next.set(k, v));
  else for (const [k, v] of Object.entries(current)) {
    const s = Array.isArray(v) ? v[0] : v;
    if (typeof s === "string" && s !== "") next.set(k, s);
  }
  if (!("page" in patch)) next.delete("page");
  for (const [k, v] of Object.entries(patch)) {
    if (v === undefined || v === "") next.delete(k);
    else next.set(k, v);
  }
  const qs = next.toString();
  return qs ? `${path}?${qs}` : path;
}

/* ===== Поля формы (components/console/range-filters) ===== */

/** Поле диапазона формы: число (key_min/key_max), порядковая шкала (key_min/key_max) или дата (key_from/key_to). */
export type RangeField =
  | { key: string; label: string; kind: "number"; min: number; max: number; step?: number; unit?: string }
  | { key: string; label: string; kind: "ordinal"; options: { value: string; label: string }[] }
  | { key: string; label: string; kind: "datetime" };

export const numberField = (key: string, label: string, spec: NumSpec & { step?: number; unit?: string }): RangeField =>
  ({ key, label, kind: "number", min: spec.min, max: spec.max, ...(spec.step ? { step: spec.step } : {}), ...(spec.unit ? { unit: spec.unit } : {}) });

export const ordinalField = (key: string, label: string, scale: Ordinal, names: Record<string, string> = {}): RangeField =>
  ({ key, label, kind: "ordinal", options: scale.map((v) => ({ value: v, label: names[v] ?? names[v.toLowerCase()] ?? v })) });

/* ===== Шкалы страниц ===== */

/** Уровень правила Wazuh. */
export const ALERT_LEVEL_SPEC: NumSpec = { min: 0, max: 15, int: true };
/** Серьёзность события единой схемы. */
export const EVENT_SEVERITY_SPEC: NumSpec = { min: 0, max: 10, int: true };
/** CVSS. */
export const CVSS_SPEC: NumSpec = { min: 0, max: 10 };
/** Счётчики (событий, алертов, инцидентов). */
export const COUNT_SPEC: NumSpec = { min: 0, max: 1_000_000_000, int: true };
/** Доля, %. */
export const PERCENT_SPEC: NumSpec = { min: 0, max: 100 };
