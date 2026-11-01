// Журнал событий: фильтры ⇄ URL ⇄ строка запроса поиска, корзины гистограммы,
// связь события с инцидентом. Чистые функции — общие для сервера, клиента и тестов.
import { RANGES, parseRange, type RangeKey } from "./ranges";
import { appendTerm, parseQuery, termToString } from "./search-query";
import { SEVERITY } from "./severity";
import { getParam as getFilterParam, parseTimeFilter, rangeLabel } from "./filters";

export const JOURNAL_PATH = "/events";
export const MAX_Q_LEN = 2000;
const VALUE_MAX = 256;

/** Порог серьёзности события 0..10: пороги — из lib/shared/severity. */
export const SEV_OPTIONS = [
  { value: "", label: "Любая" },
  { value: String(SEVERITY.events.medium), label: `≥ ${SEVERITY.events.medium} · средняя` },
  { value: String(SEVERITY.events.high), label: `≥ ${SEVERITY.events.high} · высокая` },
  { value: String(SEVERITY.events.critical), label: `≥ ${SEVERITY.events.critical} · критичная` },
] as const;

/** Верхний порог серьёзности: «не выше» — отсечь шумные критичные или смотреть только фон. */
export const SEV_MAX_OPTIONS = [
  { value: "", label: "Любая" },
  { value: String(SEVERITY.events.medium - 1), label: `≤ ${SEVERITY.events.medium - 1} · низкая` },
  { value: String(SEVERITY.events.high - 1), label: `≤ ${SEVERITY.events.high - 1} · до средней` },
  { value: String(SEVERITY.events.critical - 1), label: `≤ ${SEVERITY.events.critical - 1} · до высокой` },
] as const;

export type JournalFilters = {
  q: string;
  range: RangeKey;
  from?: string;
  to?: string;
  source?: string;
  host?: string;
  /** Серьёзность не ниже (URL level_min, прежде sev). */
  sev?: number;
  /** Серьёзность не выше (URL level_max). */
  sevMax?: number;
  rule?: string;
  page?: number;
};

type Params = Record<string, string | string[] | undefined> | URLSearchParams;

function getParam(sp: Params, k: string): string | undefined {
  const v = sp instanceof URLSearchParams ? sp.get(k) ?? undefined : sp[k];
  return typeof v === "string" ? v : undefined;
}

const clean = (v: string | undefined): string | undefined => {
  const s = v?.trim().slice(0, VALUE_MAX);
  return s ? s : undefined;
};

export function parseJournalParams(sp: Params): JournalFilters {
  const g = (k: string) => getParam(sp, k);
  // Порог серьёзности: level_min/level_max (как на остальных страницах), sev — прежнее имя нижнего.
  const sevOf = (v: string | undefined, lo: number) => {
    const n = Number(v);
    return v !== undefined && /^\d+$/.test(v.trim()) && Number.isInteger(n) && n >= lo && n <= 10 ? n : undefined;
  };
  let sev = sevOf(getFilterParam(sp, "level_min") ?? g("sev"), 1);
  let sevMax = sevOf(getFilterParam(sp, "level_max"), 0);
  if (sev !== undefined && sevMax !== undefined && sev > sevMax) [sev, sevMax] = [Math.max(1, sevMax), sev];
  if (sevMax === 10) sevMax = undefined;
  // Точный интервал: невалидные даты отбрасываются, перепутанные границы меняются местами.
  const time = parseTimeFilter(sp, { defaultRange: "24h" });
  const pageRaw = Number(g("page"));
  return {
    q: (g("q") ?? "").slice(0, MAX_Q_LEN),
    range: parseRange(g("range") ?? g("period")),
    from: time.from,
    to: time.to,
    source: clean(g("source")),
    host: clean(g("host")),
    sev,
    sevMax,
    rule: clean(g("rule")),
    page: Number.isInteger(pageRaw) && pageRaw > 1 ? pageRaw : undefined,
  };
}

/** Структурные фильтры → условия языка поиска (поля индекса events). */
export function journalQuery(f: JournalFilters): string {
  let q = f.q.trim();
  if (f.source) q = appendTerm(q, "source", f.source);
  if (f.host) q = appendTerm(q, "node", f.host);
  if (f.rule) q = appendTerm(q, "rule", f.rule);
  if (f.sev) q = `${q} severity>=${f.sev}`.trim();
  if (f.sevMax !== undefined) q = `${q} severity<=${f.sevMax}`.trim();
  return q;
}

export type JournalPatch = Partial<Record<keyof JournalFilters, string | number | undefined>>;

/** Параметры URL журнала; patch со значением undefined убирает ключ. Страница сбрасывается, если не задана явно. */
export function journalParams(f: JournalFilters, patch: JournalPatch = {}): URLSearchParams {
  const merged: JournalPatch = { q: f.q, range: f.range, from: f.from, to: f.to, source: f.source, host: f.host, sev: f.sev, sevMax: f.sevMax, rule: f.rule, ...patch };
  if (!("page" in patch)) merged.page = undefined;
  const p = new URLSearchParams();
  // Имена в URL — общие для консоли: порог серьёзности — level_min/level_max.
  const URL_KEY: Partial<Record<keyof JournalFilters, string>> = { sev: "level_min", sevMax: "level_max" };
  for (const k of ["q", "source", "host", "sev", "sevMax", "rule", "range", "from", "to", "page"] as const) {
    const v = merged[k];
    if (v === undefined || v === "") continue;
    if (k === "range" && v === "24h") continue; // диапазон по умолчанию — без шума в URL
    if (k === "page" && Number(v) <= 1) continue;
    p.set(URL_KEY[k] ?? k, String(v));
  }
  return p;
}

export function journalHref(f: JournalFilters, patch: JournalPatch = {}): string {
  const qs = journalParams(f, patch).toString();
  return qs ? `${JOURNAL_PATH}?${qs}` : JOURNAL_PATH;
}

/** Добавить (или исключить) поле:значение в свободный запрос — для действий «+»/«−» в карточке события. */
export function withTerm(q: string, field: string, value: string, negate = false): string {
  if (!negate) return appendTerm(q, field, value);
  const exists = parseQuery(q).some((t) => t.field === field && t.negate && t.value === value);
  return exists ? q : `${q} ${termToString({ field, op: "=", value, negate: true })}`.trim();
}

/** Активные фильтры — чипы над лентой: подпись и ссылка «убрать». */
export function activeChips(f: JournalFilters): { key: string; label: string; value: string; href: string }[] {
  const chips: { key: string; label: string; value: string; href: string }[] = [];
  if (f.source) chips.push({ key: "source", label: "источник", value: f.source, href: journalHref(f, { source: undefined }) });
  if (f.host) chips.push({ key: "host", label: "хост", value: f.host, href: journalHref(f, { host: undefined }) });
  if (f.sev || f.sevMax !== undefined) chips.push({ key: "sev", label: "серьёзность", value: rangeLabel(f.sev ? String(f.sev) : undefined, f.sevMax !== undefined ? String(f.sevMax) : undefined) ?? "", href: journalHref(f, { sev: undefined, sevMax: undefined }) });
  if (f.rule) chips.push({ key: "rule", label: "правило", value: f.rule, href: journalHref(f, { rule: undefined }) });
  if (f.from || f.to) chips.push({ key: "time", label: "интервал UTC", value: `${(f.from ?? "…").replace("T", " ")} — ${(f.to ?? "сейчас").replace("T", " ")}`, href: journalHref(f, { from: undefined, to: undefined }) });
  return chips;
}

/* ===== Гистограмма ===== */

export type SeriesPoint = { bucket: string; low: number; high: number; critical: number };
export type Bar = SeriesPoint & { total: number; startMs: number; endMs: number; from: string; to: string };

const pad = (n: number) => String(n).padStart(2, "0");
/** ms → 'YYYY-MM-DDTHH:MM' в UTC — формат параметров from/to. */
export function toDtParam(ms: number): string {
  const d = new Date(ms);
  return `${d.getUTCFullYear()}-${pad(d.getUTCMonth() + 1)}-${pad(d.getUTCDate())}T${pad(d.getUTCHours())}:${pad(d.getUTCMinutes())}`;
}
/** ms → 'YYYY-MM-DD HH:MM:SS' UTC — формат DateTime ClickHouse. */
export function toChDateTime(ms: number): string {
  return new Date(ms).toISOString().slice(0, 19).replace("T", " ");
}
const bucketMs = (b: string): number => Date.parse(b.replace(" ", "T") + "Z");

/** Границы окна журнала в ms: точный интервал или «сейчас − диапазон». */
export function windowBounds(f: Pick<JournalFilters, "range" | "from" | "to">, now = Date.now()): { startMs: number; endMs: number } {
  if (f.from) {
    const a = Date.parse(f.from + "Z");
    const b = f.to ? Date.parse(f.to + "Z") : now;
    return { startMs: Math.min(a, b), endMs: Math.max(a, b) };
  }
  return { startMs: now - RANGES[f.range].hours * 3_600_000, endMs: now };
}

/**
 * Ряд ClickHouse содержит только непустые корзины; на графике пропуски — тоже
 * данные. Достраиваем нулевые корзины с шагом bucketMinutes от первой
 * найденной (выравнивание toStartOfInterval сохраняется) до границ окна.
 */
export function fillBars(series: SeriesPoint[], bucketMinutes: number, startMs: number, endMs: number, maxBars = 400): Bar[] {
  const step = Math.max(1, bucketMinutes) * 60_000;
  const byMs = new Map<number, SeriesPoint>();
  for (const s of series) {
    const ms = bucketMs(s.bucket);
    if (Number.isFinite(ms)) byMs.set(ms, s);
  }
  if (byMs.size === 0) return [];
  const known = [...byMs.keys()].sort((a, b) => a - b);
  let first = known[0];
  while (first > startMs) first -= step; // корзина, в которую попадает начало окна
  const last = Math.max(known[known.length - 1], endMs);
  const bars: Bar[] = [];
  for (let ms = first; ms <= last && bars.length < maxBars; ms += step) {
    const s = byMs.get(ms);
    const low = Number(s?.low ?? 0), high = Number(s?.high ?? 0), critical = Number(s?.critical ?? 0);
    bars.push({ bucket: toChDateTime(ms), low, high, critical, total: low + high + critical, startMs: ms, endMs: ms + step, from: toDtParam(ms), to: toDtParam(ms + step) });
  }
  return bars;
}

/* ===== Событие ↔ инцидент ===== */

export type JournalEvent = {
  id: string;
  time: string;
  received: string;
  severity: number;
  source: string;
  source_class: string;
  vendor: string;
  product: string;
  action: string;
  outcome: string;
  actor_name: string;
  actor_kind: string;
  object: string;
  node: string;
  session_id: string;
  src_ip: string;
  src_port: number;
  dst_ip: string;
  dst_port: number;
  proto: string;
  bytes: number;
  packets: number;
  /** Телеметрия: измеренное значение и его единица (пусто у событий без метрики). */
  value: number;
  unit: string;
  pii: number;
  attrs: Record<string, string>;
  raw: string;
};


export type IncidentRef = {
  incident_id: string;
  rule_id: string;
  rule_title: string;
  level: string;
  status: string;
  node: string;
  actor_name: string;
  sources: string[];
  first_ts: string;
  last_ts: string;
};

export type EventKey = { id: string; time: string; source: string; node: string; actor_name: string; src_ip: string; object: string };

const tsMs = (s: string): number => Date.parse(s.includes("T") ? s : s.replace(" ", "T") + (/[zZ]|[+-]\d{2}:?\d{2}$/.test(s) ? "" : "Z"));

/**
 * Инцидент связан с событием, если событие из его источника, попало в окно
 * [first_ts; last_ts] (±1 с — округление DateTime) и совпадает узел или
 * субъект инцидента (движок кладёт в actor_name субъект, IP или объект).
 * Прямой ссылки event→incident в схеме нет — это та же логика, по которой
 * движок собирает цепочку.
 */
export function matchIncidents(events: EventKey[], incidents: IncidentRef[]): Record<string, IncidentRef[]> {
  const out: Record<string, IncidentRef[]> = {};
  const prepared = incidents.map((i) => ({ i, a: tsMs(i.first_ts) - 1000, b: tsMs(i.last_ts) + 1000 }));
  for (const e of events) {
    const t = tsMs(e.time);
    const subjects = new Set([e.actor_name, e.src_ip, e.object, e.node].filter(Boolean));
    const hits = prepared
      .filter(({ i, a, b }) => t >= a && t <= b && i.sources.includes(e.source) && ((i.node && i.node === e.node) || (i.actor_name && subjects.has(i.actor_name))))
      .map(({ i }) => i);
    if (hits.length) out[e.id] = hits;
  }
  return out;
}

/* ===== Сырое событие ===== */

export type JsonToken = { t: "key" | "str" | "num" | "lit" | "punct" | "ws"; v: string };

/** Красивый JSON или null, если сырое событие — не JSON (syslog-строка, CEF). */
export function prettyRaw(raw: string): string | null {
  const s = raw.trim();
  if (!s.startsWith("{") && !s.startsWith("[")) return null;
  try {
    return JSON.stringify(JSON.parse(s), null, 2);
  } catch {
    return null;
  }
}

const TOKEN_RE = /("(?:[^"\\]|\\.)*")(\s*:)?|(-?\d+(?:\.\d+)?(?:[eE][+-]?\d+)?)|(true|false|null)|([{}[\],:])|(\s+)/g;

/** Токены строки, выданной JSON.stringify: разбор настоящей грамматикой, а не раскраска «на глаз». */
export function tokenizeJsonLine(line: string): JsonToken[] {
  const out: JsonToken[] = [];
  let m: RegExpExecArray | null;
  TOKEN_RE.lastIndex = 0;
  let pos = 0;
  while ((m = TOKEN_RE.exec(line))) {
    if (m.index > pos) out.push({ t: "punct", v: line.slice(pos, m.index) });
    if (m[1] !== undefined) {
      out.push({ t: m[2] ? "key" : "str", v: m[1] });
      if (m[2]) out.push({ t: "punct", v: m[2] });
    } else if (m[3] !== undefined) out.push({ t: "num", v: m[3] });
    else if (m[4] !== undefined) out.push({ t: "lit", v: m[4] });
    else if (m[5] !== undefined) out.push({ t: "punct", v: m[5] });
    else out.push({ t: "ws", v: m[6] });
    pos = TOKEN_RE.lastIndex;
  }
  if (pos < line.length) out.push({ t: "punct", v: line.slice(pos) });
  return out;
}

/* ===== Live-tail ===== */

/**
 * Курсор tail — пара (received_at, id): received_at с точностью до секунды,
 * id — хеш строки (UInt64). Сравнение кортежем, ORDER BY по той же паре по
 * возрастанию — всплеск любого размера выбирается порциями без потерь.
 */
export type TailCursor = { at: string; after: string };

/**
 * Секунда received_at считается закрытой через TAIL_SEAL_SEC: tail читает
 * только received_at < now() − TAIL_SEAL_SEC. Без этого курсор (секунда, id)
 * пропускал события, которые ClickHouse делал видимыми позже в той же
 * секунде: курсор уже стоял на её последнем id, а новые id могли быть меньше.
 * received_at = DEFAULT now() вычисляется при вставке, а видимой пачка
 * становится при фиксации — запас покрывает эту задержку.
 */
export const TAIL_SEAL_SEC = 2;
/** UInt64 max: курсор «секунда целиком прочитана». */
export const ID_MAX = "18446744073709551615";
const CURSOR_RE = /^(\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2})\|(\d{1,20})$/;

export function formatTailCursor(c: TailCursor): string {
  return `${c.at}|${c.after}`;
}

export function parseTailCursor(s: string | null | undefined): TailCursor | null {
  const m = CURSOR_RE.exec(s ?? "");
  // UInt64 max = 18446744073709551615 (20 цифр): длину проверил RE, значение — сравнением строк.
  if (!m || (m[2].length === 20 && m[2] > ID_MAX)) return null;
  return { at: m[1], after: m[2] };
}

/** Курсор после порции, пришедшей по возрастанию (received_at, id): последняя строка. */
export function advanceCursor(c: TailCursor, batch: Pick<JournalEvent, "received" | "id">[]): TailCursor {
  const last = batch[batch.length - 1];
  return last ? { at: last.received.slice(0, 19), after: last.id } : c;
}

export type TailState = { rows: JournalEvent[]; seen: Set<string> };

/**
 * Влить порцию tail в ленту: новые сверху (лента — по убыванию), дубли по id
 * отброшены, длина ограничена max; seen пересобирается из оставшихся строк —
 * память не растёт, а отрезанные строки не вернутся, потому что курсор
 * монотонен. trimmed — сколько старых строк ушло за нижний край ленты.
 */
export function mergeTail(state: TailState, batchAsc: JournalEvent[], max: number): TailState & { added: JournalEvent[]; trimmed: number } {
  const added: JournalEvent[] = [];
  const ids = new Set(state.seen);
  for (const r of batchAsc) {
    if (ids.has(r.id)) continue;
    ids.add(r.id);
    added.push(r);
  }
  if (added.length === 0) return { ...state, added, trimmed: 0 };
  const all = [...[...added].reverse(), ...state.rows];
  const rows = all.slice(0, max);
  return { rows, seen: new Set(rows.map((r) => r.id)), added, trimmed: all.length - rows.length };
}
