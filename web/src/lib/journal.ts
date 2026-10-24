import "server-only";
// Журнал событий: лента единой схемы events с фильтрами, гистограммой по
// серьёзности, live-tail и связью с инцидентами. Условия WHERE — тот же
// параметризованный построитель, что у поиска (buildWhere), значения — только {pN:Type}.
import { chQuery } from "./clickhouse";
import { buildWhere, searchErrorMessage, SEARCH_SETTINGS, type SearchInput } from "./search";
import { advanceCursor, formatTailCursor, ID_MAX, journalQuery, TAIL_SEAL_SEC, matchIncidents, toDtParam, type IncidentRef, type JournalEvent, type JournalFilters, type SeriesPoint, type TailCursor } from "./shared/journal";

export type { JournalEvent };
import { SEVERITY } from "./shared/severity";

export const JOURNAL_PAGE_SIZE = 50;
export const JOURNAL_MAX_PAGE = 200;
export const TAIL_LIMIT = 100;
/** Окно ts для tail относительно курсора: события, задержанные у источника
 *  дольше, в live не попадут, но видны в ленте после обновления страницы.
 *  Узкое окно — чтобы опрос раз в 5 с не сканировал сутки партиций. */
export const TAIL_TS_SLACK_MIN = 60;

/** Идентификатор строки: received_at различает повторы, принятые в разные
 *  секунды; нормализованные поля — события с общим raw (коллектор кладёт в
 *  raw исходную запись, а одна запись CEF/JSON может дать несколько событий).
 *  Полностью одинаковые события в одну секунду неразличимы — это дубли. */
const HID = "cityHash64(received_at, ts, source, node, action, outcome, actor_name, object, src_ip, src_port, dst_ip, dst_port, raw)";

const SELECT = `toString(ts) AS time, toString(received_at) AS received,
  toString(${HID}) AS id,
  severity, source, source_class, vendor, product, action, outcome, actor_name, actor_kind, object, node, session_id,
  src_ip, src_port, dst_ip, dst_port, proto, bytes, packets, value, unit, pii, attrs, raw`;

function normalize(r: JournalEvent): JournalEvent {
  return {
    ...r,
    severity: Number(r.severity),
    src_port: Number(r.src_port),
    dst_port: Number(r.dst_port),
    bytes: Number(r.bytes),
    packets: Number(r.packets),
    value: Number(r.value ?? 0),
    unit: String(r.unit ?? ""),
    pii: Number(r.pii),
    attrs: r.attrs && typeof r.attrs === "object" ? r.attrs : {},
  };
}

function toSearchInput(f: JournalFilters): SearchInput {
  return { index: "events", q: journalQuery(f), range: f.range, from: f.from, to: f.to, page: 1 };
}

export type JournalResult = {
  rows: JournalEvent[];
  total: number;
  page: number;
  pageSize: number;
  series: SeriesPoint[];
  bucketMinutes: number;
  incidents: Record<string, IncidentRef[]>;
  options: { sources: string[]; hosts: string[] };
  error: string | null;
  ms: number;
  /** Курсор live-tail «received_at|id» — часы ClickHouse, а не консоли. */
  cursor: string;
};

export async function journalSearch(f: JournalFilters): Promise<JournalResult> {
  const page = Math.min(JOURNAL_MAX_PAGE, Math.max(1, f.page ?? 1));
  const built = buildWhere(toSearchInput(f));
  const base: JournalResult = { rows: [], total: 0, page, pageSize: JOURNAL_PAGE_SIZE, series: [], bucketMinutes: built.bucketMinutes, incidents: {}, options: { sources: [], hosts: [] }, error: built.error, ms: 0, cursor: "" };
  // Варианты для выпадающих списков — по окну времени, без остальных фильтров:
  // иначе выбранный источник «съел» бы все остальные варианты.
  const timeOnly = buildWhere({ ...toSearchInput({ ...f, q: "", source: undefined, host: undefined, sev: undefined, rule: undefined }) });
  const started = Date.now();
  let cursor = "";
  try {
    // Начальный курсор — последняя закрытая секунда по часам ClickHouse, снятая
    // до выборки страницы: всё, что позже, tail прочитает, когда секунда
    // закроется; пересечение со страницей снимет дедупликация по id на клиенте.
    const [{ n }] = await chQuery<{ n: string }>("SELECT toString(now() - {seal:UInt32} - 1) AS n", { seal: TAIL_SEAL_SEC }, SEARCH_SETTINGS);
    cursor = formatTailCursor({ at: n, after: ID_MAX });
    const optionsP = Promise.all([
      chQuery<{ v: string }>(`SELECT source AS v FROM events WHERE ${timeOnly.where} GROUP BY v ORDER BY count() DESC LIMIT 100`, timeOnly.params, SEARCH_SETTINGS),
      chQuery<{ v: string }>(`SELECT node AS v FROM events WHERE ${timeOnly.where} AND node != '' GROUP BY v ORDER BY count() DESC LIMIT 200`, timeOnly.params, SEARCH_SETTINGS),
    ]);
    if (built.error) {
      const [s, h] = await optionsP;
      return { ...base, cursor, options: { sources: s.map((r) => r.v), hosts: h.map((r) => r.v) } };
    }
    const th = SEVERITY.events;
    const [rows, series, [s, h]] = await Promise.all([
      chQuery<JournalEvent>(
        `SELECT ${SELECT} FROM events WHERE ${built.where} ORDER BY ts DESC LIMIT {limit:UInt32} OFFSET {offset:UInt32}`,
        { ...built.params, limit: JOURNAL_PAGE_SIZE, offset: (page - 1) * JOURNAL_PAGE_SIZE },
        SEARCH_SETTINGS,
      ),
      chQuery<SeriesPoint>(
        `SELECT toString(toStartOfInterval(ts, INTERVAL {bucket:UInt32} MINUTE)) AS bucket,
                countIf(severity < {high:UInt8}) AS low,
                countIf(severity >= {high:UInt8} AND severity < {critical:UInt8}) AS high,
                countIf(severity >= {critical:UInt8}) AS critical
         FROM events WHERE ${built.where} GROUP BY bucket ORDER BY bucket`,
        { ...built.params, bucket: built.bucketMinutes, high: th.high, critical: th.critical },
        SEARCH_SETTINGS,
      ),
      optionsP,
    ]);
    const events = rows.map(normalize);
    const normalized = series.map((p) => ({ bucket: p.bucket, low: Number(p.low), high: Number(p.high), critical: Number(p.critical) }));
    return {
      ...base,
      cursor,
      rows: events,
      total: normalized.reduce((n, p) => n + p.low + p.high + p.critical, 0),
      series: normalized,
      incidents: await relatedIncidents(events),
      options: { sources: s.map((r) => r.v), hosts: h.map((r) => r.v) },
      ms: Date.now() - started,
    };
  } catch (e) {
    console.error("journal:", e instanceof Error ? e.message : e);
    return { ...base, error: searchErrorMessage(e) };
  }
}

export type TailResult = {
  /** Порция по возрастанию (received_at, id) — клиент вливает её сверху. */
  rows: JournalEvent[];
  incidents: Record<string, IncidentRef[]>;
  cursor: string;
  /** Порция заполнена до лимита: за курсором есть ещё — клиент запрашивает сразу, без паузы. */
  more: boolean;
  /** Сколько событий ещё ждёт за курсором (считается только при more). */
  pending: number;
  error: string | null;
};

/**
 * Новые события после курсора (received_at, id). Выборка по возрастанию
 * порциями TAIL_LIMIT: всплеск больше лимита догоняется за несколько
 * запросов, а не теряется (раньше ORDER BY DESC LIMIT отдавал только верх).
 */
export async function journalTail(f: JournalFilters, c: TailCursor): Promise<TailResult> {
  const fromMs = Date.parse(c.at.replace(" ", "T") + "Z") - TAIL_TS_SLACK_MIN * 60_000;
  const built = buildWhere(toSearchInput({ ...f, from: toDtParam(fromMs), to: undefined }));
  const empty: TailResult = { rows: [], incidents: {}, cursor: formatTailCursor(c), more: false, pending: 0, error: built.error };
  if (built.error) return empty;
  // Только закрытые секунды (см. TAIL_SEAL_SEC): событие, ставшее видимым позже
  // в уже прочитанной секунде, иначе оказалось бы позади курсора навсегда.
  const sealed = `received_at < now() - {seal:UInt32}`;
  const where = `${built.where} AND ${sealed} AND (received_at, ${HID}) > (toDateTime({since:String}, 'UTC'), toUInt64({after:String}))`;
  const params = { ...built.params, since: c.at, after: c.after, seal: TAIL_SEAL_SEC };
  try {
    const rows = (
      await chQuery<JournalEvent>(
        `SELECT ${SELECT} FROM events WHERE ${where} ORDER BY received_at ASC, ${HID} ASC LIMIT {limit:UInt32}`,
        { ...params, limit: TAIL_LIMIT },
        SEARCH_SETTINGS,
      )
    ).map(normalize);
    const next = advanceCursor(c, rows);
    const more = rows.length === TAIL_LIMIT;
    let pending = 0;
    if (more) {
      const [cnt] = await chQuery<{ c: string }>(
        `SELECT count() AS c FROM events WHERE ${built.where} AND ${sealed} AND (received_at, ${HID}) > (toDateTime({since:String}, 'UTC'), toUInt64({after:String}))`,
        { ...built.params, since: next.at, after: next.after, seal: TAIL_SEAL_SEC },
        SEARCH_SETTINGS,
      );
      pending = Number(cnt?.c ?? 0);
    }
    return { rows, incidents: await relatedIncidents(rows), cursor: formatTailCursor(next), more, pending, error: null };
  } catch (e) {
    console.error("journal tail:", e instanceof Error ? e.message : e);
    return { ...empty, error: searchErrorMessage(e) };
  }
}

/** Инциденты, к которым относятся события страницы: один запрос по окну и источникам, сопоставление — matchIncidents. */
async function relatedIncidents(events: JournalEvent[]): Promise<Record<string, IncidentRef[]>> {
  if (events.length === 0) return {};
  const times = events.map((e) => e.time).sort();
  const sources = [...new Set(events.map((e) => e.source))].filter((s) => !s.includes(","));
  try {
    // Алиасы не повторяют имена колонок: ClickHouse подставил бы алиас и в WHERE.
    const rows = await chQuery<Omit<IncidentRef, "first_ts" | "last_ts"> & { first_s: string; last_s: string }>(
      `SELECT incident_id, rule_id, rule_title, level, status, node, actor_name, sources,
              toString(first_ts) AS first_s, toString(last_ts) AS last_s
       FROM incidents_current
       WHERE last_ts >= toDateTime64({min:String}, 3, 'UTC') - INTERVAL 1 SECOND
         AND first_ts <= toDateTime64({max:String}, 3, 'UTC') + INTERVAL 1 SECOND
         AND hasAny(sources, splitByChar(',', {sources:String}))
       ORDER BY created_at DESC LIMIT 500`,
      { min: times[0], max: times[times.length - 1], sources: sources.join(",") },
      SEARCH_SETTINGS,
    );
    const incidents = rows.map(({ first_s, last_s, ...i }) => ({ ...i, first_ts: first_s, last_ts: last_s }));
    return matchIncidents(events, incidents);
  } catch (e) {
    // Связь с инцидентом — подсказка, а не основная выдача: журнал без неё работает.
    console.error("journal incidents:", e instanceof Error ? e.message : e);
    return {};
  }
}
