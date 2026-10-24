import "server-only";
// Свободный поиск по алертам Wazuh и по событиям единой схемы (аналог Discover).
// Строка запроса → параметризованный SQL: значения только через {pN:Type},
// имена колонок — только из таблицы полей индекса.
import { ClickHouseError, chQuery } from "./clickhouse";
import { RANGES, type RangeKey } from "./shared/ranges";
import { parseQuery, type Op, type Term } from "./shared/search-query";
import type { SeriesPoint } from "./queries";
import { SEVERITY, type SeverityThresholds } from "./shared/severity";
import { clampInt } from "./shared/limits";
import { wazuhEnabled } from "./integrations";

export type IndexKey = "alerts" | "events";
type Kind = "text" | "exact" | "number" | "array" | "map" | "rule";
type FieldDef = { col: string; kind: Kind; label: string; facet?: boolean };

type IndexDef = {
  table: string;
  tsCol: string;
  /** Где ищется свободный текст */
  haystack: string;
  fields: Record<string, FieldDef>;
  /** Колонки таблицы результатов (в порядке вывода) */
  columns: { key: string; label: string }[];
  select: string;
  severity: { col: string; thresholds: SeverityThresholds };
  notMuted?: string;
  /** Колонки привязки строк сессии разбора (SearchInput.bind). */
  bindCols: { actor?: string; node: string };
};

const NOT_MUTED = `rule_id NOT IN (SELECT rule_id FROM console_rule_mutes GROUP BY rule_id HAVING argMax(muted, updated_at) = 1)`;

export const INDEXES: Record<IndexKey, IndexDef> = {
  alerts: {
    table: "wazuh_alerts",
    tsCol: "timestamp",
    haystack: "raw",
    fields: {
      agent: { col: "agent_name", kind: "exact", label: "агент", facet: true },
      "agent.id": { col: "agent_id", kind: "exact", label: "id агента" },
      "agent.ip": { col: "agent_ip", kind: "exact", label: "ip агента" },
      rule: { col: "rule_id", kind: "number", label: "правило", facet: true },
      level: { col: "rule_level", kind: "number", label: "уровень", facet: true },
      desc: { col: "rule_description", kind: "text", label: "описание" },
      group: { col: "rule_groups", kind: "array", label: "группа", facet: true },
      mitre: { col: "mitre_ids", kind: "array", label: "MITRE" },
      tactic: { col: "mitre_tactics", kind: "array", label: "тактика" },
      decoder: { col: "decoder_name", kind: "exact", label: "декодер", facet: true },
      location: { col: "location", kind: "exact", label: "источник лога" },
      srcip: { col: "srcip", kind: "exact", label: "srcip", facet: true },
      manager: { col: "manager_name", kind: "exact", label: "менеджер" },
      log: { col: "full_log", kind: "text", label: "полный лог" },
    },
    columns: [
      { key: "time", label: "Время" }, { key: "rule_level", label: "Ур." }, { key: "rule_id", label: "Правило" },
      { key: "rule_description", label: "Описание" }, { key: "agent_name", label: "Агент" }, { key: "srcip", label: "srcip" }, { key: "location", label: "Источник" },
    ],
    // ВАЖНО: алиасы в select не должны повторять имена колонок таблицы —
  // ClickHouse подставит алиас и в WHERE (см. has(rule_groups, …)).
  select: `toString(timestamp) AS time, rule_level, rule_id, rule_description, agent_name, agent_id, srcip, location, decoder_name,
             arrayStringConcat(rule_groups, ', ') AS groups, arrayStringConcat(mitre_ids, ', ') AS mitre, full_log, raw`,
    severity: { col: "rule_level", thresholds: SEVERITY.alerts },
    notMuted: NOT_MUTED,
    bindCols: { node: "agent_name" },
  },
  events: {
    table: "events",
    tsCol: "ts",
    haystack: "concat(raw, ' ', actor_name, ' ', object, ' ', node, ' ', src_ip, ' ', dst_ip, ' ', action, ' ', toString(attrs))",
    fields: {
      source: { col: "source", kind: "exact", label: "источник", facet: true },
      class: { col: "source_class", kind: "exact", label: "класс", facet: true },
      vendor: { col: "vendor", kind: "exact", label: "вендор" },
      product: { col: "product", kind: "exact", label: "продукт" },
      action: { col: "action", kind: "exact", label: "действие", facet: true },
      outcome: { col: "outcome", kind: "exact", label: "исход", facet: true },
      severity: { col: "severity", kind: "number", label: "серьёзность" },
      actor: { col: "actor_name", kind: "exact", label: "субъект", facet: true },
      object: { col: "object", kind: "text", label: "объект" },
      node: { col: "node", kind: "exact", label: "узел", facet: true },
      src: { col: "src_ip", kind: "exact", label: "src ip", facet: true },
      dst: { col: "dst_ip", kind: "exact", label: "dst ip" },
      sport: { col: "src_port", kind: "number", label: "src port" },
      dport: { col: "dst_port", kind: "number", label: "dst port" },
      proto: { col: "proto", kind: "exact", label: "протокол" },
      pii: { col: "pii", kind: "number", label: "ПДн" },
      attr: { col: "attrs", kind: "map", label: "атрибут attr.<ключ>" },
      // rule:5763 — правило Wazuh (action rule.5763); rule:a41c-auth-030 — правило
      // корреляции: события источника и узла его инцидентов внутри окна инцидента.
      rule: { col: "action", kind: "rule", label: "правило" },
    },
    columns: [
      { key: "time", label: "Время" }, { key: "severity", label: "Ур." }, { key: "source", label: "Источник" }, { key: "action", label: "Действие" },
      { key: "actor_name", label: "Субъект" }, { key: "object", label: "Объект" }, { key: "node", label: "Узел" }, { key: "src_ip", label: "src" }, { key: "dst_ip", label: "dst" },
    ],
    select: `toString(ts) AS time, severity, source, source_class, action, outcome, actor_name, object, node, src_ip, dst_ip, src_port, dst_port, proto, pii, toString(attrs) AS attributes, raw`,
    severity: { col: "severity", thresholds: SEVERITY.events },
    bindCols: { actor: "actor_name", node: "node" },
  },
};

/** Индекс по умолчанию — alerts при включённом модуле Wazuh, иначе events. */
export function parseIndex(v: string | undefined): IndexKey {
  if (v === "events" || v === "alerts") return v;
  return wazuhEnabled() ? "alerts" : "events";
}

/** Индексы, доступные в этой установке (alerts — только с модулем Wazuh). */
export function availableIndexes(): IndexKey[] {
  return wazuhEnabled() ? ["alerts", "events"] : ["events"];
}

export const WAZUH_DISABLED_ERROR = "индекс alerts недоступен: модуль Wazuh выключен (ARGUS_INTEGRATION_WAZUH)";

export type SearchInput = {
  index: IndexKey;
  q: string;
  range: RangeKey;
  from?: string; // 'YYYY-MM-DDTHH:MM' (UTC), переопределяет range
  to?: string;
  page: number;
  showMuted?: boolean;
  /** false — без фасетов (сессия разбора): запрос фасетов не выполняется. */
  facets?: boolean;
  /** Сессия разбора: строки только своего субъекта или своих узлов —
   *  обязательный предикат в WHERE (и строк, и гистограммы). */
  bind?: { actors: string[]; nodes: string[] };
};

export type SearchResult = {
  rows: Record<string, unknown>[];
  total: number;
  page: number;
  pageSize: number;
  series: SeriesPoint[];
  facets: { field: string; label: string; values: { value: string; count: number }[] }[];
  error: string | null;
  ms: number;
};

export const PAGE_SIZE = 50;
/** Потолок страницы: 200 × 50 = 10 000 строк — столько же отдаёт экспорт. */
export const MAX_PAGE = 200;
export const MAX_TERMS = 32;
export const MAX_QUERY_LEN = 2000;
const DT_RE = /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}(:\d{2})?$/;
/** Серверные лимиты на поисковые запросы: консольный пользователь без квот,
 *  а поиск по raw за 30 дней — полный скан. */
export const SEARCH_SETTINGS = { max_execution_time: 20, max_memory_usage: 2_000_000_000, max_result_rows: 20000, result_overflow_mode: "break" } as const;

export function clampPage(v: string | number | undefined): number {
  return clampInt(v, 1, MAX_PAGE, 1);
}

/** 'YYYY-MM-DDTHH:MM[:SS]' → 'YYYY-MM-DD HH:MM:SS' или null, если дата невалидна. */
function parseDt(v: string | undefined): { ch: string; ms: number } | null {
  if (!v || !DT_RE.test(v)) return null;
  const ms = Date.parse(v + "Z");
  if (!Number.isFinite(ms)) return null;
  const [d, t] = v.split("T");
  return { ch: `${d} ${t.length === 5 ? t + ":00" : t}`, ms };
}

type Built = { where: string; params: Record<string, string | number>; error: string | null; bucketMinutes: number };

/** Условие WHERE из строки запроса и диапазона. Ошибка — неизвестное поле/оператор. */
export function buildWhere(input: SearchInput): Built {
  const def = INDEXES[input.index];
  const params: Record<string, string | number> = {};
  const conds: string[] = [];
  let bucketMinutes = RANGES[input.range].bucketMinutes;

  const from = parseDt(input.from);
  if (input.from && !from) return { where: "", params, error: "начало интервала: ожидается дата вида 2026-09-13T10:00 (UTC)", bucketMinutes };
  if (from) {
    // Точный интервал: конец — не позже «сейчас», перепутанные границы меняем местами.
    let to = parseDt(input.to) ?? { ch: "", ms: Date.now() };
    if (input.to && !parseDt(input.to)) return { where: "", params, error: "конец интервала: ожидается дата вида 2026-09-13T23:59 (UTC)", bucketMinutes };
    let start = from;
    if (to.ms < start.ms) [start, to] = [to as { ch: string; ms: number }, start];
    params.from = start.ch;
    conds.push(`${def.tsCol} >= toDateTime({from:String}, 'UTC')`);
    if (to.ch) {
      params.to = to.ch;
      conds.push(`${def.tsCol} <= toDateTime({to:String}, 'UTC')`);
    }
    bucketMinutes = Math.max(1, Math.round((to.ms - start.ms) / 60000 / 48));
  } else {
    params.hours = RANGES[input.range].hours;
    conds.push(`${def.tsCol} >= now() - INTERVAL {hours:UInt32} HOUR`);
  }
  if (def.notMuted && !input.showMuted) conds.push(def.notMuted);

  let n = 0;
  const p = (value: string | number, type: string): string => {
    const name = `p${n++}`;
    params[name] = value;
    return `{${name}:${type}}`;
  };
  const errors: string[] = [];
  const terms = parseQuery(input.q.slice(0, MAX_QUERY_LEN));
  if (terms.length > MAX_TERMS) errors.push(`слишком много условий: ${terms.length}, максимум ${MAX_TERMS}`);
  for (const t of terms.slice(0, MAX_TERMS)) {
    const c = termCondition(def, t, p, errors);
    if (c) conds.push(t.negate ? `NOT (${c})` : c);
  }
  if (input.bind) conds.push(bindCondition(def, input.bind, p));
  return { where: conds.join(" AND "), params, error: errors[0] ?? null, bucketMinutes };
}

/** Привязка строк сессии разбора: (actor IN … OR node IN …); у алертов —
 *  только agent_name IN …. Нечем привязать — «0»: ни одной строки. */
function bindCondition(def: IndexDef, bind: { actors: string[]; nodes: string[] }, p: (v: string | number, type: string) => string): string {
  const parts: string[] = [];
  const list = (vs: string[]) => vs.map((v) => p(v, "String")).join(", ");
  if (def.bindCols.actor && bind.actors.length) parts.push(`${def.bindCols.actor} IN (${list(bind.actors)})`);
  if (bind.nodes.length) parts.push(`${def.bindCols.node} IN (${list(bind.nodes)})`);
  return parts.length ? `(${parts.join(" OR ")})` : "0";
}

const NUM_OPS: Record<Op, string> = { "=": "=", "!=": "!=", ">": ">", ">=": ">=", "<": "<", "<=": "<=" };

function termCondition(def: IndexDef, t: Term, p: (v: string | number, type: string) => string, errors: string[]): string | null {
  if (t.field === null) {
    return `positionCaseInsensitiveUTF8(${def.haystack}, ${p(t.value, "String")}) > 0`;
  }
  let f = def.fields[t.field];
  let mapKey: string | null = null;
  if (!f && t.field.startsWith("attr.") && def.fields.attr) {
    f = def.fields.attr;
    mapKey = t.field.slice(5);
  }
  if (!f) {
    errors.push(`неизвестное поле «${t.field}»; доступны: ${Object.keys(def.fields).join(", ")}`);
    return null;
  }
  // Маска — у значения без кавычек и у ~"…"; в обычных кавычках «*» буквальная
  // (точные фильтры MCP, фасеты). Старая маска в кавычках — подсказка, а не пустая выдача.
  if (t.starInQuotes) {
    errors.push(`«${t.field}»: маска «*» в кавычках больше не работает — для маски уберите кавычки или напишите ${t.field}:~"${t.value}", для буквальной звёздочки — \\*`);
    return null;
  }
  const wildcard = (!t.quoted || t.mask === true) && t.value.includes("*");
  const like = () => p(t.value.replace(/[\\%_]/g, "\\$&").replace(/\*/g, "%"), "String");
  if (f.kind !== "number" && t.op !== "=" && t.op !== "!=") {
    errors.push(`для поля «${t.field}» допустимы только = и !=`);
    return null;
  }
  switch (f.kind) {
    case "number": {
      const num = Number(t.value);
      if (!Number.isFinite(num)) {
        errors.push(`поле «${t.field}» числовое, а значение «${t.value}» — нет`);
        return null;
      }
      return `${f.col} ${NUM_OPS[t.op]} ${p(num, "Float64")}`;
    }
    case "array": {
      const c = wildcard ? `arrayExists(x -> x ILIKE ${like()}, ${f.col})` : `has(${f.col}, ${p(t.value, "String")})`;
      return t.op === "!=" ? `NOT ${c}` : c;
    }
    case "map": {
      if (!mapKey) { errors.push("атрибут указывается как attr.<ключ>:значение"); return null; }
      const c = wildcard ? `${f.col}[${p(mapKey, "String")}] ILIKE ${like()}` : `${f.col}[${p(mapKey, "String")}] = ${p(t.value, "String")}`;
      return t.op === "!=" ? `NOT (${c})` : c;
    }
    case "rule": {
      const c = /^\d+$/.test(t.value)
        ? `${f.col} = concat('rule.', ${p(t.value, "String")})`
        : // Правило корреляции: событие из источника и с узла инцидента этого
          // правила и внутри его окна [first_ts; last_ts]. Окна — одним
          // скалярным подзапросом, проверка — arrayExists. LIMIT 5000 отрезает
          // старые окна у шумного правила (подсказка поля и README об этом говорят).
          `arrayExists(w -> source = w.1 AND node = w.2 AND ts >= w.3 AND ts <= w.4, (SELECT groupArray((s, inode, ifirst, ilast)) FROM (SELECT arrayJoin(sources) AS s, node AS inode, first_ts AS ifirst, last_ts AS ilast FROM incidents_current WHERE ${wildcard ? `rule_id ILIKE ${like()}` : `rule_id = ${p(t.value, "String")}`} ORDER BY last_ts DESC LIMIT 5000)))`;
      return t.op === "!=" ? `NOT (${c})` : c;
    }
    case "text": {
      const c = wildcard ? `${f.col} ILIKE ${like()}` : `positionCaseInsensitiveUTF8(${f.col}, ${p(t.value, "String")}) > 0`;
      return t.op === "!=" ? `NOT (${c})` : c;
    }
    default: {
      const c = wildcard ? `${f.col} ILIKE ${like()}` : `${f.col} = ${p(t.value, "String")}`;
      return t.op === "!=" ? `NOT (${c})` : c;
    }
  }
}

/** Фасеты одним сканом: пары (поле, значение) через arrayJoin в подзапросе
 *  (arrayJoin в SELECT подменил бы колонки и в WHERE), LIMIT 6 BY field. */
function facetsSql(def: IndexDef, where: string): string {
  const pairs = Object.entries(def.fields).filter(([, f]) => f.facet);
  const scalars = pairs.filter(([, f]) => f.kind !== "array").map(([name, f]) => `('${name}', toString(${f.col}))`);
  const arrays = pairs.filter(([, f]) => f.kind === "array").map(([name, f]) => `arrayMap(x -> ('${name}', toString(x)), ${f.col})`);
  const tuples = `arrayConcat([${scalars.join(", ")}]${arrays.map((a) => `, ${a}`).join("")})`;
  return `SELECT fv.1 AS field, fv.2 AS value, count() AS count
          FROM (SELECT arrayJoin(${tuples}) AS fv FROM ${def.table} WHERE ${where})
          WHERE value != '' GROUP BY field, value ORDER BY count DESC LIMIT 6 BY field`;
}

/** Коды ошибок ClickHouse (ErrorCodes.cpp): 159 TIMEOUT_EXCEEDED, 241 MEMORY_LIMIT_EXCEEDED. */
const CH_TIMEOUT_EXCEEDED = 159;
const CH_MEMORY_LIMIT_EXCEEDED = 241;

/** Ошибка ClickHouse — в панель запроса, а не 500: классификация по коду
 *  сервера, а не по тексту (он зависит от версии и локали); текст — только в лог. */
export function searchErrorMessage(e: unknown): string {
  const code = e instanceof ClickHouseError ? e.code : null;
  if (code === CH_TIMEOUT_EXCEEDED) return `запрос не уложился в ${SEARCH_SETTINGS.max_execution_time} с — сузьте интервал или добавьте поле`;
  if (code === CH_MEMORY_LIMIT_EXCEEDED) return "запросу не хватило памяти — сузьте интервал";
  return "хранилище недоступно или запрос отклонён — подробности в логе консоли";
}

export async function search(input: SearchInput): Promise<SearchResult> {
  const def = INDEXES[input.index];
  const built = buildWhere(input);
  const page = clampPage(input.page);
  const empty: SearchResult = { rows: [], total: 0, page, pageSize: PAGE_SIZE, series: [], facets: [], error: built.error, ms: 0 };
  if (input.index === "alerts" && !wazuhEnabled()) return { ...empty, error: WAZUH_DISABLED_ERROR };
  if (built.error) return empty;
  const started = Date.now();
  const { where, params, bucketMinutes } = built;
  const offset = (page - 1) * PAGE_SIZE;
  const th = def.severity.thresholds;
  const sevCol = def.severity.col;
  const facetFields = Object.entries(def.fields).filter(([, f]) => f.facet);

  try {
    const [rows, series, facetRows] = await Promise.all([
      chQuery<Record<string, unknown>>(
        `SELECT ${def.select} FROM ${def.table} WHERE ${where} ORDER BY ${def.tsCol} DESC LIMIT {limit:UInt32} OFFSET {offset:UInt32}`,
        { ...params, limit: PAGE_SIZE, offset },
        SEARCH_SETTINGS,
      ),
      chQuery<SeriesPoint>(
        `SELECT toString(toStartOfInterval(${def.tsCol}, INTERVAL {bucket:UInt32} MINUTE)) AS bucket,
                countIf(${sevCol} < {high:UInt8}) AS low,
                countIf(${sevCol} >= {high:UInt8} AND ${sevCol} < {critical:UInt8}) AS high,
                countIf(${sevCol} >= {critical:UInt8}) AS critical
         FROM ${def.table} WHERE ${where} GROUP BY bucket ORDER BY bucket`,
        { ...params, bucket: bucketMinutes, high: th.high, critical: th.critical },
        SEARCH_SETTINGS,
      ),
      input.facets === false
        ? Promise.resolve([] as { field: string; value: string; count: number }[])
        : chQuery<{ field: string; value: string; count: number }>(facetsSql(def, where), params, SEARCH_SETTINGS).catch(
            () => [] as { field: string; value: string; count: number }[],
          ),
    ]);
    const normalized = series.map((s) => ({ ...s, low: Number(s.low), high: Number(s.high), critical: Number(s.critical) }));
    const total = normalized.reduce((n, s) => n + s.low + s.high + s.critical, 0); // итог — сумма гистограммы, без отдельного count()
    return {
      rows,
      total,
      page,
      pageSize: PAGE_SIZE,
      series: normalized,
      facets: input.facets === false ? [] : facetFields.map(([name, f]) => ({
        field: name,
        label: f.label,
        values: facetRows.filter((r) => r.field === name).map((r) => ({ value: r.value, count: Number(r.count) })),
      })),
      error: null,
      ms: Date.now() - started,
    };
  } catch (e) {
    console.error("search:", e instanceof Error ? e.message : e);
    return { ...empty, error: searchErrorMessage(e) };
  }
}

/** Выгрузка для отчёта: до 10 000 строк без пагинации. */
export async function searchExport(input: SearchInput, limit = 10000, withRaw = true): Promise<{ rows: Record<string, unknown>[]; error: string | null }> {
  const def = INDEXES[input.index];
  if (input.index === "alerts" && !wazuhEnabled()) return { rows: [], error: WAZUH_DISABLED_ERROR };
  const built = buildWhere(input);
  if (built.error) return { rows: [], error: built.error };
  const select = withRaw ? def.select : def.select.replace(/,\s*raw\s*$/, "");
  try {
    const rows = await chQuery<Record<string, unknown>>(
      `SELECT ${select} FROM ${def.table} WHERE ${built.where} ORDER BY ${def.tsCol} DESC LIMIT {limit:UInt32}`,
      { ...built.params, limit: Math.min(10000, Math.max(1, Math.floor(limit) || 1)) },
      SEARCH_SETTINGS,
    );
    return { rows, error: null };
  } catch (e) {
    console.error("searchExport:", e instanceof Error ? e.message : e);
    return { rows: [], error: "хранилище недоступно или запрос отклонён — подробности в логе консоли" };
  }
}

/** CSV для Excel/LibreOffice: BOM для кириллицы; значения из логов, начинающиеся
 *  с = + - @ или табуляции, получают префикс ' — иначе табличный процессор
 *  выполнит их как формулу (CSV-инъекция). */
export function toCsv(rows: Record<string, unknown>[]): string {
  if (rows.length === 0) return "\uFEFF";
  const cols = Object.keys(rows[0]);
  const esc = (v: unknown) => {
    let s = v === null || v === undefined ? "" : String(v);
    if (/^[=+\-@\t\r]/.test(s)) s = "'" + s;
    return /[",\n\r']/.test(s) || s.startsWith("'") ? `"${s.replace(/"/g, '""')}"` : s;
  };
  return "\uFEFF" + [cols.join(","), ...rows.map((r) => cols.map((c) => esc(r[c])).join(","))].join("\r\n") + "\r\n";
}
