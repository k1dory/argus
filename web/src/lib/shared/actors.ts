// Паспорт субъекта: типы персоны и алиасов, разбор параметров, сборка
// предиката по алиасам с учётом интервалов действия, классификация событий
// по разделам паспорта и Markdown-экспорт. Чистые функции — без БД и Next.
//
// Паспорт — представление над журналом argus.events, а не отдельная база:
// срез по человеку за период строится по ключу идентичности с учётом времени
// действия алиасов (кто сидел на адресе в июле — из истории, не из снимка).
import { chTs, type LogItem } from "./log-query";
import { RANGES } from "./ranges";
import { literal } from "./incident-wiki";
import { termToString } from "./search-query";

export const ALIAS_KINDS = ["email", "login", "uid", "ip", "host", "sid", "peer", "phone"] as const;
export type AliasKind = (typeof ALIAS_KINDS)[number];
export const isAliasKind = (x: unknown): x is AliasKind => typeof x === "string" && (ALIAS_KINDS as readonly string[]).includes(x);

/** Виды алиасов, сравниваемые без учёта регистра (хранятся в нижнем). */
export const LOWERCASE_KINDS: readonly AliasKind[] = ["email", "login", "host"];
/** Виды, значения которых ищутся в actor_name событий и инцидентов. */
export const ACTOR_KINDS: readonly AliasKind[] = ["email", "login", "uid", "sid", "peer", "phone"];

/* ===== Алиасы «на удержании» =====
 * Движок при нарушении политики идентичности (слишком много логинов у одной
 * персоны за окно и т. п.) не отбрасывает алиас, а записывает его с
 * confidence < HOLD_CONFIDENCE и note вида «policy:hold:<политика>». Такой
 * алиас виден в паспорте с пометкой, но в сшивке событий, резолве и подсчётах
 * не участвует, пока администратор его не подтвердит (confidence = 1). */
export const HOLD_CONFIDENCE = 0.5;
export const HOLD_NOTE_PREFIX = "policy:hold:";
/** Пометка подтверждённого алиаса: тот же текст политики, другой префикс. */
export const CONFIRMED_NOTE_PREFIX = "policy:confirmed:";

export const isHeld = (a: Pick<Alias, "confidence">): boolean => a.confidence < HOLD_CONFIDENCE;

/** Текст политики из note удержанного алиаса (без префикса); null — пометки нет. */
export function holdPolicy(a: Pick<Alias, "confidence" | "note">): string | null {
  if (!isHeld(a)) return null;
  return a.note.startsWith(HOLD_NOTE_PREFIX) ? a.note.slice(HOLD_NOTE_PREFIX.length) : a.note || null;
}

/** Алиасы, участвующие в сшивке: без удержанных. */
export const activeAliases = <T extends Pick<Alias, "confidence">>(aliases: T[]): T[] => aliases.filter((a) => !isHeld(a));

export const PERSON_ID_RE = /^[a-z0-9][a-z0-9._-]{0,63}$/;
export const PERSON_KINDS = ["person", "service"] as const;
export type PersonKind = (typeof PERSON_KINDS)[number];
export const ALIAS_VALUE_MAX = 256;
export const TEXT_MAX = 500;

export type Person = { person_id: string; display: string; kind: PersonKind; team: string; note: string };

/** Алиас: valid_to === null — действует сейчас. Время — строки ClickHouse (UTC). */
export type Alias = {
  person_id: string;
  kind: AliasKind;
  value: string;
  valid_from: string;
  valid_to: string | null;
  source: string;
  confidence: number;
  note: string;
};

export type AliasColumn = "actor_name" | "src_ip" | "node";

/** Колонка события, с которой сравнивается алиас данного вида. */
export function aliasColumn(kind: AliasKind): AliasColumn {
  if (kind === "ip") return "src_ip";
  if (kind === "host") return "node";
  return "actor_name";
}

/** SQL-выражение колонки для сравнения с алиасом: email/login/host хранятся в
 *  нижнем регистре, поэтому колонка тоже приводится (bloom-индекс при этом не
 *  работает — окно паспорта не шире 30 дней, это допустимо); ip/uid/sid/peer — точно. */
export function aliasColumnExpr(kind: AliasKind, column: string = aliasColumn(kind)): string {
  return LOWERCASE_KINDS.includes(kind) ? `lowerUTF8(${column})` : column;
}

/** Значение алиаса в том виде, в каком его сравнивают с колонкой: email/login/host
 *  — в нижнем регистре (как предикат с lowerUTF8), uid/sid/peer/ip — точно. */
export function compareValue(a: Pick<Alias, "kind" | "value">): string {
  return LOWERCASE_KINDS.includes(a.kind) ? a.value.toLowerCase() : a.value;
}

/** Ключ неоднозначности: целевая колонка + нормализованное значение. login=alice
 *  одного человека и uid=alice другого сопоставляются с одним actor_name и
 *  получают одни события — вид алиаса здесь не разделяет. */
export const aliasKey = (a: Pick<Alias, "kind" | "value">): string => `${aliasColumn(a.kind)}\u0000${compareValue(a)}`;

/** Нормализация значения алиаса, как у движка: email/login/host — нижний
 *  регистр и обрезка пробелов; ip — каноническая форма адреса (если разобрался);
 *  phone — E.164 без пробелов, дефисов и скобок (если разобрался). */
export function normalizeAliasValue(kind: AliasKind, value: string): string {
  const v = value.trim();
  if (kind === "ip") return canonicalIp(v) ?? v;
  if (kind === "phone") return canonicalPhone(v) ?? v;
  return LOWERCASE_KINDS.includes(kind) ? v.toLowerCase() : v;
}

const PHONE_RE = /^\+\d{8,15}$/;

/**
 * Каноническая форма телефона — E.164: ведущий «+» и 8–15 цифр. Пробелы,
 * дефисы, точки и скобки отбрасываются («+7 (999) 123-45-67» → «+79991234567»);
 * номер без «+» (8999…, 00…) — не телефон: страна неизвестна. null — не разобрать.
 * Сравнивается с actor_name точно, регистр не приводится.
 */
export function canonicalPhone(input: string): string | null {
  const s = input.trim().replace(/[\s\-().]/g, "");
  return PHONE_RE.test(s) ? s : null;
}

export const isPhone = (v: string): boolean => canonicalPhone(v) !== null;

const V4_RE = /^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})$/;

function parseV4(v: string): string | null {
  const m = V4_RE.exec(v);
  if (!m) return null;
  const octets = m.slice(1);
  // Ведущие нули отвергаются, как в netip (010 — не 10 и не восьмеричное).
  return octets.every((o) => Number(o) <= 255 && !(o.length > 1 && o.startsWith("0"))) ? octets.map(Number).join(".") : null;
}

/**
 * Каноническая форма адреса, совместимая с netip у движка: IPv4 как есть;
 * IPv6 — строчные hex без ведущих нулей, самая длинная серия нулевых групп
 * (≥2, при равенстве — левая) сжата в «::», зона (%eth0) отброшена,
 * ::ffff:a.b.c.d → a.b.c.d. null — не адрес.
 */
export function canonicalIp(input: string): string | null {
  const v = input.trim();
  const v4 = parseV4(v);
  if (v4) return v4;
  if (!v.includes(":")) return null;
  let s = v.toLowerCase();
  const zone = s.indexOf("%");
  if (zone >= 0) s = s.slice(0, zone);
  if (!/^[0-9a-f:.]{2,45}$/.test(s)) return null;
  // Хвост IPv4 (::ffff:1.2.3.4) → две hex-группы.
  const tail = /(?:^|:)(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})$/.exec(s);
  let mapped4: string | null = null;
  if (tail) {
    const t4 = parseV4(tail[1]);
    if (!t4) return null;
    const o = t4.split(".").map(Number);
    s = s.slice(0, s.length - tail[1].length) + ((o[0] << 8) | o[1]).toString(16) + ":" + ((o[2] << 8) | o[3]).toString(16);
    mapped4 = t4;
  } else if (s.includes(".")) return null;
  const halves = s.split("::");
  if (halves.length > 2) return null;
  const left = halves[0] === "" ? [] : halves[0].split(":");
  const right = halves.length === 2 ? (halves[1] === "" ? [] : halves[1].split(":")) : [];
  if ([...left, ...right].some((g) => g === "" || g.length > 4 || !/^[0-9a-f]+$/.test(g))) return null;
  let groups: number[];
  if (halves.length === 2) {
    if (left.length + right.length > 7) return null;
    groups = [...left.map((g) => parseInt(g, 16)), ...Array<number>(8 - left.length - right.length).fill(0), ...right.map((g) => parseInt(g, 16))];
  } else {
    if (left.length !== 8) return null;
    groups = left.map((g) => parseInt(g, 16));
  }
  // IPv4-mapped (::ffff:a.b.c.d) — в чистый IPv4, как netip.Unmap.
  if (groups.slice(0, 5).every((g) => g === 0) && groups[5] === 0xffff) {
    return mapped4 ?? [groups[6] >> 8, groups[6] & 0xff, groups[7] >> 8, groups[7] & 0xff].join(".");
  }
  // RFC 5952: самая длинная серия нулей длиной ≥ 2, при равенстве — первая.
  let best = { start: -1, len: 0 };
  for (let i = 0; i < 8; ) {
    if (groups[i] !== 0) { i++; continue; }
    let j = i;
    while (j < 8 && groups[j] === 0) j++;
    if (j - i > best.len) best = { start: i, len: j - i };
    i = j;
  }
  const hex = groups.map((g) => g.toString(16));
  if (best.len < 2) return hex.join(":");
  return `${hex.slice(0, best.start).join(":")}::${hex.slice(best.start + best.len).join(":")}`;
}

/** Небольшая проверка IP: IPv4 с октетами 0–255 или IPv6 (в любой записи). */
export const isIp = (v: string): boolean => canonicalIp(v) !== null;

/* ===== Параметры ===== */

export const ACTOR_RANGES = ["24h", "7d", "30d"] as const;
export type ActorRange = (typeof ACTOR_RANGES)[number];
export const ACTOR_RANGE_DEFAULT: ActorRange = "7d";
export const ACTOR_LIMIT_DEFAULT = 200;
export const ACTOR_LIMIT_MAX = 500;
/** Жёсткий потолок окна паспорта: 30 дней. */
export const ACTOR_WINDOW_MAX_MS = 30 * 86_400_000;

export const isActorRange = (x: unknown): x is ActorRange => typeof x === "string" && (ACTOR_RANGES as readonly string[]).includes(x);
export const parseActorRange = (v: string | undefined | null): ActorRange => (isActorRange(v) ? v : ACTOR_RANGE_DEFAULT);

export type ActorParams = { range: ActorRange; limit: number };
export type ActorParamsParse = { ok: true; params: ActorParams } | { ok: false; error: string };

export function parseActorsParams(sp: URLSearchParams): ActorParamsParse {
  const range = sp.get("range");
  if (range && !isActorRange(range)) return { ok: false, error: `range: ожидается ${ACTOR_RANGES.join("|")}` };
  const limit = sp.get("limit");
  let n = ACTOR_LIMIT_DEFAULT;
  if (limit !== null && limit !== "") {
    n = Number(limit);
    if (!Number.isInteger(n) || n < 1 || n > ACTOR_LIMIT_MAX) return { ok: false, error: `limit: целое от 1 до ${ACTOR_LIMIT_MAX}` };
  }
  return { ok: true, params: { range: isActorRange(range) ? range : ACTOR_RANGE_DEFAULT, limit: n } };
}

export type Window = { fromMs: number; toMs: number };

/** Окно периода по ключу; конец — «сейчас». */
export function rangeWindow(range: ActorRange, now = Date.now()): Window {
  return { fromMs: now - RANGES[range].hours * 3600_000, toMs: now };
}

/** Окно не шире 30 дней и не пустое: начало подтягивается к концу. */
export function clampWindow(w: Window): Window {
  const toMs = w.toMs;
  const fromMs = Math.max(w.fromMs, toMs - ACTOR_WINDOW_MAX_MS);
  return { fromMs: Math.min(fromMs, toMs), toMs };
}

/* ===== Предикат по алиасам ===== */

/** Строка ClickHouse 'YYYY-MM-DD HH:MM:SS[.mmm]' (UTC) или ISO → мс; null — не разобрать. */
export function tsMs(value: string | null | undefined): number | null {
  if (!value) return null;
  const s = /^\d{4}-\d{2}-\d{2}[ T]\d{2}:\d{2}(:\d{2}(\.\d{1,9})?)?$/.test(value) ? value.replace(" ", "T") + "Z" : value;
  const ms = Date.parse(s);
  return Number.isFinite(ms) ? ms : null;
}

export type Predicate = { sql: string; params: Record<string, string | number> };

/** Интервал действия алиаса, обрезанный окном; null — вне окна. */
export function aliasInterval(a: Pick<Alias, "valid_from" | "valid_to">, w: Window): { fromMs: number; toMs: number } | null {
  const from = Math.max(tsMs(a.valid_from) ?? w.fromMs, w.fromMs);
  const to = Math.min(a.valid_to === null ? w.toMs : (tsMs(a.valid_to) ?? w.toMs), w.toMs);
  return from < to ? { fromMs: from, toMs: to } : null;
}

/**
 * Предикат выборки событий персоны: по каждому алиасу — его колонка и его
 * интервал действия внутри окна (открытый valid_to — до конца окна), всё
 * нумерованными параметрами как в buildLogSql. Без алиасов в окне — «0».
 * Удержанные алиасы (confidence < HOLD_CONFIDENCE) пропускаются.
 * prefix — чтобы два предиката в одном запросе не делили имена параметров;
 * tsColumn — колонка времени (first_ts для инцидентов).
 */
/** Алиасов в предикате больше стольких — компактная форма (aliasPredicate). */
export const PREDICATE_OR_MAX = 64;

export function aliasPredicate(aliases: Alias[], window: Window, prefix = "", tsColumn = "ts", form: "auto" | "or" | "arrays" = "auto"): Predicate {
  const w = clampWindow(window);
  const params: Record<string, string | number> = {};
  const live = aliases.flatMap((a) => {
    if (isHeld(a)) return []; // удержанный алиас не сшивает события
    const iv = aliasInterval(a, w);
    return iv ? [{ a, iv }] : [];
  });
  if (form === "arrays" || (form === "auto" && live.length > PREDICATE_OR_MAX)) {
    // Компактная форма, как activityPlan: интервалы одного значения пронумерованы подряд,
    // transform по колонке сравнения даёт отрезок их номеров (хеш-поиск), лямбда проходит
    // только по нему. Массивы — параметрами (arrayParam делит их на части), текст SQL не
    // растёт с числом алиасов. Ветки OR позволяют индексу отсекать гранулы, но строки и
    // так отбирает aliasPrefilter, а тысячи веток не помещались в max_query_size
    // (256 КиБ) и в поле формы ClickHouse. Массивы значений — не аргументами
    // arrayExists: те ClickHouse разворачивает на каждую строку (тысячи значений ×
    // строки — гигабайты).
    const byColumn = new Map<string, Map<string, { fromMs: number; toMs: number }[]>>();
    for (const { a, iv } of live) {
      const col = aliasColumnExpr(a.kind);
      const byValue = byColumn.get(col) ?? new Map<string, { fromMs: number; toMs: number }[]>();
      byColumn.set(col, byValue);
      byValue.set(a.value, [...(byValue.get(a.value) ?? []), iv]);
    }
    const from: string[] = [], to: string[] = [];
    const lookups: string[] = [];
    [...byColumn].forEach(([col, byValue], j) => {
      const keys: string[] = [], spans: string[] = [];
      for (const [value, ivs] of byValue) {
        keys.push(chStringLiteral(value));
        spans.push(span(from.length + 1, ivs.length));
        for (const iv of ivs) {
          from.push(String(iv.fromMs));
          to.push(String(iv.toMs));
        }
      }
      const k = arrayParam(params, `${prefix}ck${j}`, "Array(String)", keys);
      const r = arrayParam(params, `${prefix}cr${j}`, "Array(UInt64)", spans);
      lookups.push(spanRange(`transform(${col}, ${k}, ${r}, toUInt64(0))`));
    });
    if (!lookups.length) return { sql: "0", params };
    const f = arrayParam(params, `${prefix}cf`, "Array(Int64)", from);
    const t = arrayParam(params, `${prefix}ct`, "Array(Int64)", to);
    const ms = `toUnixTimestamp64Milli(${tsColumn})`;
    return { sql: `arrayExists(c -> ${ms} >= ${f}[c] AND ${ms} < ${t}[c], arrayConcat(${lookups.join(", ")}))`, params };
  }
  const parts: string[] = [];
  let i = 0;
  for (const { a, iv } of live) {
    const an = `${prefix}a${i}`, fn = `${prefix}f${i}`, tn = `${prefix}t${i}`;
    params[an] = a.value;
    params[fn] = chTs(iv.fromMs);
    params[tn] = chTs(iv.toMs);
    parts.push(`(${aliasColumnExpr(a.kind)} = {${an}:String} AND ${tsColumn} >= parseDateTime64BestEffort({${fn}:String}, 3, 'UTC') AND ${tsColumn} < parseDateTime64BestEffort({${tn}:String}, 3, 'UTC'))`);
    i++;
  }
  return { sql: parts.length ? `(${parts.join(" OR ")})` : "0", params };
}

/** Слоты ключей строки события — по порядку ACTOR_KEYS_EXPR. */
const KEY_SLOTS = ["actor_name", "lowerUTF8(actor_name)", "src_ip", "lowerUTF8(node)"] as const;

export type ActivityPlan = {
  /** Персоны с хотя бы одним алиасом в окне. */
  persons: string[];
  /** Класс алиасов (1-based) → номера персон (1-based в persons). */
  owners: number[][];
  /** Выражение: отсортированный массив классов, совпавших со строкой в момент ts. */
  hits: string;
  /** Выражение над колонкой hits: номера персон (1-based в persons) без повторов. */
  who: string;
  params: Record<string, string | number>;
};

/** Часть массива-параметра не больше стольких байт в виде, в каком она уходит в URL
 *  (application/x-www-form-urlencoded, как сериализует URLSearchParams), — значит, и в
 *  сыром UTF-8 не больше. У поля формы ClickHouse предел значения (Poco HTMLForm,
 *  http_max_field_value_size — 128 КиБ на 24.8; из URL не поднимается), и в URL он
 *  меряется до percent-decoding: часть годится и для URL, и для multipart (clickhouse.ts). */
export const ARRAY_PARAM_CHUNK = 60_000;

/** Длина строки в байтах UTF-8 (без Buffer: модуль общий с клиентом). */
export function utf8Bytes(s: string): number {
  let n = 0;
  for (let i = 0; i < s.length; i++) {
    const c = s.charCodeAt(i);
    if (c < 0x80) n += 1;
    else if (c < 0x800) n += 2;
    else if (c >= 0xd800 && c <= 0xdbff && i + 1 < s.length) { n += 4; i++; } // суррогатная пара
    else n += 3;
  }
  return n;
}

/** Длина строки после сериализации URLSearchParams: буквы, цифры и «*-._» как есть,
 *  пробел — «+», остальное — %XX на каждый байт UTF-8 (в том числе «~», «'», «,»). */
export function formEncodedBytes(s: string): number {
  let n = 0;
  for (let i = 0; i < s.length; i++) {
    const c = s.charCodeAt(i);
    if ((c >= 0x30 && c <= 0x39) || (c >= 0x41 && c <= 0x5a) || (c >= 0x61 && c <= 0x7a) || c === 0x2a || c === 0x2d || c === 0x2e || c === 0x5f || c === 0x20) n += 1;
    else if (c < 0x80) n += 3;
    else if (c < 0x800) n += 6;
    else if (c >= 0xd800 && c <= 0xdbff && i + 1 < s.length) { n += 12; i++; }
    else n += 9;
  }
  return n;
}

/**
 * Массив-параметр из готовых литералов элементов: одним параметром {name:Type}, а если
 * в URL он длиннее ARRAY_PARAM_CHUNK байт (formEncodedBytes) — частями name_0, name_1… и arrayConcat в SQL. Делится
 * только между элементами, поэтому элементы — скаляры (вложенные массивы не годятся:
 * один элемент мог бы сам превысить предел поля). Склейка констант — константа: её
 * принимают transform и IN.
 */
export function arrayParam(params: Record<string, string | number>, name: string, type: string, elements: string[]): string {
  const chunks: string[][] = [[]];
  let len = 0;
  for (const el of elements) {
    const bytes = formEncodedBytes(el) + 3; // «,» — %2C
    if (len + bytes > ARRAY_PARAM_CHUNK && chunks[chunks.length - 1].length) {
      chunks.push([]);
      len = 0;
    }
    chunks[chunks.length - 1].push(el);
    len += bytes;
  }
  if (chunks.length === 1) {
    params[name] = `[${chunks[0].join(",")}]`;
    return `{${name}:${type}}`;
  }
  return `arrayConcat(${chunks.map((c, i) => {
    params[`${name}_${i}`] = `[${c.join(",")}]`;
    return `{${name}_${i}:${type}}`;
  }).join(", ")})`;
}

const chStringLiteral = (v: string): string => `'${v.replace(/\\/g, "\\\\").replace(/'/g, "\\'")}'`;

/** Отрезок [start, start + n) одним UInt64: start в старших 32 битах. */
const SPAN = 4294967296;
const span = (start: number, n: number): string => String(start * SPAN + n);
const spanRange = (x: string): string => `range(toUInt32(intDiv(${x}, ${SPAN})), toUInt32(intDiv(${x}, ${SPAN}) + modulo(${x}, ${SPAN})))`;

/**
 * Активность многих персон за один проход по окну — без OR по алиасам. Алиасы с
 * одинаковыми слотом (колонкой сравнения), значением и интервалом внутри окна — один
 * класс; у класса — список персон-владельцев (одно значение бывает у нескольких).
 * Классы одного значения пронумерованы подряд, поэтому каждый из четырёх ключей строки
 * (ACTOR_KEYS_EXPR) хеш-поиском transform даёт отрезок номеров классов, а не вложенный
 * массив; остаются классы, действующие в момент ts. Так же — владельцы класса: отрезок
 * плоского массива персон. Вызывающий группирует строки по набору совпавших классов
 * (count, max(ts)) и затем раскрывает наборы в персоны выражением who в самом
 * ClickHouse: строка засчитывается персоне один раз, даже если совпала с несколькими
 * её алиасами, общие значения сотни персон не размножают строки событий, а в ответе
 * не больше строк, чем персон. Два события в одну мс — два события (как count()
 * паспорта, без хеша). Строки отбирает aliasPrefilter (hasAny или IN).
 */
export function activityPlan(byPerson: { id: string; aliases: Alias[] }[], window: Window, prefix = "ap_"): ActivityPlan {
  const w = clampWindow(window);
  const persons: string[] = [];
  // слот → значение → интервал → номера владельцев
  const slotValues = KEY_SLOTS.map(() => new Map<string, Map<string, { fromMs: number; toMs: number; owners: number[] }>>());
  for (const { id, aliases } of byPerson) {
    let personNo = 0;
    for (const a of aliases) {
      if (isHeld(a)) continue;
      const iv = aliasInterval(a, w);
      if (!iv) continue;
      const slot = KEY_SLOTS.indexOf(aliasColumnExpr(a.kind) as (typeof KEY_SLOTS)[number]);
      if (slot < 0) continue;
      if (!personNo) {
        persons.push(id);
        personNo = persons.length;
      }
      const byInterval = slotValues[slot].get(a.value) ?? new Map();
      slotValues[slot].set(a.value, byInterval);
      const key = `${iv.fromMs}\u0000${iv.toMs}`;
      const cls = byInterval.get(key) ?? { fromMs: iv.fromMs, toMs: iv.toMs, owners: [] };
      byInterval.set(key, cls);
      if (!cls.owners.includes(personNo)) cls.owners.push(personNo);
    }
  }
  const params: Record<string, string | number> = {};
  const owners: number[][] = [];
  const from: string[] = [], to: string[] = [], ownerSpan: string[] = [], ownerFlat: string[] = [];
  const lookups: string[] = [];
  KEY_SLOTS.forEach((expr, s) => {
    if (!slotValues[s].size) return;
    const keys: string[] = [], spans: string[] = [];
    for (const [value, byInterval] of slotValues[s]) {
      keys.push(chStringLiteral(value));
      spans.push(span(owners.length + 1, byInterval.size));
      for (const cls of byInterval.values()) {
        owners.push(cls.owners);
        from.push(String(cls.fromMs));
        to.push(String(cls.toMs));
        ownerSpan.push(span(ownerFlat.length + 1, cls.owners.length));
        ownerFlat.push(...cls.owners.map(String));
      }
    }
    const k = arrayParam(params, `${prefix}k${s}`, "Array(String)", keys);
    const r = arrayParam(params, `${prefix}r${s}`, "Array(UInt64)", spans);
    lookups.push(spanRange(`transform(${expr}, ${k}, ${r}, toUInt64(0))`));
  });
  if (!lookups.length) return { persons, owners, hits: "[]", who: "[]", params };
  const vf = arrayParam(params, `${prefix}vf`, "Array(Int64)", from);
  const vt = arrayParam(params, `${prefix}vt`, "Array(Int64)", to);
  const os = arrayParam(params, `${prefix}os`, "Array(UInt64)", ownerSpan);
  const ow = arrayParam(params, `${prefix}ow`, "Array(UInt32)", ownerFlat);
  const ms = "toUnixTimestamp64Milli(ts)";
  const hits = `arraySort(arrayFilter(c -> ${ms} >= ${vf}[c] AND ${ms} < ${vt}[c], arrayConcat(${lookups.join(", ")})))`;
  const who = `arrayDistinct(arrayFlatten(arrayMap(c -> arrayMap(i -> ${ow}[i], ${spanRange(`${os}[c]`)}), hits)))`;
  return { persons, owners, hits, who, params };
}

/** Строка ClickHouse Array(String) для параметра запроса. */
export const chStringArray = (values: string[]): string => `[${values.map(chStringLiteral).join(",")}]`;

/** Выражение skip-индекса idx_actor_keys (миграция 0032): все колонки, с которыми
 *  сравниваются алиасы, в том виде, в каком их сравнивает aliasColumnExpr. Текст должен
 *  совпадать с индексом дословно — иначе ClickHouse индекс не применит. */
export const ACTOR_KEYS_EXPR = "[actor_name, lowerUTF8(actor_name), src_ip, lowerUTF8(node)]";

/** Больше стольких значений — предфильтр не hasAny, а IN по колонкам (см. aliasPrefilter). */
export const PREFILTER_INDEX_MAX = 32;

/**
 * Грубый фильтр строк по значениям алиасов без интервалов. Ставится в WHERE рядом с
 * точным aliasPredicate, значения — те же, что сравнивает предикат, поэтому фильтр
 * не уже точного предиката. Удержанные алиасы не участвуют.
 *
 * До PREFILTER_INDEX_MAX значений — hasAny(ключи строки, массив значений): bloom-индекс
 * idx_actor_keys отсекает гранулы для любой смеси видов алиасов (login OR ip …), чего
 * OR по отдельным индексам не умеет; паспорт одного человека идёт по тысячам строк, а
 * не по всему окну (100+ млн строк за 7 суток).
 *
 * Больше — IN по колонке каждого вида (actor_name, lowerUTF8(actor_name), src_ip,
 * lowerUTF8(node)): множество из констант — хеш-поиск. hasAny сравнивает каждую строку
 * с каждым значением, а отсечения у bloom_filter(0.01) при n значениях почти нет
 * (группа гранул «может содержать» с вероятностью 1 − 0,99ⁿ): на argus1 список
 * «Субъекты» с 374 значениями шёл по hasAny 60+ с, по IN — 2 с на 180 млн строк.
 */
export function aliasPrefilter(aliases: Alias[], prefix = "pf_"): Predicate {
  const live = aliases.filter((a) => !isHeld(a));
  const values = new Set(live.map(compareValue));
  if (!values.size) return { sql: "0", params: {} };
  if (values.size <= PREFILTER_INDEX_MAX) {
    const params: Record<string, string> = {};
    const keys = arrayParam(params, `${prefix}keys`, "Array(String)", [...values].sort().map(chStringLiteral));
    return { sql: `hasAny(${ACTOR_KEYS_EXPR}, ${keys})`, params };
  }
  const bySlot = new Map<string, Set<string>>();
  for (const a of live) {
    const expr = aliasColumnExpr(a.kind);
    bySlot.set(expr, (bySlot.get(expr) ?? new Set()).add(a.value));
  }
  const params: Record<string, string> = {};
  const parts = [...bySlot].sort(([x], [y]) => x.localeCompare(y)).map(([expr, vals], i) =>
    `${expr} IN ${arrayParam(params, `${prefix}in${i}`, "Array(String)", [...vals].sort().map(chStringLiteral))}`);
  return { sql: `(${parts.join(" OR ")})`, params };
}

/** Действует ли алиас в момент at. */
export function aliasActiveAt(a: Pick<Alias, "valid_from" | "valid_to">, atMs: number): boolean {
  const from = tsMs(a.valid_from);
  const to = a.valid_to === null ? null : tsMs(a.valid_to);
  return from !== null && from <= atMs && (to === null || atMs < to);
}

/** Совпадает ли сырое значение с алиасом по правилу его вида (регистр). */
export function aliasMatches(a: Pick<Alias, "kind" | "value">, raw: string): boolean {
  return a.value === normalizeAliasValue(a.kind, raw);
}

/** Пары (вид, значение), которые внутри окна действуют у двух и более персон.
 *  Удержанные алиасы не сшивают события и неоднозначности не создают. */
export function ambiguousAliases(all: Alias[], window: Window): Set<string> {
  const byKey = new Map<string, Alias[]>();
  for (const a of all) {
    if (isHeld(a) || !aliasInterval(a, window)) continue;
    const key = aliasKey(a);
    byKey.set(key, [...(byKey.get(key) ?? []), a]);
  }
  const out = new Set<string>();
  for (const [key, list] of byKey) {
    const persons = new Set(list.map((a) => a.person_id));
    if (persons.size < 2) continue;
    // Общий алиас без пересечения интервалов (адрес передан другому) — не неоднозначность.
    const ivs = list.map((a) => ({ p: a.person_id, iv: aliasInterval(a, window)! }));
    const overlap = ivs.some((x, i) => ivs.some((y, j) => j !== i && x.p !== y.p && x.iv.fromMs < y.iv.toMs && y.iv.fromMs < x.iv.toMs));
    if (overlap) out.add(key);
  }
  return out;
}

/* ===== Резолв ===== */

export type ResolveStatus = "resolved" | "unbound" | "ambiguous";
export type ResolveMatch = { person_id: string; display: string; kind: PersonKind; alias_kind: AliasKind; valid_from: string; valid_to: string | null };

export function resolveStatus(matches: { person_id: string }[]): ResolveStatus {
  const n = new Set(matches.map((m) => m.person_id)).size;
  return n === 0 ? "unbound" : n === 1 ? "resolved" : "ambiguous";
}

/* ===== Разделы паспорта ===== */

export const SECTIONS = ["login", "host", "network", "app", "change", "other"] as const;
export type Section = (typeof SECTIONS)[number];
export const SECTION_LABELS: Record<Section, string> = {
  login: "Входы", host: "Хосты и сеансы", network: "Сеть", app: "Приложения", change: "Изменения", other: "Прочее",
};

const CHANGE_RE = /create|update|delete|change|modify/i;
const SU_RE = /(^|[._-])su($|[._-])/;

/**
 * Раздел паспорта по единой схеме события — без знания вендоров: входы по
 * auth./login/logon/sshd, сеансы и привилегии по priv./sudo/su/session., сеть
 * по классу источника netflow/ngfw или net., приложения по app./authorize/oauth,
 * изменения — identity.* (алиасы, нарушения политики идентичности — независимо
 * от исхода) и create|update|delete|change|modify с успешным исходом.
 */
export function classifyEvent(action: string, outcome: string, sourceClass = ""): Section {
  const a = action.toLowerCase();
  if (a.startsWith("auth.") || a.includes("login") || a.includes("logon") || a.includes("sshd")) return "login";
  if (a.startsWith("identity.")) return "change";
  const sc = sourceClass.toLowerCase();
  if (sc === "netflow" || sc === "ngfw" || a.startsWith("net.")) return "network";
  if (a.startsWith("priv.") || a.includes("sudo") || SU_RE.test(a) || a.startsWith("session.")) return "host";
  if (a.startsWith("app.") || a.includes("authorize") || a.includes("oauth")) return "app";
  if (CHANGE_RE.test(a) && outcome.toLowerCase() === "success") return "change";
  return "other";
}

/**
 * classifyEvent на SQL — для выборки последних событий каждого раздела отдельно:
 * частый раздел (журнал соединений) не вытесняет редкие из общей ленты.
 * Порядок веток совпадает с classifyEvent; сверка — tests/actors-sections-ch.test.ts.
 */
export const SECTION_SQL = `multiIf(
  startsWith(lowerUTF8(action), 'auth.') OR position(lowerUTF8(action), 'login') > 0 OR position(lowerUTF8(action), 'logon') > 0 OR position(lowerUTF8(action), 'sshd') > 0, 'login',
  startsWith(lowerUTF8(action), 'identity.'), 'change',
  lowerUTF8(source_class) IN ('netflow', 'ngfw') OR startsWith(lowerUTF8(action), 'net.'), 'network',
  startsWith(lowerUTF8(action), 'priv.') OR position(lowerUTF8(action), 'sudo') > 0 OR match(lowerUTF8(action), '(^|[._-])su($|[._-])') OR startsWith(lowerUTF8(action), 'session.'), 'host',
  startsWith(lowerUTF8(action), 'app.') OR position(lowerUTF8(action), 'authorize') > 0 OR position(lowerUTF8(action), 'oauth') > 0, 'app',
  match(lowerUTF8(action), 'create|update|delete|change|modify') AND lowerUTF8(outcome) = 'success', 'change',
  'other')`;

/** Разложить события по разделам (порядок строк сохраняется). */
export function bucketEvents(items: LogItem[]): Record<Section, LogItem[]> {
  const out: Record<Section, LogItem[]> = { login: [], host: [], network: [], app: [], change: [], other: [] };
  for (const it of items) out[classifyEvent(it.action, it.outcome, it.source_class)].push(it);
  return out;
}

/* ===== Ссылки ===== */

/** Запрос журнала по алиасу: actor для субъектных видов, src для адреса, node для хоста. */
export function aliasEventsQuery(a: Pick<Alias, "kind" | "value">): string {
  const field = a.kind === "ip" ? "src" : a.kind === "host" ? "node" : "actor";
  return termToString({ field, op: "=", value: a.value, negate: false, quoted: true });
}

/** Ссылка в журнал: язык поиска без ИЛИ, поэтому — по одному алиасу;
 *  для паспорта берётся основной субъектный (login, затем uid, email …). */
export function aliasEventsHref(a: Pick<Alias, "kind" | "value">, range: ActorRange): string {
  return `/events?q=${encodeURIComponent(aliasEventsQuery(a))}&range=${range}`;
}

const PRIMARY_ORDER: AliasKind[] = ["login", "uid", "email", "sid", "peer", "phone", "host", "ip"];

/** Основной алиас для ссылки в журнал: действующий прежде закрытого, удержанные не берутся. */
export function primaryAlias(all: Alias[]): Alias | null {
  const aliases = activeAliases(all);
  for (const k of PRIMARY_ORDER) {
    const a = aliases.find((x) => x.kind === k && x.valid_to === null) ?? aliases.find((x) => x.kind === k);
    if (a) return a;
  }
  return null;
}

/* ===== Контракт identities (YAML/JSON) ===== */

export type AliasInput = { kind: AliasKind; value: string; valid_from: string | null; valid_to: string | null; confidence: number; note: string };
export type PersonInput = Person & { aliases: AliasInput[] };
export type IdentitiesParse = { ok: true; persons: PersonInput[] } | { ok: false; path: string; error: string };

const DATE_RE = /^\d{4}-\d{2}-\d{2}$/;
const RFC3339_RE = /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}(:\d{2}(\.\d{1,3})?)?(Z|[+-]\d{2}:\d{2})$/;

/** Дата YYYY-MM-DD (полуночь UTC) или RFC 3339 → 'YYYY-MM-DD HH:MM:SS.mmm'; null — не разобрать. */
export function parseDateInput(v: unknown): string | null {
  if (typeof v !== "string") return null;
  const s = v.trim();
  if (DATE_RE.test(s)) {
    const ms = Date.parse(s + "T00:00:00Z");
    return Number.isFinite(ms) ? chTs(ms) : null;
  }
  if (RFC3339_RE.test(s)) {
    const ms = Date.parse(s);
    return Number.isFinite(ms) ? chTs(ms) : null;
  }
  return null;
}

const str = (v: unknown, max: number): string | null => (v === undefined || v === null ? "" : typeof v === "string" && v.length <= max && !/[\u0000-\u0008\u000b-\u001f\u007f]/.test(v) ? v.trim() : null);

/**
 * Проверка документа {"persons": {"<id>": {display, kind, team, note, aliases: [{kind, value, from, to, confidence, note}]}}}
 * — тот же контракт, что у identities.yml. Ошибка — с путём до поля.
 */
export function parseIdentitiesDoc(body: unknown): IdentitiesParse {
  const bad = (path: string, error: string): IdentitiesParse => ({ ok: false, path, error });
  if (!body || typeof body !== "object" || Array.isArray(body)) return bad("", "ожидается объект {persons: {…}}");
  const persons = (body as { persons?: unknown }).persons;
  if (!persons || typeof persons !== "object" || Array.isArray(persons)) return bad("persons", "ожидается объект id → персона");
  const out: PersonInput[] = [];
  const entries = Object.entries(persons as Record<string, unknown>);
  if (entries.length === 0) return bad("persons", "пусто");
  if (entries.length > 10_000) return bad("persons", "не больше 10 000 персон за раз");
  for (const [id, raw] of entries) {
    const p = `persons.${id}`;
    if (!PERSON_ID_RE.test(id)) return bad(p, "person_id: латиница в нижнем регистре, цифры, . _ -, до 64 символов");
    if (!raw || typeof raw !== "object" || Array.isArray(raw)) return bad(p, "ожидается объект");
    const r = raw as Record<string, unknown>;
    const display = str(r.display, TEXT_MAX);
    if (display === null) return bad(`${p}.display`, `строка до ${TEXT_MAX} символов`);
    const kind = r.kind === undefined || r.kind === null || r.kind === "" ? "person" : r.kind;
    if (kind !== "person" && kind !== "service") return bad(`${p}.kind`, "person|service");
    const team = str(r.team, TEXT_MAX);
    if (team === null) return bad(`${p}.team`, `строка до ${TEXT_MAX} символов`);
    const note = str(r.note, 2000);
    if (note === null) return bad(`${p}.note`, "строка до 2000 символов");
    const aliasesRaw = r.aliases === undefined || r.aliases === null ? [] : r.aliases;
    if (!Array.isArray(aliasesRaw)) return bad(`${p}.aliases`, "ожидается список");
    if (aliasesRaw.length > 1000) return bad(`${p}.aliases`, "не больше 1000 алиасов у персоны");
    const aliases: AliasInput[] = [];
    for (let i = 0; i < aliasesRaw.length; i++) {
      const ap = `${p}.aliases[${i}]`;
      const parsed = parseAliasInput(aliasesRaw[i]);
      if (!parsed.ok) return bad(`${ap}.${parsed.field}`, parsed.error);
      aliases.push(parsed.alias);
    }
    out.push({ person_id: id, display: display || id, kind, team, note, aliases });
  }
  return { ok: true, persons: out };
}

export type AliasInputParse = { ok: true; alias: AliasInput } | { ok: false; field: string; error: string };

/** Один алиас {kind, value, from, to, confidence, note}: вид, нормализация, адрес, даты. */
export function parseAliasInput(raw: unknown): AliasInputParse {
  const bad = (field: string, error: string): AliasInputParse => ({ ok: false, field, error });
  if (!raw || typeof raw !== "object" || Array.isArray(raw)) return bad("", "ожидается объект {kind, value}");
  const a = raw as Record<string, unknown>;
  if (!isAliasKind(a.kind)) return bad("kind", ALIAS_KINDS.join("|"));
  const kind = a.kind;
  const value0 = str(a.value, ALIAS_VALUE_MAX);
  if (!value0) return bad("value", `непустая строка до ${ALIAS_VALUE_MAX} символов`);
  if (kind === "ip" && !isIp(value0)) return bad("value", "ожидается IPv4 или IPv6");
  if (kind === "phone" && !isPhone(value0)) return bad("value", "ожидается телефон E.164: «+» и 8–15 цифр");
  const value = normalizeAliasValue(kind, value0);
  if (kind === "email" && !/^[^\s@]+@[^\s@]+$/.test(value)) return bad("value", "ожидается адрес вида user@domain");
  if (/\s/.test(value)) return bad("value", "без пробелов");
  const from = a.from === undefined || a.from === null || a.from === "" ? null : parseDateInput(a.from);
  if (from === null && !(a.from === undefined || a.from === null || a.from === "")) return bad("from", "YYYY-MM-DD или RFC 3339");
  const to = a.to === undefined || a.to === null || a.to === "" ? null : parseDateInput(a.to);
  if (to === null && !(a.to === undefined || a.to === null || a.to === "")) return bad("to", "YYYY-MM-DD или RFC 3339");
  if (from !== null && to !== null && to <= from) return bad("to", "раньше from");
  let confidence = 1;
  if (a.confidence !== undefined && a.confidence !== null && a.confidence !== "") {
    confidence = Number(a.confidence);
    if (!Number.isFinite(confidence) || confidence < 0 || confidence > 1) return bad("confidence", "число от 0 до 1");
  }
  const note = str(a.note, TEXT_MAX);
  if (note === null) return bad("note", `строка до ${TEXT_MAX} символов`);
  return { ok: true, alias: { kind, value, valid_from: from, valid_to: to, confidence, note } };
}

/* ===== Отчёт и Markdown ===== */

export type ClassCount = { source_class: string; count: number };
export type NodeStat = { node: string; count: number; first_ts: string; last_ts: string };
export type IpStat = { src_ip: string; count: number; first_ts: string; last_ts: string };
export type SourceCoverage = { source: string; source_class: string; count: number; first_ts: string; last_ts: string };
export type ActorIncident = { id: string; level: string; status: string; rule_id: string; rule_title: string; created_at: string };

export type ActorReport = {
  person: Person;
  aliases: Alias[];
  /** Алиасы (ключ aliasKey), которые в окне действуют и у другой персоны. */
  ambiguous: string[];
  range: { key: ActorRange; from: string; to: string };
  summary: { events: number; by_source_class: Record<string, number>; nodes: NodeStat[]; src_ips: IpStat[]; incidents: number };
  sources: SourceCoverage[];
  sections: Record<Section, LogItem[]>;
  incidents: ActorIncident[];
  timeline: LogItem[];
  limit: number;
  /** Что не загрузилось (частичная деградация). */
  missing: string[];
  generated_at: string;
};

const RANGE_WORDS: Record<ActorRange, string> = { "24h": "24 часа", "7d": "7 дней", "30d": "30 дней" };

function eventLine(e: LogItem): string {
  const parts = [literal(e.ts), literal(e.source), literal(e.action), literal(e.outcome || "—")];
  if (e.actor_name) parts.push(`субъект ${literal(e.actor_name)}`);
  if (e.node) parts.push(`узел ${literal(e.node)}`);
  if (e.src_ip) parts.push(`с ${literal(e.src_ip)}`);
  if (e.dst_ip) parts.push(`на ${literal(e.dst_ip)}`);
  if (e.object) parts.push(literal(e.object));
  return `- ${parts.join(" · ")}`;
}

/** Markdown-паспорт для скачивания и агентов: все значения через literal(). */
export function actorMarkdown(r: ActorReport): string {
  const p = r.person;
  const lines: string[] = [
    `# Паспорт субъекта — ${literal(p.display || p.person_id)}`,
    "",
    `- Идентификатор: ${literal(p.person_id)}`,
    `- Вид: ${p.kind === "service" ? "служебная учётка" : "человек"}`,
    `- Команда: ${p.team ? literal(p.team) : "не указана"}`,
    `- Период: ${literal(r.range.from)} → ${literal(r.range.to)} UTC (${RANGE_WORDS[r.range.key]})`,
    `- Сформирован: ${literal(r.generated_at)} UTC`,
  ];
  if (p.note) lines.push(`- Заметка: ${literal(p.note)}`);
  if (r.missing.length) lines.push("", `Часть данных недоступна: ${r.missing.map(literal).join(", ")}.`);
  lines.push("", "## Алиасы", "");
  if (!r.aliases.length) lines.push("Алиасов нет — паспорт пуст.");
  else {
    lines.push("| Вид | Значение | Действует с | По | Источник | Уверенность |", "|---|---|---|---|---|---|");
    for (const a of r.aliases) {
      const amb = r.ambiguous.includes(aliasKey(a)) ? " (неоднозначно)" : "";
      const hold = isHeld(a) ? ` (на удержании: ${literal(holdPolicy(a) ?? "политика идентичности")})` : "";
      lines.push(`| ${literal(a.kind)} | ${literal(a.value)}${amb}${hold} | ${literal(a.valid_from)} | ${a.valid_to ? literal(a.valid_to) : "действует"} | ${literal(a.source)} | ${literal(String(a.confidence))} |`);
    }
  }
  lines.push("", "## Источники данных и их период", "");
  if (!r.sources.length) lines.push("В окне нет событий по алиасам субъекта.");
  else {
    lines.push("| Источник | Класс | Событий | Первое | Последнее |", "|---|---|---|---|---|");
    for (const s of r.sources) lines.push(`| ${literal(s.source)} | ${literal(s.source_class)} | ${s.count} | ${literal(s.first_ts)} | ${literal(s.last_ts)} |`);
  }
  lines.push("", "## Сводка", "", `- Событий: ${r.summary.events}`);
  const classes = Object.entries(r.summary.by_source_class);
  lines.push(`- По классам: ${classes.length ? classes.map(([c, n]) => `${literal(c)} ${n}`).join(", ") : "—"}`);
  lines.push(`- Узлы: ${r.summary.nodes.length ? r.summary.nodes.map((n) => `${literal(n.node)} (${n.count})`).join(", ") : "—"}`);
  lines.push(`- Адреса: ${r.summary.src_ips.length ? r.summary.src_ips.map((n) => `${literal(n.src_ip)} (${n.count})`).join(", ") : "—"}`);
  lines.push(`- Инцидентов: ${r.summary.incidents}`);
  for (const s of SECTIONS) {
    if (s === "other") continue;
    const items = r.sections[s];
    lines.push("", `## ${SECTION_LABELS[s]}`, "");
    if (!items.length) lines.push("Нет событий этого раздела в окне.");
    else lines.push(...items.map(eventLine));
  }
  lines.push("", "## Инциденты", "");
  if (!r.incidents.length) lines.push("Инцидентов с субъектом в периоде нет.");
  else for (const i of r.incidents) lines.push(`- ${literal(i.id)} · ${literal(i.level)} · ${literal(i.status)} · ${literal(i.rule_id)} · ${literal(i.rule_title)} · ${literal(i.created_at)} UTC`);
  lines.push("", `## Таймлайн · последние ${r.timeline.length} из не больше ${r.limit}`, "");
  if (!r.timeline.length) lines.push("Событий нет.");
  else lines.push(...r.timeline.map(eventLine));
  lines.push(
    "", "## Чего нет в данных", "",
    "- Содержимое данных внутри приложений: паспорт строится по журналу событий, а не по данным систем.",
    "- События вне интервалов действия алиасов: до valid_from и после valid_to они субъекту не приписываются.",
    "- Источники, не подключённые к ARGUS, и события старше срока хранения.",
    `- Разделы «Входы» … «Изменения» — последние ${r.limit} событий каждого раздела в окне, сводка — по всем.`,
  );
  if (r.ambiguous.length) lines.push("- Алиасы с пометкой «неоднозначно» в окне делятся с другой персоной: их события могут быть не этого субъекта.");
  if (r.aliases.some(isHeld)) lines.push("- Алиасы «на удержании» (нарушение политики идентичности) в сшивку не входят: их события в паспорте не учтены, пока администратор не подтвердит алиас.");
  return lines.join("\n").trimEnd() + "\n";
}
