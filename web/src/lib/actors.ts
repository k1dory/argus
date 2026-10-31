import "server-only";

// Запросы паспорта субъекта: персоны и алиасы (argus.identities,
// argus.identity_aliases — ReplacingMergeTree, последняя версия через argMax
// по updated_at, deleted = 0), срез событий по алиасам с учётом интервалов
// действия, инциденты субъекта, резолв сырого значения в персону. Все
// значения — только параметрами, окно по ts обязательно и не шире 30 дней.
import { chCommand, chQuery as chQueryRaw, safeQuery } from "./clickhouse";
import { SEARCH_SETTINGS } from "./search";
import { chTs, LOG_COLUMNS, toLogItem, type LogItem } from "./shared/log-query";
import type { TriageBinding } from "./shared/triage";
import {
  ACTOR_KINDS, activeAliases, aliasColumnExpr, aliasPredicate, aliasPrefilter, aliasActiveAt, aliasMatches, aliasKey, ambiguousAliases, bucketEvents, canonicalIp, canonicalPhone, clampWindow, CONFIRMED_NOTE_PREFIX, HOLD_NOTE_PREFIX, isAliasKind, isHeld, LOWERCASE_KINDS, normalizeAliasValue, rangeWindow, resolveStatus,
  type ActorIncident, type ActorRange, type ActorReport, type Alias, type AliasInput, type ClassCount, type IpStat, type NodeStat, type Person, type PersonInput, type ResolveMatch, type ResolveStatus, type SourceCoverage, type Window,
} from "./shared/actors";

const chQuery = <T,>(sql: string, params: Record<string, string | number> = {}): Promise<T[]> => chQueryRaw<T>(sql, params, SEARCH_SETTINGS);

/** Последние версии персон (без удалённых). */
const PERSONS_LATEST = `
  SELECT person_id, argMax(display, updated_at) AS display, argMax(kind, updated_at) AS kind,
         argMax(team, updated_at) AS team, argMax(note, updated_at) AS note
  FROM identities GROUP BY person_id HAVING argMax(deleted, updated_at) = 0`;

/** Последние версии алиасов: ключ строки — (alias_kind, alias_value, valid_from, person_id).
 *  argMax пропускает NULL в аргументе, поэтому открытый valid_to хранится
 *  через сентинел и возвращается обратно в NULL. */
const ALIASES_LATEST = `
  SELECT person_id, alias_kind, alias_value, valid_from,
         nullIf(argMax(coalesce(valid_to, toDateTime64('2200-01-01 00:00:00', 3, 'UTC')), updated_at), toDateTime64('2200-01-01 00:00:00', 3, 'UTC')) AS valid_to_raw,
         argMax(source, updated_at) AS source,
         argMax(confidence, updated_at) AS confidence, argMax(note, updated_at) AS note
  FROM identity_aliases GROUP BY alias_kind, alias_value, valid_from, person_id
  HAVING argMax(deleted, updated_at) = 0`;

type PersonRow = { person_id: string; display: string; kind: string; team: string; note: string };
type AliasRow = { person_id: string; alias_kind: string; alias_value: string; valid_from: string; valid_to_raw: string | null; source: string; confidence: number | string; note: string };

const toPerson = (r: PersonRow): Person => ({ person_id: r.person_id, display: r.display, kind: r.kind === "service" ? "service" : "person", team: r.team, note: r.note });

function toAlias(r: AliasRow): Alias | null {
  if (!isAliasKind(r.alias_kind)) return null;
  return {
    person_id: r.person_id, kind: r.alias_kind, value: r.alias_value, valid_from: String(r.valid_from),
    valid_to: r.valid_to_raw === null || r.valid_to_raw === "" ? null : String(r.valid_to_raw),
    source: r.source, confidence: Number(r.confidence), note: r.note,
  };
}

const aliasesOf = (rows: AliasRow[]): Alias[] => rows.map(toAlias).filter((a): a is Alias => a !== null);

export async function getPerson(id: string): Promise<Person | null> {
  const rows = await chQuery<PersonRow>(`SELECT * FROM (${PERSONS_LATEST}) WHERE person_id = {id:String}`, { id });
  return rows[0] ? toPerson(rows[0]) : null;
}

export async function personAliases(id: string): Promise<Alias[]> {
  const rows = await chQuery<AliasRow>(`SELECT * FROM (${ALIASES_LATEST}) WHERE person_id = {id:String} ORDER BY alias_kind, valid_from`, { id });
  return aliasesOf(rows);
}

/** Все алиасы (таблица небольшая) — для пометки «неоднозначно» и непривязанных. */
export async function allAliases(): Promise<Alias[]> {
  return aliasesOf(await chQuery<AliasRow>(`SELECT * FROM (${ALIASES_LATEST}) ORDER BY person_id, alias_kind, valid_from LIMIT 100000`));
}

export type PersonSummary = Person & { aliases: number; events: number; incidents: number; last_ts: string | null };

/** Персон в одном запросе активности: на каждую — countIf/maxIf по её предикату. */
const PERSONS_PER_QUERY = 100;

/**
 * Список персон с активностью за период. Каждый человек считается одним
 * OR-предикатом по своим алиасам (тот же aliasPredicate, что у паспорта —
 * счётчики совпадают с count() паспорта, без дедупликации по хешу), партиями
 * по PERSONS_PER_QUERY персон на один проход по окну. Инциденты — по
 * субъектным алиасам, действовавшим на first_ts инцидента.
 */
export async function listPersons(range: ActorRange, now = Date.now()): Promise<PersonSummary[]> {
  const w = clampWindow(rangeWindow(range, now));
  const [persons, aliases] = await Promise.all([
    chQuery<PersonRow>(`${PERSONS_LATEST} ORDER BY display, person_id LIMIT 5000`),
    allAliases(),
  ]);
  const byPerson = new Map<string, Alias[]>();
  for (const a of aliases) byPerson.set(a.person_id, [...(byPerson.get(a.person_id) ?? []), a]);
  const events = new Map<string, { events: number; last_ts: string | null }>();
  const incidents = new Map<string, number>();
  for (let i = 0; i < persons.length; i += PERSONS_PER_QUERY) {
    const chunk = persons.slice(i, i + PERSONS_PER_QUERY).filter((p) => (byPerson.get(p.person_id) ?? []).length > 0);
    if (!chunk.length) continue;
    const evParams: Record<string, string | number> = { from: chTs(w.fromMs), to: chTs(w.toMs) };
    const incParams: Record<string, string | number> = { from: chTs(w.fromMs), to: chTs(w.toMs) };
    const evCols: string[] = [];
    const incCols: string[] = [];
    // Предфильтр по всем алиасам партии: точные countIf считаются только по совпавшим строкам.
    const pf = aliasPrefilter(chunk.flatMap((p) => byPerson.get(p.person_id) ?? []));
    Object.assign(evParams, pf.params);
    chunk.forEach((p, j) => {
      const own = byPerson.get(p.person_id) ?? [];
      const pe = aliasPredicate(own, w, `p${j}_`);
      Object.assign(evParams, pe.params);
      evCols.push(`countIf(${pe.sql}) AS e${j}, toString(maxIf(ts, ${pe.sql})) AS l${j}`);
      const pi = aliasPredicate(own.filter((a) => ACTOR_KINDS.includes(a.kind)), w, `p${j}_`, "first_ts");
      Object.assign(incParams, pi.params);
      incCols.push(`countIf(${pi.sql}) AS i${j}`);
    });
    const [ev, inc] = await Promise.all([
      chQuery<Record<string, string | number>>(
        `SELECT ${evCols.join(", ")} FROM events WHERE ts >= parseDateTime64BestEffort({from:String}, 3, 'UTC') AND ts < parseDateTime64BestEffort({to:String}, 3, 'UTC') AND ${pf.sql}`,
        evParams,
      ),
      chQuery<Record<string, string | number>>(
        `SELECT ${incCols.join(", ")} FROM incidents_current WHERE created_at >= parseDateTimeBestEffort({from:String}) AND created_at < parseDateTimeBestEffort({to:String})`,
        incParams,
      ),
    ]);
    chunk.forEach((p, j) => {
      const n = Number(ev[0]?.[`e${j}`] ?? 0);
      const last = String(ev[0]?.[`l${j}`] ?? "");
      events.set(p.person_id, { events: n, last_ts: n > 0 && !last.startsWith("1970") ? last : null });
      incidents.set(p.person_id, Number(inc[0]?.[`i${j}`] ?? 0));
    });
  }
  return persons.map((p) => ({
    ...toPerson(p),
    aliases: (byPerson.get(p.person_id) ?? []).length,
    events: events.get(p.person_id)?.events ?? 0,
    incidents: incidents.get(p.person_id) ?? 0,
    last_ts: events.get(p.person_id)?.last_ts ?? null,
  }));
}

export type Resolution = { status: ResolveStatus; matches: ResolveMatch[] };

/**
 * Персоны, чьи алиасы любого вида равны значению (email/login/host — без
 * учёта регистра, ip и phone — в канонической форме) и действуют в момент at.
 * 0 — «не привязан», >1 — «неоднозначно»: показывается явно, первый не
 * выбирается. Удержанные алиасы (confidence < 0.5) персону не резолвят.
 */
export async function resolveAlias(value: string, atMs = Date.now()): Promise<Resolution> {
  const rows = await chQuery<AliasRow & { display: string; kind: string }>(
    `SELECT a.person_id, a.alias_kind, a.alias_value, a.valid_from, a.valid_to_raw, a.source, a.confidence, a.note, p.display AS display, p.kind AS kind
     FROM (${ALIASES_LATEST}) a LEFT JOIN (${PERSONS_LATEST}) p ON a.person_id = p.person_id
     WHERE a.alias_value IN ({v:String}, {lv:String}, {cv:String}, {pv:String})
       AND a.valid_from <= parseDateTime64BestEffort({at:String}, 3, 'UTC')
       AND (a.valid_to_raw IS NULL OR parseDateTime64BestEffort({at:String}, 3, 'UTC') < a.valid_to_raw)
     ORDER BY a.person_id, a.alias_kind`,
    { v: value, lv: value.toLowerCase(), cv: canonicalIp(value) ?? value, pv: canonicalPhone(value) ?? value, at: chTs(atMs) },
  );
  // Один алиас может лежать в нескольких строках (yaml и event:<source>,
  // разные valid_from) — на персону одна запись, открытый интервал предпочтительнее.
  const byPerson = new Map<string, ResolveMatch>();
  for (const r of rows) {
    const a = toAlias(r);
    if (!a || isHeld(a) || !aliasMatches(a, value)) continue;
    const m: ResolveMatch = { person_id: a.person_id, display: r.display ?? "", kind: r.kind === "service" ? "service" : "person", alias_kind: a.kind, valid_from: a.valid_from, valid_to: a.valid_to };
    const prev = byPerson.get(a.person_id);
    if (!prev || (prev.valid_to !== null && m.valid_to === null)) byPerson.set(a.person_id, m);
  }
  const matches = [...byPerson.values()];
  return { status: resolveStatus(matches), matches };
}

export type AliasHistoryRow = Alias & { display: string; person_kind: string; held: boolean };

/**
 * История владения значением: все интервалы любого вида алиаса, равного
 * значению (те же правила сравнения, что у resolveAlias), включая закрытые и
 * удержанные, — «кому и когда принадлежал этот IP / почта / телефон».
 * Сортировка по началу интервала, новые сверху.
 */
export async function aliasHistory(value: string, limit = 500): Promise<AliasHistoryRow[]> {
  const rows = await chQuery<AliasRow & { display: string; kind: string }>(
    `SELECT a.person_id, a.alias_kind, a.alias_value, a.valid_from, a.valid_to_raw, a.source, a.confidence, a.note, p.display AS display, p.kind AS kind
     FROM (${ALIASES_LATEST}) a LEFT JOIN (${PERSONS_LATEST}) p ON a.person_id = p.person_id
     WHERE a.alias_value IN ({v:String}, {lv:String}, {cv:String}, {pv:String})
     ORDER BY a.valid_from DESC, a.person_id LIMIT {limit:UInt32}`,
    { v: value, lv: value.toLowerCase(), cv: canonicalIp(value) ?? value, pv: canonicalPhone(value) ?? value, limit: Math.min(5000, Math.max(1, Math.floor(limit))) },
  );
  const out: AliasHistoryRow[] = [];
  for (const r of rows) {
    const a = toAlias(r);
    if (!a || !aliasMatches(a, value)) continue;
    out.push({ ...a, display: r.display ?? "", person_kind: r.kind === "service" ? "service" : "person", held: isHeld(a) });
  }
  return out;
}

export type Sighting = { source: string; action: string; who: string; where: string; ips: string[]; events: number; first_ts: string; last_ts: string };
export type VpnConnection = { actor_name: string; peer_name: string; peer_ip: string; events: number; first_ts: string; last_ts: string };
export type Sightings = { kind: "ip" | "actor"; rows: Sighting[]; vpn: VpnConnection[] };

/**
 * Где значение встречалось в журнале за окно (не шире 30 дней). IP — как адрес
 * источника в событиях не-NetFlow (входы, sshd, прокси, WAF: NetFlow слишком
 * объёмный и смотрится в журнале) и как внешний адрес клиента VPN
 * (attrs.connection_ip у событий класса vpn). Остальное — как actor_name.
 * Индексы: bloom по src_ip и actor_name.
 */
export async function aliasSightings(value: string, range: ActorRange, now = Date.now()): Promise<Sightings> {
  const w = clampWindow(rangeWindow(range, now));
  const win = { from: chTs(w.fromMs), to: chTs(w.toMs) };
  const ts = `ts >= parseDateTime64BestEffort({from:String}, 3, 'UTC') AND ts < parseDateTime64BestEffort({to:String}, 3, 'UTC')`;
  type Row = { source: string; action: string; who: string; at_node: string; ips: string[]; events: string | number; first_ts: string; last_ts: string };
  const toSighting = (r: Row): Sighting => ({ source: r.source, action: r.action, who: r.who, where: r.at_node, ips: (r.ips ?? []).filter(Boolean), events: Number(r.events), first_ts: r.first_ts, last_ts: r.last_ts });
  const ip = canonicalIp(value);
  if (ip) {
    const [rows, vpn] = await Promise.all([
      chQuery<Row>(
        `SELECT source, action, actor_name AS who, any(node) AS at_node, groupUniqArray(5)(dst_ip) AS ips, count() AS events, toString(min(ts)) AS first_ts, toString(max(ts)) AS last_ts
         FROM events WHERE ${ts} AND src_ip = {ip:String} AND source_class != 'netflow'
         GROUP BY source, action, actor_name ORDER BY last_ts DESC LIMIT 100`,
        { ...win, ip },
      ),
      chQuery<{ actor_name: string; peer_name: string; peer_ip: string; events: string | number; first_ts: string; last_ts: string }>(
        `SELECT actor_name, attrs['peer_name'] AS peer_name, any(src_ip) AS peer_ip, count() AS events, toString(min(ts)) AS first_ts, toString(max(ts)) AS last_ts
         FROM events WHERE ${ts} AND source_class = 'vpn' AND attrs['connection_ip'] = {ip:String}
         GROUP BY actor_name, peer_name ORDER BY last_ts DESC LIMIT 100`,
        { ...win, ip },
      ),
    ]);
    return { kind: "ip", rows: rows.map(toSighting), vpn: vpn.map((r) => ({ ...r, events: Number(r.events) })) };
  }
  const rows = await chQuery<Row>(
    `SELECT source, action, actor_name AS who, node AS at_node, groupUniqArray(5)(src_ip) AS ips, count() AS events, toString(min(ts)) AS first_ts, toString(max(ts)) AS last_ts
     FROM events WHERE ${ts} AND actor_name IN ({v:String}, {lv:String})
     GROUP BY source, action, actor_name, node ORDER BY last_ts DESC LIMIT 100`,
    { ...win, v: value, lv: value.toLowerCase() },
  );
  return { kind: "actor", rows: rows.map(toSighting), vpn: [] };
}

export type UnboundSubject = { actor_name: string; count: number; first_ts: string; last_ts: string; sources: string[] };

/** Топ actor_name за период без действующего (на момент последней активности) субъектного алиаса. */
// Системные субъекты (actor_kind system: телеметрия самого ARGUS, сторожа) людям не
// принадлежат и в список не попадают; сервисные учётки остаются — их заводят персонами вида service.
export async function unboundSubjects(range: ActorRange, limit = 30, now = Date.now()): Promise<UnboundSubject[]> {
  const w = clampWindow(rangeWindow(range, now));
  const [top, aliases] = await Promise.all([
    chQuery<{ actor_name: string; count: string | number; first_ts: string; last_ts: string; sources: string[] }>(
      `SELECT actor_name, count() AS count, toString(min(ts)) AS first_ts, toString(max(ts)) AS last_ts, groupUniqArray(5)(source) AS sources
       FROM events WHERE ts >= parseDateTime64BestEffort({from:String}, 3, 'UTC') AND ts < parseDateTime64BestEffort({to:String}, 3, 'UTC')
         AND actor_name != '' AND actor_kind != 'system'
       GROUP BY actor_name ORDER BY count DESC LIMIT {limit:UInt32}`,
      { from: chTs(w.fromMs), to: chTs(w.toMs), limit: Math.max(limit * 3, 30) },
    ),
    allAliases(),
  ]);
  const subjectAliases = activeAliases(aliases).filter((a) => ACTOR_KINDS.includes(a.kind));
  const out: UnboundSubject[] = [];
  for (const t of top) {
    const lastMs = Date.parse(t.last_ts.replace(" ", "T") + "Z");
    const bound = subjectAliases.some((a) => aliasMatches(a, t.actor_name) && aliasActiveAt(a, lastMs));
    if (!bound) out.push({ actor_name: t.actor_name, count: Number(t.count), first_ts: t.first_ts, last_ts: t.last_ts, sources: t.sources ?? [] });
    if (out.length >= limit) break;
  }
  return out;
}

type IncidentRaw = Omit<ActorIncident, "created_at"> & { created_s: string; actor_name: string; first_s: string };

export type ReportOptions = {
  /** Окно вместо окна периода (сессия разбора: не раньше first_ts − 30 дней). */
  window?: Window;
  /** Привязка строк сессии разбора — обязательный предикат всех частей отчёта
   *  (сводки, источники, разделы, таймлайн), не только таймлайна. */
  bind?: TriageBinding;
  /** Сессия разбора видит только свой инцидент и связанные с ним. */
  incidentIds?: string[];
  now?: number;
};

function bindPredicate(bind: TriageBinding, params: Record<string, string | number>): string {
  const parts: string[] = [];
  if (bind.actors.length) {
    bind.actors.forEach((a, i) => (params[`ba${i}`] = a));
    parts.push(`actor_name IN (${bind.actors.map((_, i) => `{ba${i}:String}`).join(", ")})`);
  }
  if (bind.nodes.length) {
    bind.nodes.forEach((n, i) => (params[`bn${i}`] = n));
    parts.push(`node IN (${bind.nodes.map((_, i) => `{bn${i}:String}`).join(", ")})`);
  }
  return parts.length ? `(${parts.join(" OR ")})` : "0";
}

/**
 * Паспорт за период: сводка по классам источников, узлы, адреса, покрытие
 * источников, инциденты (actor_name ∈ субъектных алиасов, действовавших на
 * first_ts), таймлайн последних N событий в форме /api/v1/log и его разбивка
 * по разделам. Персона и алиасы обязательны (исключение), остальное —
 * частичная деградация через missing. Удержанные алиасы в aliases остаются
 * (паспорт их показывает), но ни один предикат их не использует.
 */
export async function actorReport(person: Person, aliases: Alias[], range: ActorRange, limit: number, opts: ReportOptions = {}): Promise<ActorReport> {
  const now = opts.now ?? Date.now();
  const w = clampWindow(opts.window ?? rangeWindow(range, now));
  const pred = aliasPredicate(aliases, w);
  // Предфильтр по индексу idx_actor_keys: без него каждая агрегация читала всё окно.
  const pf = aliasPrefilter(aliases);
  const params: Record<string, string | number> = { ...pred.params, ...pf.params, from: chTs(w.fromMs), to: chTs(w.toMs) };
  const bind = opts.bind ? ` AND ${bindPredicate(opts.bind, params)}` : "";
  const base = `ts >= parseDateTime64BestEffort({from:String}, 3, 'UTC') AND ts < parseDateTime64BestEffort({to:String}, 3, 'UTC') AND ${pf.sql} AND ${pred.sql}${bind}`;

  // Инциденты: actor_name инцидента среди субъектных алиасов (без удержанных) — для email/login без учёта регистра.
  const subject = activeAliases(aliases).filter((a) => ACTOR_KINDS.includes(a.kind));
  const incParams: Record<string, string | number> = { from: chTs(w.fromMs), to: chTs(w.toMs) };
  // Сессия разбора: разрешённые инциденты отбираются в SQL до LIMIT — иначе 200
  // других инцидентов субъекта вытеснили бы свой. Array(String) параметром.
  let incScope = "";
  if (opts.incidentIds) {
    incParams.ids = `[${opts.incidentIds.map((id) => `'${id.replace(/\\/g, "\\\\").replace(/'/g, "\\'")}'`).join(",")}]`;
    incScope = " AND incident_id IN ({ids:Array(String)})";
  }
  const incParts: string[] = [];
  for (const [kinds, expr] of [[subject.filter((a) => LOWERCASE_KINDS.includes(a.kind)), aliasColumnExpr("login", "actor_name")], [subject.filter((a) => !LOWERCASE_KINDS.includes(a.kind)), "actor_name"]] as const) {
    if (!kinds.length) continue;
    const names = kinds.map((a, i) => { const n = `${expr === "actor_name" ? "x" : "l"}${i}`; incParams[n] = a.value; return `{${n}:String}`; });
    incParts.push(`${expr} IN (${names.join(", ")})`);
  }
  const tlParams: Record<string, string | number> = { ...params, limit };

  const [classes, nodes, ips, sources, incRows, tl, amb] = await Promise.all([
    safeQuery(() => chQuery<{ source_class: string; count: string | number }>(`SELECT source_class, count() AS count FROM events WHERE ${base} GROUP BY source_class ORDER BY count DESC`, params)),
    safeQuery(() => chQuery<NodeStat>(`SELECT node, count() AS count, toString(min(ts)) AS first_ts, toString(max(ts)) AS last_ts FROM events WHERE ${base} AND node != '' GROUP BY node ORDER BY count DESC LIMIT 50`, params)),
    safeQuery(() => chQuery<IpStat>(`SELECT src_ip, count() AS count, toString(min(ts)) AS first_ts, toString(max(ts)) AS last_ts FROM events WHERE ${base} AND src_ip != '' GROUP BY src_ip ORDER BY count DESC LIMIT 50`, params)),
    safeQuery(() => chQuery<SourceCoverage>(`SELECT source, source_class, count() AS count, toString(min(ts)) AS first_ts, toString(max(ts)) AS last_ts FROM events WHERE ${base} GROUP BY source, source_class ORDER BY count DESC LIMIT 100`, params)),
    // Алиасы created_s/first_s: одноимённый алиас затенял бы колонку в WHERE (String против DateTime).
    safeQuery(() => incParts.length === 0 ? Promise.resolve([]) : chQuery<IncidentRaw>(
      `SELECT incident_id AS id, level, status, rule_id, rule_title, toString(created_at) AS created_s, actor_name, toString(first_ts) AS first_s
       FROM incidents_current WHERE (${incParts.join(" OR ")})${incScope}
         AND created_at >= parseDateTimeBestEffort({from:String}) AND created_at < parseDateTimeBestEffort({to:String})
       ORDER BY created_at DESC LIMIT 200`, incParams)),
    safeQuery(() => chQuery<Record<string, unknown>>(`SELECT ${LOG_COLUMNS} FROM events WHERE ${base} ORDER BY ts DESC LIMIT {limit:UInt32}`, tlParams)),
    safeQuery(() => allAliases()),
  ]);

  const missing: string[] = [];
  const take = <T,>(r: { ok: true; data: T } | { ok: false }, label: string, empty: T): T => {
    if (r.ok) return r.data;
    missing.push(label);
    return empty;
  };
  const byClass = take(classes, "сводка по классам", [] as { source_class: string; count: string | number }[]).map((c): ClassCount => ({ source_class: c.source_class, count: Number(c.count) }));
  const nodeStats = take(nodes, "узлы", [] as NodeStat[]).map((n) => ({ ...n, count: Number(n.count) }));
  const ipStats = take(ips, "адреса", [] as IpStat[]).map((n) => ({ ...n, count: Number(n.count) }));
  const coverage = take(sources, "источники", [] as SourceCoverage[]).map((s) => ({ ...s, count: Number(s.count) }));
  // Инцидент — субъекта, только если алиас действовал на first_ts инцидента.
  const allowed = opts.incidentIds ? new Set(opts.incidentIds) : null;
  const incidents: ActorIncident[] = take(incRows, "инциденты", [] as IncidentRaw[])
    .filter((i) => !allowed || allowed.has(i.id))
    .filter((i) => subject.some((a) => aliasMatches(a, i.actor_name) && aliasActiveAt(a, Date.parse(i.first_s.replace(" ", "T") + "Z"))))
    .map(({ id, level, status, rule_id, rule_title, created_s }) => ({ id, level, status, rule_id, rule_title, created_at: created_s }));
  const timeline: LogItem[] = take(tl, "таймлайн", [] as Record<string, unknown>[]).map(toLogItem);
  let ambiguous: string[] = [];
  if (amb.ok) ambiguous = [...ambiguousAliases(amb.data, w)].filter((k) => aliases.some((a) => aliasKey(a) === k));
  else missing.push("проверка неоднозначности");

  return {
    person, aliases, ambiguous,
    range: { key: range, from: chTs(w.fromMs), to: chTs(w.toMs) },
    summary: {
      events: byClass.reduce((s, c) => s + c.count, 0),
      by_source_class: Object.fromEntries(byClass.map((c) => [c.source_class, c.count])),
      nodes: nodeStats, src_ips: ipStats, incidents: incidents.length,
    },
    sources: coverage,
    sections: bucketEvents(timeline),
    incidents, timeline, limit, missing,
    generated_at: chTs(now),
  };
}

/* ===== Запись: upsert персон и алиасов, закрытие алиаса ===== */

const CHUNK = 200;

/** Upsert персон и их алиасов (новая версия строки; ReplacingMergeTree схлопнет). */
export async function upsertIdentities(persons: PersonInput[], source: string): Promise<{ persons: number; aliases: number }> {
  let aliasCount = 0;
  for (let i = 0; i < persons.length; i += CHUNK) {
    const chunk = persons.slice(i, i + CHUNK);
    const params: Record<string, string | number> = {};
    const rows = chunk.map((p, j) => {
      params[`p${j}`] = p.person_id; params[`d${j}`] = p.display; params[`k${j}`] = p.kind; params[`t${j}`] = p.team; params[`n${j}`] = p.note;
      return `({p${j}:String}, {d${j}:String}, {k${j}:String}, {t${j}:String}, {n${j}:String}, now64(3), 0)`;
    });
    await chCommand(`INSERT INTO identities (person_id, display, kind, team, note, updated_at, deleted) VALUES ${rows.join(", ")}`, params);
  }
  const flat = persons.flatMap((p) => p.aliases.map((a) => ({ person_id: p.person_id, a })));
  for (let i = 0; i < flat.length; i += CHUNK) {
    await insertAliases(flat.slice(i, i + CHUNK), source);
    aliasCount += Math.min(CHUNK, flat.length - i);
  }
  return { persons: persons.length, aliases: aliasCount };
}

/** Алиас без from действует на всю историю журнала (как в identities.yml);
 *  фиксированное начало делает повторный импорт идемпотентным (тот же ключ строки). */
const ALIAS_EPOCH = "1970-01-01 00:00:00.000";

async function insertAliases(rows: { person_id: string; a: AliasInput }[], source: string): Promise<void> {
  if (!rows.length) return;
  const params: Record<string, string | number> = { src: source };
  const values = rows.map(({ person_id, a }, j) => {
    params[`p${j}`] = person_id; params[`k${j}`] = a.kind; params[`v${j}`] = a.value;
    params[`f${j}`] = a.valid_from ?? ALIAS_EPOCH; params[`t${j}`] = a.valid_to ?? ""; params[`c${j}`] = a.confidence; params[`n${j}`] = a.note;
    return `({p${j}:String}, {k${j}:String}, {v${j}:String}, parseDateTime64BestEffort({f${j}:String}, 3, 'UTC'), parseDateTime64BestEffortOrNull({t${j}:String}, 3, 'UTC'), {src:String}, {c${j}:Float32}, {n${j}:String}, now64(3), 0)`;
  });
  await chCommand(`INSERT INTO identity_aliases (person_id, alias_kind, alias_value, valid_from, valid_to, source, confidence, note, updated_at, deleted) VALUES ${values.join(", ")}`, params);
}

/** Привязать алиас к персоне (создав персону, если её нет). */
export async function bindAlias(person: Person, alias: AliasInput, source: string, createPerson: boolean): Promise<void> {
  if (createPerson) await upsertIdentities([{ ...person, aliases: [] }], source);
  await insertAliases([{ person_id: person.person_id, a: alias }], source);
}

/** Новые версии строк алиаса с тем же ключом (person, kind, value, valid_from) и подменёнными полями. */
async function rewriteAliases(rows: Alias[], patch: (a: Alias) => Pick<Alias, "valid_to" | "confidence" | "note">): Promise<void> {
  if (!rows.length) return;
  const params: Record<string, string | number> = {};
  const values = rows.map((a, j) => {
    const p = patch(a);
    params[`p${j}`] = a.person_id; params[`k${j}`] = a.kind; params[`v${j}`] = a.value; params[`f${j}`] = a.valid_from;
    params[`t${j}`] = p.valid_to ?? ""; params[`s${j}`] = a.source; params[`c${j}`] = p.confidence; params[`n${j}`] = p.note;
    return `({p${j}:String}, {k${j}:String}, {v${j}:String}, parseDateTime64BestEffort({f${j}:String}, 3, 'UTC'), parseDateTime64BestEffortOrNull({t${j}:String}, 3, 'UTC'), {s${j}:String}, {c${j}:Float32}, {n${j}:String}, now64(3), 0)`;
  });
  await chCommand(`INSERT INTO identity_aliases (person_id, alias_kind, alias_value, valid_from, valid_to, source, confidence, note, updated_at, deleted) VALUES ${values.join(", ")}`, params);
}

/** Последние версии строк алиаса персоны по виду и нормализованному значению. */
async function aliasRows(personId: string, kind: string, value: string): Promise<Alias[]> {
  if (!isAliasKind(kind)) return [];
  const v = normalizeAliasValue(kind, value);
  return aliasesOf(await chQuery<AliasRow>(
    `SELECT * FROM (${ALIASES_LATEST}) WHERE person_id = {id:String} AND alias_kind = {k:String} AND alias_value = {v:String}`,
    { id: personId, k: kind, v },
  ));
}

/**
 * Подтвердить удержанный алиас: версии строки с confidence < 0.5 получают
 * confidence = 1 новой версией с тем же ключом; пометка policy:hold:<…>
 * становится policy:confirmed:<…>. Возвращает число подтверждённых.
 */
export async function confirmAlias(personId: string, kind: string, value: string): Promise<number> {
  const rows = (await aliasRows(personId, kind, value)).filter(isHeld);
  await rewriteAliases(rows, (a) => ({
    valid_to: a.valid_to, confidence: 1,
    note: a.note.startsWith(HOLD_NOTE_PREFIX) ? CONFIRMED_NOTE_PREFIX + a.note.slice(HOLD_NOTE_PREFIX.length) : a.note,
  }));
  return rows.length;
}

/**
 * Закрыть алиас: действующие версии строки (person, kind, value) получают
 * valid_to = at новой версией с тем же ключом. Возвращает число закрытых.
 */
export async function closeAlias(personId: string, kind: string, value: string, atMs = Date.now()): Promise<number> {
  const rows = (await aliasRows(personId, kind, value)).filter((a) => a.valid_to === null || Date.parse(a.valid_to.replace(" ", "T") + "Z") > atMs);
  await rewriteAliases(rows, (a) => ({ valid_to: chTs(atMs), confidence: a.confidence, note: a.note }));
  return rows.length;
}
