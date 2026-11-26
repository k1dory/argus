// Трассировка субъекта: события паспорта, свёрнутые в «сессия → откуда → куда →
// что». ClickHouse отдаёт агрегаты по корзинам времени (TraceRow), здесь из них
// собирается дерево. Чистые функции — без ClickHouse, проверяются юнит-тестами.
import { appendTerm } from "./search-query";
import { toDtParam } from "./filters";
import { ACTOR_KINDS, activeAliases, aliasMatches, tsMs, type ActorIncident, type ActorRange, type Alias, type Section } from "./actors";
import { MAX_Q_LEN } from "./journal";

/** Чем является цель: узел, адрес назначения, объект события или (если ничего нет) источник. */
export type TargetKind = "node" | "dst" | "object" | "source";

/** Строка агрегата: одна корзина времени × раздел × откуда × куда × источник × действие. */
export type TraceRow = {
  section: Section;
  origin: string;
  target: string;
  target_kind: TargetKind;
  dst_port: number;
  source: string;
  action: string;
  /** actor_name события ('' у NetFlow) — для ссылки в журнал в границах субъекта. */
  actor?: string;
  /** Что именно на узле (команды sudo, объект сеанса) — topK корзины со счётчиками
   *  ({item, count}); строки без счётчика — в порядке убывания частоты. Только раздел host. */
  details?: (string | { item: string; count: string | number })[];
  count: number;
  fails: number;
  first_ts: string;
  last_ts: string;
  /** Время первого неотказного события корзины ('' или эпоха — успехов не было). */
  first_ok_ts?: string;
};

export type TraceAction = { action: string; source: string; count: number; fails: number; first: number; last: number; actors: string[];
  /** Активность каждого actor действия [первое, последнее] — для окна ссылки. */
  actorSpan?: Record<string, Segment>;
  /** Команды/объекты действия на узле, частые — первыми (до TRACE_DETAILS_MAX). */
  details: string[] };

export const TRACE_DETAILS_MAX = 5;
/** Интервал активности внутри полосы. */
export type Segment = [from: number, to: number];

export type TraceSpan = {
  section: Section;
  target: string;
  target_kind: TargetKind;
  dst_port: number;
  first: number;
  last: number;
  count: number;
  fails: number;
  sources: string[];
  /** actor_name событий полосы, частые — первыми. */
  actors: string[];
  actions: TraceAction[];
  segments: Segment[];
  /** Свёрнутая строка «ещё N адресов» (только сеть). */
  folded?: number;
  /** Событие без адреса источника, привязанное к входу на тот же узел. */
  attached?: boolean;
};

export type TraceOrigin = { origin: string; first: number; last: number; count: number; fails: number; spans: TraceSpan[] };

export type TraceSession = {
  id: string;
  first: number;
  last: number;
  count: number;
  fails: number;
  /** Сессия целиком из сетевых потоков — без входов, команд и приложений. */
  networkOnly: boolean;
  origins: TraceOrigin[];
  incidents: ActorIncident[];
};

export type ActorTrace = {
  sessions: TraceSession[];
  /** Выборка упёрлась в потолок строк — показаны самые свежие корзины. */
  truncated: boolean;
  bucketSec: number;
  gapMs: number;
  networkTop: number;
};

/** Корзина агрегации по периоду: чем шире окно, тем грубее. */
export const TRACE_BUCKET_SEC: Record<ActorRange, number> = { "24h": 60, "7d": 300, "30d": 900 };
/** Перерыв дольше — новая сессия. */
export const TRACE_GAP_MS = 30 * 60_000;
/** Сколько сети до первого и после последнего действия ещё относится к сессии. */
export const TRACE_NET_SLACK_MS = 5 * 60_000;
/** Адресов назначения на источник в сессии; остальное — одной строкой. */
export const TRACE_NETWORK_TOP = 8;
export const TRACE_ROWS_MAX = 20_000;

const FAIL_RE = /fail|deny|denied|error/i;
export const isFailOutcome = (outcome: string): boolean => FAIL_RE.test(outcome);

type Item = TraceRow & { firstMs: number; lastMs: number; okMs: number | null };

function toItems(rows: TraceRow[]): Item[] {
  const out: Item[] = [];
  for (const r of rows) {
    const firstMs = tsMs(r.first_ts);
    const lastMs = tsMs(r.last_ts) ?? firstMs;
    if (firstMs === null || lastMs === null) continue;
    const count = Number(r.count);
    const fails = Number(r.fails);
    // Успех корзины: явное время из SQL; без него — только если отказов не было вовсе.
    const ok = tsMs(r.first_ok_ts);
    const okMs = ok !== null && ok > 86_400_000 ? ok : fails === 0 && count > 0 ? firstMs : null;
    out.push({ ...r, count, fails, dst_port: Number(r.dst_port) || 0, firstMs, lastMs: Math.max(firstMs, lastMs), okMs });
  }
  return out.sort((a, b) => a.firstMs - b.firstMs || a.lastMs - b.lastMs);
}

/** Склейка по перерыву: группы, внутри которых соседние элементы ближе gap. */
function clusters<T extends { firstMs: number; lastMs: number }>(items: T[], gapMs: number): T[][] {
  const out: T[][] = [];
  let cur: T[] = [];
  let end = -Infinity;
  for (const it of items) {
    if (cur.length && it.firstMs > end + gapMs) {
      out.push(cur);
      cur = [];
      end = -Infinity;
    }
    cur.push(it);
    end = Math.max(end, it.lastMs);
  }
  if (cur.length) out.push(cur);
  return out;
}

function mergeSegments(segs: Segment[], joinMs: number): Segment[] {
  const sorted = [...segs].sort((a, b) => a[0] - b[0]);
  const out: Segment[] = [];
  for (const s of sorted) {
    const last = out[out.length - 1];
    if (last && s[0] <= last[1] + joinMs) last[1] = Math.max(last[1], s[1]);
    else out.push([s[0], s[1]]);
  }
  return out;
}

const spanKey = (it: Pick<TraceRow, "section" | "target" | "target_kind" | "dst_port">) => `${it.section}\u0000${it.target_kind}\u0000${it.target}\u0000${it.dst_port}`;

function buildSpan(items: Item[], joinMs: number): TraceSpan {
  const actions = new Map<string, { a: TraceAction; items: Item[] }>();
  for (const it of items) {
    const k = `${it.source}\u0000${it.action}`;
    const e = actions.get(k);
    if (e) {
      e.a.count += it.count; e.a.fails += it.fails;
      e.a.first = Math.min(e.a.first, it.firstMs); e.a.last = Math.max(e.a.last, it.lastMs);
      e.items.push(it);
    } else actions.set(k, { a: { action: it.action, source: it.source, count: it.count, fails: it.fails, first: it.firstMs, last: it.lastMs, actors: [], details: [] }, items: [it] });
  }
  for (const e of actions.values()) {
    e.a.actors = rankActors(e.items);
    const span: Record<string, Segment> = {};
    for (const i of e.items) {
      if (!i.actor) continue;
      const cur = span[i.actor];
      span[i.actor] = cur ? [Math.min(cur[0], i.firstMs), Math.max(cur[1], i.lastMs)] : [i.firstMs, i.lastMs];
    }
    e.a.actorSpan = span;
    const d = new Map<string, number>();
    for (const i of e.items) {
      const list = i.details ?? [];
      list.forEach((x, idx) => {
        // Частота детали — её собственный счётчик topK, а не count всей корзины;
        // без счётчика — убывающий вес по позиции (topK уже упорядочен).
        const [item, w] = typeof x === "string" ? [x, i.count * (list.length - idx) / list.length] : [x.item, Number(x.count) || 0];
        if (item) d.set(item, (d.get(item) ?? 0) + w);
      });
    }
    e.a.details = [...d.entries()].sort((x, y) => y[1] - x[1] || x[0].localeCompare(y[0])).slice(0, TRACE_DETAILS_MAX).map(([k]) => k);
  }
  const h = items[0];
  return {
    section: h.section, target: h.target, target_kind: h.target_kind, dst_port: h.dst_port,
    first: Math.min(...items.map((i) => i.firstMs)), last: Math.max(...items.map((i) => i.lastMs)),
    count: items.reduce((s, i) => s + i.count, 0), fails: items.reduce((s, i) => s + i.fails, 0),
    sources: [...new Set(items.map((i) => i.source))].sort(),
    actors: rankActors(items),
    actions: [...actions.values()].map((e) => e.a).sort((a, b) => b.count - a.count || a.first - b.first),
    segments: mergeSegments(items.map((i) => [i.firstMs, i.lastMs]), joinMs),
  };
}

function foldNetwork(spans: TraceSpan[], top: number): TraceSpan[] {
  const net = spans.filter((s) => s.section === "network").sort((a, b) => b.count - a.count);
  if (net.length <= top) return spans;
  const keep = new Set(net.slice(0, top));
  const rest = net.slice(top);
  const folded: TraceSpan = {
    section: "network", target: "", target_kind: "dst", dst_port: 0,
    first: Math.min(...rest.map((s) => s.first)), last: Math.max(...rest.map((s) => s.last)),
    count: rest.reduce((n, s) => n + s.count, 0), fails: rest.reduce((n, s) => n + s.fails, 0),
    sources: [...new Set(rest.flatMap((s) => s.sources))].sort(), actors: [], actions: [],
    segments: mergeSegments(rest.flatMap((s) => s.segments), 0), folded: rest.length,
  };
  return [...spans.filter((s) => s.section !== "network" || keep.has(s)), folded];
}

function rankActors(items: Pick<TraceRow, "actor" | "count">[]): string[] {
  const n = new Map<string, number>();
  for (const i of items) if (i.actor) n.set(i.actor, (n.get(i.actor) ?? 0) + i.count);
  return [...n.entries()].sort((a, b) => b[1] - a[1] || a[0].localeCompare(b[0])).map(([a]) => a);
}

const SECTION_ORDER: Record<Section, number> = { login: 0, app: 1, host: 2, change: 3, other: 4, network: 5 };

function buildOrigins(items: Item[], joinMs: number, networkTop: number): TraceOrigin[] {
  // События без адреса источника (sudo, сеанс на узле) — к источнику входа на
  // тот же узел: только раздел «вход», только успех и только раньше события
  // (по времени первого успеха, а не первого события корзины). Источников
  // несколько — не угадываем: событие остаётся в ветке «без адреса».
  const loginsByNode = new Map<string, { origin: string; okMs: number }[]>();
  for (const it of items) {
    if (!it.origin || it.target_kind !== "node" || it.section !== "login" || it.okMs === null || LOGOUT_RE.test(it.action)) continue;
    const list = loginsByNode.get(it.target) ?? [];
    list.push({ origin: it.origin, okMs: it.okMs });
    loginsByNode.set(it.target, list);
  }
  const entryFor = (it: Item): string | null => {
    const origins = new Set((loginsByNode.get(it.target) ?? []).filter((l) => l.okMs <= it.firstMs).map((l) => l.origin));
    return origins.size === 1 ? [...origins][0] : null;
  };
  const byOrigin = new Map<string, Map<string, { items: Item[]; attached: boolean }>>();
  for (const it of items) {
    let origin = it.origin;
    let attached = false;
    const entry = !origin && it.target_kind === "node" ? entryFor(it) : null;
    if (entry) {
      origin = entry;
      attached = true;
    }
    const spans = byOrigin.get(origin) ?? new Map();
    byOrigin.set(origin, spans);
    const k = `${spanKey(it)}\u0000${attached ? 1 : 0}`;
    const s = spans.get(k) ?? { items: [], attached };
    spans.set(k, s);
    s.items.push(it);
  }
  const origins: TraceOrigin[] = [];
  for (const [origin, spansMap] of byOrigin) {
    const built = [...spansMap.values()].map(({ items: its, attached }) => ({ ...buildSpan(its, joinMs), ...(attached ? { attached } : {}) }));
    const spans = foldNetwork(built, networkTop).sort((a, b) => a.first - b.first || SECTION_ORDER[a.section] - SECTION_ORDER[b.section]);
    origins.push({
      origin, spans,
      first: Math.min(...spans.map((s) => s.first)), last: Math.max(...spans.map((s) => s.last)),
      count: spans.reduce((n, s) => n + s.count, 0), fails: spans.reduce((n, s) => n + s.fails, 0),
    });
  }
  // Ветка без адреса — последней: она не «откуда», а остаток.
  return origins.sort((a, b) => (a.origin ? 0 : 1) - (b.origin ? 0 : 1) || a.first - b.first);
}

export type BuildTraceOptions = { gapMs?: number; bucketSec?: number; networkTop?: number; incidents?: ActorIncident[]; truncated?: boolean };

/**
 * Сессии строятся по «осмысленной» активности (входы, узлы, приложения,
 * изменения): фоновые потоки NetFlow идут сутками и склеили бы всё в одну
 * сессию. Сеть подвешивается к сессии, в окно действий которой попала (строки —
 * корзины, поэтому поток режется по времени); сеть вне сессий — свои сессии
 * «только сеть».
 */
export function buildTrace(rows: TraceRow[], opts: BuildTraceOptions = {}): ActorTrace {
  const gapMs = opts.gapMs ?? TRACE_GAP_MS;
  const bucketSec = opts.bucketSec ?? 60;
  const networkTop = opts.networkTop ?? TRACE_NETWORK_TOP;
  const joinMs = bucketSec * 1000;
  const items = toItems(rows);
  const active = items.filter((i) => i.section !== "network");
  const net = items.filter((i) => i.section === "network");

  const groups = clusters(active, gapMs).map((g) => ({ first: g[0].firstMs, last: Math.max(...g.map((i) => i.lastMs)), items: [...g], networkOnly: false }));
  const loose: Item[] = [];
  for (const n of net) {
    // Ближайшая по времени сессия, в чьё окно (±gap) попал поток.
    let best: (typeof groups)[number] | null = null;
    let bestDist = Infinity;
    for (const g of groups) {
      // Сеть — в окне действий с малым допуском: с допуском gap фон растягивал шкалу сессии на ±30 мин.
      if (n.lastMs < g.first - TRACE_NET_SLACK_MS || n.firstMs > g.last + TRACE_NET_SLACK_MS) continue;
      const dist = n.firstMs > g.last ? n.firstMs - g.last : n.lastMs < g.first ? g.first - n.lastMs : 0;
      if (dist < bestDist) { best = g; bestDist = dist; }
    }
    if (best) best.items.push(n);
    else loose.push(n);
  }
  for (const g of clusters(loose, gapMs)) groups.push({ first: g[0].firstMs, last: Math.max(...g.map((i) => i.lastMs)), items: g, networkOnly: true });

  const incidents = opts.incidents ?? [];
  const sessions: TraceSession[] = groups.map((g) => {
    const first = Math.min(...g.items.map((i) => i.firstMs));
    const last = Math.max(...g.items.map((i) => i.lastMs));
    return {
      id: `s${first}`,
      first, last, networkOnly: g.networkOnly,
      count: g.items.reduce((n, i) => n + i.count, 0),
      fails: g.items.reduce((n, i) => n + i.fails, 0),
      origins: buildOrigins(g.items, joinMs, networkTop),
      incidents: [] as ActorIncident[],
    };
  }).sort((a, b) => b.first - a.first);

  attachIncidents(sessions, incidents, gapMs);
  return { sessions, truncated: Boolean(opts.truncated), bucketSec, gapMs, networkTop };
}

/** Инцидент — к ближайшей сессии, в окно которой (±gap) попало его создание. Мутирует sessions. */
export function attachIncidents(sessions: TraceSession[], incidents: ActorIncident[], gapMs: number = TRACE_GAP_MS): void {
  for (const inc of incidents) {
    const at = tsMs(inc.created_at);
    if (at === null) continue;
    let best: TraceSession | null = null;
    let bestDist = Infinity;
    for (const s of sessions) {
      if (at < s.first - gapMs || at > s.last + gapMs) continue;
      const dist = at < s.first ? s.first - at : at > s.last ? at - s.last : 0;
      if (dist < bestDist) { best = s; bestDist = dist; }
    }
    if (best && !best.incidents.some((i) => i.id === inc.id)) best.incidents.push(inc);
  }
}

/* ===== Подписи и ссылки ===== */

export const TRACE_SECTION_LABELS: Record<Section, string> = {
  login: "вход", host: "узел", network: "сеть", app: "приложение", change: "изменение", other: "прочее",
};

/** Подпись объекта в строке; ключ и ссылка — по полному значению. */
const OBJECT_LABEL_MAX = 160;

export function spanLabel(s: Pick<TraceSpan, "target" | "target_kind" | "dst_port" | "folded">): string {
  if (s.folded) return `ещё ${s.folded} адресов`;
  if (s.target_kind === "dst") return s.dst_port ? `${s.target}:${s.dst_port}` : s.target || "—";
  const t = s.target || "—";
  return s.target_kind === "object" && t.length > OBJECT_LABEL_MAX ? `${t.slice(0, OBJECT_LABEL_MAX)}…` : t;
}

export function fmtDuration(ms: number): string {
  if (ms < 60_000) return `${Math.max(0, Math.round(ms / 1000))} с`;
  const m = Math.round(ms / 60_000);
  if (m < 60) return `${m} мин`;
  const h = Math.floor(m / 60);
  return m % 60 ? `${h} ч ${m % 60} мин` : `${h} ч`;
}

/** Потолок строки поиска журнала (MAX_QUERY_LEN в search.ts, MAX_Q_LEN в journal.ts):
 *  длиннее — журнал молча обрежет условия, поэтому такую ссылку не строим. */
export const TRACE_LINK_Q_MAX = MAX_Q_LEN;

/** Интервалы владения значением фильтра: actor — субъектные алиасы, src — ip. */
export type OwnerScope = (field: "actor" | "src" | "node", value: string) => Segment[];

/** Интервалы владения из алиасов субъекта [valid_from, valid_to) (удержанные не дают владения). */
export function ownerScope(aliases: Alias[]): OwnerScope {
  const live = activeAliases(aliases);
  const fits = (field: "actor" | "src" | "node", a: Alias) =>
    field === "actor" ? ACTOR_KINDS.includes(a.kind) : field === "src" ? a.kind === "ip" : a.kind === "host";
  return (field, value) => live
    .filter((a) => fits(field, a) && aliasMatches(a, value))
    .map((a): Segment => [tsMs(a.valid_from) ?? 0, a.valid_to ? tsMs(a.valid_to) ?? Infinity : Infinity])
    .sort((x, y) => x[0] - y[0]);
}

const floorS = (ms: number) => Math.floor(ms / 1000) * 1000;
const ceilS = (ms: number) => Math.ceil(ms / 1000) * 1000;

/**
 * Окно ссылки в секундах журнала (ts >= from AND ts <= to, обе границы — целые
 * секунды). Без интервала владения — [⌊first⌋, ⌈last⌉]. С интервалом [vf, vt):
 * from ≥ vf, to < vt — иначе захватили бы события прежнего или следующего
 * владельца. null — окно не задевает активность (непредставимо в секундах).
 */
export function linkWindow(first: number, last: number, iv: Segment | null): [number, number] | null {
  let from = floorS(first);
  let to = ceilS(last);
  if (iv) {
    from = Math.max(from, ceilS(iv[0]));
    if (Number.isFinite(iv[1])) to = Math.min(to, iv[1] % 1000 === 0 ? iv[1] - 1000 : floorS(iv[1]));
  }
  if (from > to || from > last || to < first) return null;
  return [from, to];
}

const windowQuery = ([from, to]: [number, number]) => `from=${toDtParam(from, true)}&to=${toDtParam(to, true)}`;

/** Выход из системы: в разделе «вход» по SECTION_SQL, но не вход. */
export const LOGOUT_RE = /logout|logoff|log_off|signout|sign_out|sign-out|disconnect/i;

/**
 * Журнал событий полосы или действия: структурные поля цели, окно активности
 * и граница субъекта. Действие — конкретный TraceAction (источник + действие):
 * actor и окно берутся у него. Граница субъекта — подтверждающий алиас: actor,
 * иначе адрес источника, иначе узел (host-алиас); окно — пересечение активности
 * с интервалом владения этого алиаса. null — ссылку честно построить нельзя
 * (нет подтверждающего интервала, окно непредставимо, условия длиннее лимита).
 */
export function spanEventsHref(
  origin: string,
  s: Pick<TraceSpan, "target" | "target_kind" | "dst_port" | "first" | "last" | "attached"> & { actors?: string[]; actions?: TraceAction[] },
  _bucketSec: number,
  action?: TraceAction | string,
  owner?: OwnerScope,
): string | null {
  const L = { literal: true };
  const act = typeof action === "string" ? s.actions?.find((a) => a.action === action) : action;
  const actionName = typeof action === "string" ? action : action?.action;
  const actor = (act ? act.actors : s.actors)?.[0];
  const useSrc = Boolean(origin && !s.attached);
  let q = "";
  if (actor) q = appendTerm(q, "actor", actor, L);
  if (useSrc) q = appendTerm(q, "src", origin, L);
  if (s.target) {
    if (s.target_kind === "node") q = appendTerm(q, "node", s.target, L);
    else if (s.target_kind === "dst") {
      q = appendTerm(q, "dst", s.target, L);
      if (s.dst_port) q = `${q} dport:${s.dst_port}`;
    } else if (s.target_kind === "source") q = appendTerm(q, "source", s.target, L);
    else q = appendTerm(q, "object", s.target, L);
  }
  if (act && typeof action !== "string" && s.target_kind !== "source") q = appendTerm(q, "source", act.source, L);
  if (actionName) q = appendTerm(q, "action", actionName, L);
  if (q.length > TRACE_LINK_Q_MAX) return null;
  // Окно — активность выбранного actor, а не всего действия: иначе интервал
  // владения подбирался бы под чужие события и журнал открывался пустым.
  const own = actor ? act?.actorSpan?.[actor] : undefined;
  const first = own ? own[0] : act ? act.first : s.first;
  const last = own ? own[1] : act ? act.last : s.last;
  let w: [number, number] | null = null;
  if (!owner) w = linkWindow(first, last, null);
  else {
    const anchors: ["actor" | "src" | "node", string][] = [];
    if (actor) anchors.push(["actor", actor]);
    if (useSrc) anchors.push(["src", origin]);
    if (s.target_kind === "node" && s.target) anchors.push(["node", s.target]);
    for (const [field, value] of anchors) {
      for (const iv of owner(field, value)) {
        if (iv[1] <= first || iv[0] > last) continue;
        w = linkWindow(first, last, iv);
        if (w) break;
      }
      if (w) break;
    }
  }
  return w ? `/events?q=${encodeURIComponent(q)}&${windowQuery(w)}` : null;
}

/** Журнал по адресу источника в окне ветки: значение — литерал языка поиска; все субъекты. */
export function originEventsHref(o: Pick<TraceOrigin, "origin" | "first" | "last">): string | null {
  const q = appendTerm("", "src", o.origin, { literal: true });
  if (q.length > TRACE_LINK_Q_MAX) return null;
  const w = linkWindow(o.first, o.last, null);
  return w ? `/events?q=${encodeURIComponent(q)}&${windowQuery(w)}` : null;
}
