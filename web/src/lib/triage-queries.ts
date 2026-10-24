// Данные для сессий разбора (triage-session): сущности инцидента, связанные
// инциденты, история правила. Область считается сервером при выпуске токена,
// а не агентом.
import "server-only";
import { chQuery, incidentGet, type IncidentRow } from "./argus-queries";
import {
  ANCHOR_ATTRS, isEntityKind, TRIAGE_ANCHOR_MAX_SPREAD, TRIAGE_ENTITIES_MAX, TRIAGE_ENTITY_MAX_LEN,
  TRIAGE_EVENTS_LOOKBACK_DAYS, TRIAGE_RELATED_MAX, TRIAGE_RELATED_WINDOW_DAYS, TRIAGE_SPREAD_TIMEOUT_SEC,
  relatedSummary, type RelatedSummary, type TriageBinding, type TriageEntity, type TriageRelation, type TriageScope,
} from "./shared/triage";
import { wazuhEnabled } from "./integrations";

const IP_RE = /^(?:\d{1,3}(?:\.\d{1,3}){3}|[0-9a-f:]*:[0-9a-f:.]+)$/i;
const HASH_RE = /^(?:[0-9a-f]{32}|[0-9a-f]{40}|[0-9a-f]{64})$/i;
const DOMAIN_RE = /^(?=.{4,253}$)(?:[a-z0-9_](?:[a-z0-9_-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}$/i;

export const isIp = (v: string) => IP_RE.test(v);
export const isIoc = (v: string) => IP_RE.test(v) || HASH_RE.test(v) || DOMAIN_RE.test(v);

/** Порог «частого значения»: ARGUS_TRIAGE_ANCHOR_MAX_SPREAD или 5 (README). */
export function anchorMaxSpread(): number {
  const n = Number(process.env.ARGUS_TRIAGE_ANCHOR_MAX_SPREAD);
  return Number.isInteger(n) && n > 0 ? n : TRIAGE_ANCHOR_MAX_SPREAD;
}

/** Сущности инцидента: субъект, узел и IP/IOC-атрибуты событий этого
 *  субъекта или узла в окне инцидента (±1 ч) — с видом (в каком поле
 *  якорь), и привязка строк поиска. project, namespace, job не сущности: это
 *  фильтры. Частота (entitySpread) — по всему окну поиска и
 *  обоим индексам: частое значение не якорь, частые субъект или узел самого
 *  инцидента — только в паре (weak), частый субъект не привязывает строки,
 *  если есть узел. */
export async function incidentEntities(inc: IncidentRow): Promise<{ entities: TriageEntity[]; bind: TriageBinding }> {
  const actor = inc.actor_name && inc.actor_name !== "-" ? inc.actor_name : "";
  const node = inc.node && inc.node !== "-" ? inc.node : "";
  let found: TriageEntity[] = [];
  if (actor || node) {
    const who: string[] = [];
    const params: Record<string, string | number> = { first: inc.first_ts, last: inc.last_ts, limit: TRIAGE_ENTITIES_MAX };
    if (actor) {
      who.push("actor_name = {actor:String}");
      params.actor = actor;
    }
    if (node) {
      who.push("node = {node:String}");
      params.node = node;
    }
    const pairs = [`('ip', src_ip)`, `('ip', dst_ip)`, ...ANCHOR_ATTRS.map((k) => `('attr.${k}', attrs['${k}'])`)].join(", ");
    const rows = await chQuery<{ k: string; v: string }>(
      `SELECT DISTINCT kv.1 AS k, kv.2 AS v FROM (
         SELECT arrayJoin([${pairs}]) AS kv FROM events
         WHERE ts >= parseDateTime64BestEffort({first:String}, 3, 'UTC') - INTERVAL 1 HOUR
           AND ts <= parseDateTime64BestEffort({last:String}, 3, 'UTC') + INTERVAL 1 HOUR
           AND (${who.join(" OR ")})
       ) WHERE v != '' AND length(v) <= ${TRIAGE_ENTITY_MAX_LEN} LIMIT {limit:UInt32}`,
      params,
    );
    found = rows.filter((r) => isEntityKind(r.k)).map((r): TriageEntity => ({ kind: r.k as TriageEntity["kind"], value: r.v }));
  }
  const spread = await entitySpread(inc, actor, node, [...new Set(found.map((e) => e.value))]);
  const base: TriageEntity[] = [];
  if (actor) base.push({ kind: "actor", value: actor, ...(spread.actor && { weak: true }) });
  if (node) base.push({ kind: "node", value: node, ...(spread.node && { weak: true }) });
  const entities = [...base, ...found.filter((e) => !spread.values.has(e.value))].slice(0, TRIAGE_ENTITIES_MAX);
  // Привязка строк: свой субъект и свой узел. Частый субъект (root) при
  // известном узле не привязывает: иначе открыл бы свои события на всех узлах.
  const bind: TriageBinding = { actors: actor && !(spread.actor && node) ? [actor] : [], nodes: node ? [node] : [] };
  return { entities, bind };
}

export type EntitySpread = { values: Set<string>; actor: boolean; node: boolean; timedOut: boolean };

/** Частота сущностей за всё окно поиска (first_ts − 30 дней … сейчас):
 *  значение (IP, IOC-атрибут) — в events (src/dst/attrs) и wazuh_alerts
 *  (srcip, только при включённом модуле Wazuh), больше чем у anchorMaxSpread() разных субъектов или узлов
 *  (агентов); субъект инцидента — больше чем на стольких узлах; узел — больше
 *  чем у стольких субъектов. Считается один раз при выпуске, не дольше
 *  TRIAGE_SPREAD_TIMEOUT_SEC: не уложились или ошибка — всё частое (значения
 *  не якоря, субъект и узел только в паре), сессия всё равно выдаётся. */
export async function entitySpread(inc: IncidentRow, actor: string, node: string, values: string[]): Promise<EntitySpread> {
  const all: EntitySpread = { values: new Set(values), actor: !!actor, node: !!node, timedOut: true };
  const params: Record<string, string | number> = { first: inc.first_ts, days: TRIAGE_EVENTS_LOOKBACK_DAYS, spread: anchorMaxSpread() };
  const floor = (col: string) => `${col} >= parseDateTime64BestEffort({first:String}, 3, 'UTC') - INTERVAL {days:UInt32} DAY`;
  const parts: string[] = [];
  if (values.length) {
    values.forEach((v, i) => (params[`v${i}`] = v));
    const vs = values.map((_, i) => `{v${i}:String}`).join(", ");
    const cols = ["src_ip", "dst_ip", ...ANCHOR_ATTRS.map((k) => `attrs['${k}']`)].join(", ");
    parts.push(`SELECT 'v' AS k, v, actor_name AS a, node AS n FROM events ARRAY JOIN [${cols}] AS v WHERE ${floor("ts")} AND v IN (${vs})`);
    if (wazuhEnabled()) parts.push(`SELECT 'v' AS k, srcip AS v, '' AS a, agent_name AS n FROM wazuh_alerts WHERE ${floor("timestamp")} AND srcip IN (${vs})`);
  }
  if (actor) {
    params.actor = actor;
    parts.push(`SELECT 'actor' AS k, actor_name AS v, '' AS a, node AS n FROM events WHERE ${floor("ts")} AND actor_name = {actor:String}`);
  }
  if (node) {
    params.node = node;
    parts.push(`SELECT 'node' AS k, node AS v, actor_name AS a, '' AS n FROM events WHERE ${floor("ts")} AND node = {node:String}`);
  }
  if (parts.length === 0) return { values: new Set(), actor: false, node: false, timedOut: false };
  const sql = `SELECT k, v FROM (${parts.join("\n UNION ALL ")})
     GROUP BY k, v
     HAVING uniqExactIf(a, a NOT IN ('', '-')) > {spread:UInt32} OR uniqExactIf(n, n NOT IN ('', '-')) > {spread:UInt32}`;
  let timer: ReturnType<typeof setTimeout> | undefined;
  const deadline = new Promise<never>((_, reject) => {
    timer = setTimeout(() => reject(new Error("timeout")), TRIAGE_SPREAD_TIMEOUT_SEC * 1000 + 2000);
  });
  try {
    const rows = await Promise.race([
      chQuery<{ k: string; v: string }>(sql, params, { max_execution_time: TRIAGE_SPREAD_TIMEOUT_SEC, timeout_overflow_mode: "throw" }),
      deadline,
    ]);
    return {
      values: new Set(rows.filter((r) => r.k === "v").map((r) => r.v)),
      actor: rows.some((r) => r.k === "actor"),
      node: rows.some((r) => r.k === "node"),
      timedOut: false,
    };
  } catch (err) {
    console.error("triage entity spread (якоря отключены):", err instanceof Error ? err.message : err);
    return all;
  } finally {
    clearTimeout(timer);
  }
}

/** Шаблон re2 для IP в тексте цепочки с границами токена: 10.0.0.1 не
 *  находит 10.0.0.15 и 110.0.0.1. */
export function ipTokenPattern(ip: string): string {
  const esc = ip.replace(/[.]/g, "\\.");
  return ip.includes(":") ? `(^|[^0-9A-Fa-f:])${esc}([^0-9A-Fa-f:]|$)` : `(^|[^0-9.])${esc}([^0-9]|$)`;
}

/** Связанные инциденты: общий субъект, узел или IOC в окне ±7 дней, до 20.
 *  Порядок важности связи: субъект, узел, IP, домен/хеш. */
export async function relatedIncidents(inc: IncidentRow, entities: TriageEntity[]): Promise<Record<string, TriageRelation>> {
  const params: Record<string, string | number> = { id: inc.incident_id, first: inc.first_ts, last: inc.last_ts, days: TRIAGE_RELATED_WINDOW_DAYS, limit: TRIAGE_RELATED_MAX };
  const list = (prefix: string, values: string[]) => {
    values.forEach((v, i) => (params[`${prefix}${i}`] = v));
    return `[${values.map((_, i) => `{${prefix}${i}:String}`).join(", ")}]`;
  };
  const ips = [...new Set(entities.filter((e) => e.kind === "ip" && isIp(e.value)).map((e) => e.value))];
  const others = [...new Set(entities.filter((e) => e.kind.startsWith("attr.") && isIoc(e.value) && !isIp(e.value)).map((e) => e.value))];
  const cases: [string, TriageRelation][] = [];
  if (inc.actor_name) {
    params.actor = inc.actor_name;
    cases.push(["actor_name = {actor:String}", "same_subject"]);
  }
  if (inc.node) {
    params.node = inc.node;
    cases.push(["node = {node:String}", "same_node"]);
  }
  if (ips.length) {
    const arr = list("ip", ips);
    // В цепочке — по границам токена, не подстрокой: 10.0.0.1 ≠ 10.0.0.15.
    const re = list("ipre", ips.map(ipTokenPattern));
    cases.push([`has(${arr}, actor_name) OR has(${arr}, node) OR arrayExists(c -> multiMatchAny(c, ${re}), chain)`, "same_remote_ip"]);
  }
  if (others.length) {
    cases.push([`arrayExists(c -> multiSearchAnyCaseInsensitive(c, ${list("ioc", others)}), chain)`, "same_ioc"]);
  }
  if (cases.length === 0) return {};
  const relation = `multiIf(${cases.map(([c, r]) => `${c}, '${r}'`).join(", ")}, '')`;
  const rows = await chQuery<{ incident_id: string; relation: TriageRelation }>(
    `SELECT incident_id, ${relation} AS relation FROM incidents_current
     WHERE incident_id != {id:String}
       AND last_ts >= parseDateTime64BestEffort({first:String}, 3, 'UTC') - INTERVAL {days:UInt32} DAY
       AND first_ts <= parseDateTime64BestEffort({last:String}, 3, 'UTC') + INTERVAL {days:UInt32} DAY
       AND relation != ''
     ORDER BY indexOf(['same_subject', 'same_node', 'same_remote_ip', 'same_ioc'], relation), created_at DESC, incident_id
     LIMIT {limit:UInt32}`,
    params,
  );
  return Object.fromEntries(rows.map((r) => [r.incident_id, r.relation]));
}

/** Начало окна поиска событий: first_ts − 30 дней (ISO, UTC). */
export function searchFloor(inc: IncidentRow): string {
  const first = Date.parse(inc.first_ts.replace(" ", "T") + (/[zZ+]/.test(inc.first_ts) ? "" : "Z"));
  const base = Number.isFinite(first) ? first : Date.now();
  return new Date(base - TRIAGE_EVENTS_LOOKBACK_DAYS * 86_400_000).toISOString();
}

/** Всё, что нужно для выпуска токена: сущности, привязка, связанные, начало окна. */
export async function triageScopeFor(inc: IncidentRow): Promise<{ related: Record<string, TriageRelation>; entities: TriageEntity[]; bind: TriageBinding; searchFrom: string }> {
  const { entities, bind } = await incidentEntities(inc);
  const related = await relatedIncidents(inc, entities);
  return { related, entities, bind, searchFrom: searchFloor(inc) };
}

/** Минимальная сводка связанных инцидентов сессии. */
export async function relatedSummaries(scope: TriageScope): Promise<RelatedSummary[]> {
  const ids = Object.keys(scope.related);
  if (ids.length === 0) return [];
  const params = Object.fromEntries(ids.map((id, i) => [`id${i}`, id]));
  const rows = await chQuery<Record<string, unknown>>(
    `SELECT incident_id, level, rule_id, rule_title, status, toString(first_ts) AS first_ts, toString(last_ts) AS last_ts,
            toString(created_at) AS created_at
     FROM incidents_current WHERE incident_id IN (${ids.map((_, i) => `{id${i}:String}`).join(", ")})`,
    params,
  );
  const byId = new Map(rows.map((r) => [String(r.incident_id), r]));
  return ids.filter((id) => byId.has(id)).map((id) => relatedSummary(byId.get(id)!, scope.related[id]));
}

export type RuleHistory = { window_days: number; total: number; by_status: Record<string, number>; last_false_positive_at: string | null };

/** История правила за 90 дней — только счётчики, без чужих инцидентов. */
export async function ruleHistory(ruleId: string, excludeId: string): Promise<RuleHistory> {
  const rows = await chQuery<{ status: string; c: string | number; last_at: string }>(
    `SELECT status, count() AS c, toString(max(updated_at)) AS last_at FROM incidents_current
     WHERE rule_id = {rule:String} AND incident_id != {id:String} AND created_at >= now() - INTERVAL 90 DAY
     GROUP BY status`,
    { rule: ruleId, id: excludeId },
  );
  const by_status: Record<string, number> = {};
  let total = 0;
  let lastFp: string | null = null;
  for (const r of rows) {
    const n = Number(r.c);
    by_status[r.status] = n;
    total += n;
    if (r.status === "false_positive") lastFp = r.last_at;
  }
  return { window_days: 90, total, by_status, last_false_positive_at: lastFp };
}

export { incidentGet };
