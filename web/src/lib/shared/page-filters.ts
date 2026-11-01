// Диапазонные фильтры каждой страницы консоли: какие параметры она понимает,
// как они разбираются (lib/shared/filters), какие поля у формы и что писать
// в пустом списке. Один файл — чтобы имена параметров не расходились.
import {
  ALERT_LEVEL_SPEC, COUNT_SPEC, CVSS_SPEC, describeChips, EVENT_SEVERITY_SPEC, getParam, INCIDENT_LEVELS, numberField, numChip,
  ordinalChip, ordinalField, parseNumRange, parseOrdinalRange, parseTimeFilter, PERCENT_SPEC, timeChip, VULN_SEVERITIES,
  type FilterChip, type NumRange, type OrdinalRange, type RangeField, type SearchParamsLike, type TimeFilter,
} from "./filters";
import { INCIDENT_LEVEL_LABELS, VULN_SEVERITY_LABELS } from "./labels";
import type { RangeKey } from "./ranges";

/** Параметры окна времени (общие для всех страниц). */
export const TIME_KEYS = ["range", "period", "from", "to"] as const;

const chipsText = (chips: (FilterChip | null)[]): string => describeChips(chips);

/** Чип окна, только если оно отличается от окна страницы по умолчанию. */
function windowChip(t: TimeFilter, label: string, def: RangeKey): FilterChip | null {
  return !t.from && !t.to && t.range === def ? null : timeChip(t, label);
}

/** Подстрока строки запроса только с заданными ключами — для скрытых полей форм. */
export function pickParams(sp: SearchParamsLike, keys: readonly string[]): string {
  const out = new URLSearchParams();
  for (const k of keys) {
    const v = getParam(sp, k);
    if (v !== undefined) out.set(k, v);
  }
  return out.toString();
}

/* ===== Инциденты ===== */

export const INCIDENT_RANGE_KEYS = [...TIME_KEYS, "level_min", "level_max", "events_min", "events_max"] as const;
export type IncidentRanges = { time: TimeFilter; level: OrdinalRange; events: NumRange };

/** Прежний level=<значение> (точный уровень) живёт отдельно — его разбирают страница и API, как раньше. */
export function parseIncidentRanges(sp: SearchParamsLike, now = Date.now()): IncidentRanges {
  return {
    time: parseTimeFilter(sp, {}, now),
    level: parseOrdinalRange(sp, "level", INCIDENT_LEVELS),
    events: parseNumRange(sp, "events", COUNT_SPEC),
  };
}

export const isEmptyIncidentRanges = (r: IncidentRanges): boolean =>
  !r.time.range && !r.time.from && !r.level.min && !r.level.max && r.events.min === undefined && r.events.max === undefined;

export function incidentRangeChips(r: IncidentRanges): FilterChip[] {
  return [
    timeChip(r.time, "начало"),
    ordinalChip("level", "уровень", r.level, INCIDENT_LEVEL_LABELS),
    numChip("events", "событий", r.events),
  ].filter((c): c is FilterChip => c !== null);
}

export const INCIDENT_RANGE_FIELDS: RangeField[] = [
  ordinalField("level", "Уровень", INCIDENT_LEVELS, INCIDENT_LEVEL_LABELS),
  numberField("events", "Событий в цепочке", COUNT_SPEC),
];

/* ===== Алерты Wazuh (журнал, агенты, MITRE) ===== */

export const ALERT_RANGE_KEYS = [...TIME_KEYS, "level_min", "level_max", "level"] as const;
export type AlertRanges = { time: TimeFilter; level: NumRange };

/** level=N — прежний порог «не ниже N»: читается как level_min. */
export function parseAlertRanges(sp: SearchParamsLike, now = Date.now(), defaultRange: RangeKey = "24h"): AlertRanges {
  const legacy = getParam(sp, "level");
  const src = legacy && !getParam(sp, "level_min") && !getParam(sp, "level_max")
    ? new URLSearchParams({ level_min: legacy })
    : sp;
  return {
    time: parseTimeFilter(sp, { defaultRange }, now),
    level: parseNumRange(src, "level", ALERT_LEVEL_SPEC),
  };
}

export const ALERT_LEVEL_FIELD: RangeField = numberField("level", "Уровень правила", ALERT_LEVEL_SPEC);

export function alertRangeChips(r: AlertRanges): FilterChip[] {
  return [windowChip(r.time, "интервал", "24h"), numChip("level", "уровень", r.level)].filter((c): c is FilterChip => c !== null);
}

export type AgentRanges = AlertRanges & { alerts: NumRange; critical: NumRange };

export function parseAgentRanges(sp: SearchParamsLike, now = Date.now()): AgentRanges {
  return { ...parseAlertRanges(sp, now), alerts: parseNumRange(sp, "alerts", COUNT_SPEC), critical: parseNumRange(sp, "critical", COUNT_SPEC) };
}

export const AGENT_RANGE_FIELDS: RangeField[] = [
  ALERT_LEVEL_FIELD,
  numberField("alerts", "Алертов", COUNT_SPEC),
  numberField("critical", "Критичных", COUNT_SPEC),
];

export function agentRangeChips(r: AgentRanges): FilterChip[] {
  return [...alertRangeChips(r), numChip("alerts", "алертов", r.alerts), numChip("critical", "критичных", r.critical)].filter((c): c is FilterChip => c !== null);
}

/* ===== Уязвимости ===== */

export type VulnRanges = { time: TimeFilter; severity: OrdinalRange; cvss: NumRange };

/** Окно витрины CVE — 30 дней по умолчанию; точный интервал не шире 30 дней (как была витрина). */
export const VULN_MAX_DAYS = 30;

export function parseVulnRanges(sp: SearchParamsLike, now = Date.now()): VulnRanges {
  return {
    time: parseTimeFilter(sp, { defaultRange: "30d", maxDays: VULN_MAX_DAYS }, now),
    severity: parseOrdinalRange(sp, "level", VULN_SEVERITIES),
    cvss: parseNumRange(sp, "cvss", CVSS_SPEC),
  };
}

export const VULN_RANGE_FIELDS: RangeField[] = [
  ordinalField("level", "Серьёзность", VULN_SEVERITIES, VULN_SEVERITY_LABELS),
  numberField("cvss", "CVSS", { ...CVSS_SPEC, step: 0.1 }),
];

export function vulnRangeChips(r: VulnRanges): FilterChip[] {
  return [
    windowChip(r.time, "обнаружено", "30d"),
    ordinalChip("level", "серьёзность", r.severity, VULN_SEVERITY_LABELS),
    numChip("cvss", "CVSS", r.cvss, (n) => n.toFixed(1)),
  ].filter((c): c is FilterChip => c !== null);
}

/* ===== Поиск и журнал событий ===== */

/** Порог уровня по индексу поиска: alerts — rule_level 0..15, events — severity 0..10. */
export function parseSearchLevel(sp: SearchParamsLike, index: "alerts" | "events"): NumRange {
  return parseNumRange(sp, "level", index === "alerts" ? ALERT_LEVEL_SPEC : EVENT_SEVERITY_SPEC);
}

export const searchLevelField = (index: "alerts" | "events"): RangeField =>
  numberField("level", index === "alerts" ? "Уровень правила" : "Серьёзность", index === "alerts" ? ALERT_LEVEL_SPEC : EVENT_SEVERITY_SPEC);

/* ===== Источники ===== */

export type SourceRanges = { time: TimeFilter; severity: NumRange; seen: TimeFilter; events: NumRange; eps: NumRange };

/** Окно ленты «Источников» — 24 часа по умолчанию (как было), не шире 30 дней. */
export function parseSourceRanges(sp: SearchParamsLike, now = Date.now()): SourceRanges {
  return {
    time: parseTimeFilter(sp, { defaultRange: "24h", maxDays: 30 }, now),
    severity: parseNumRange(sp, "level", EVENT_SEVERITY_SPEC),
    seen: parseTimeFilter(sp, { prefix: "seen" }, now),
    events: parseNumRange(sp, "events", COUNT_SPEC),
    eps: parseNumRange(sp, "eps", { min: 0, max: 1_000_000 }),
  };
}

export const SOURCE_HEALTH_FIELDS: RangeField[] = [
  { key: "seen", label: "Последний приём", kind: "datetime" },
  numberField("events", "Событий за час", COUNT_SPEC),
  numberField("eps", "EPS/60 с", { min: 0, max: 1_000_000, step: 0.1 }),
];
export const SOURCE_FEED_FIELDS: RangeField[] = [numberField("level", "Серьёзность", EVENT_SEVERITY_SPEC)];

export function sourceHealthChips(r: SourceRanges): FilterChip[] {
  return [timeChip(r.seen, "последний приём"), numChip("events", "событий за час", r.events), numChip("eps", "EPS", r.eps)].filter((c): c is FilterChip => c !== null);
}
export function sourceFeedChips(r: SourceRanges): FilterChip[] {
  return [windowChip(r.time, "поступило", "24h"), numChip("level", "серьёзность", r.severity)].filter((c): c is FilterChip => c !== null);
}

/* ===== Субъекты ===== */

export type ActorRanges = { time: TimeFilter; events: NumRange; incidents: NumRange };

/** Окно паспорта не шире 30 дней (ACTOR_WINDOW_MAX_MS); пресеты — ActorRangeLinks. */
export function parseActorRanges(sp: SearchParamsLike, now = Date.now()): ActorRanges {
  return {
    time: parseTimeFilter(sp, { ranges: ["24h", "7d", "30d"], maxDays: 30 }, now),
    events: parseNumRange(sp, "events", COUNT_SPEC),
    incidents: parseNumRange(sp, "incidents", COUNT_SPEC),
  };
}

export const ACTOR_RANGE_FIELDS: RangeField[] = [numberField("events", "Событий", COUNT_SPEC), numberField("incidents", "Инцидентов", COUNT_SPEC)];

export function actorRangeChips(r: ActorRanges): FilterChip[] {
  return [timeChip(r.time, "интервал", true), numChip("events", "событий", r.events), numChip("incidents", "инцидентов", r.incidents)].filter((c): c is FilterChip => c !== null);
}

/* ===== Правила корреляции ===== */

export type RuleRanges = { level: OrdinalRange; incidents: NumRange; fp: NumRange };

export function parseRuleRanges(sp: SearchParamsLike): RuleRanges {
  return {
    level: parseOrdinalRange(sp, "level", INCIDENT_LEVELS),
    incidents: parseNumRange(sp, "incidents", COUNT_SPEC),
    fp: parseNumRange(sp, "fp", PERCENT_SPEC),
  };
}

export const RULE_RANGE_FIELDS: RangeField[] = [
  ordinalField("level", "Уровень", INCIDENT_LEVELS, INCIDENT_LEVEL_LABELS),
  numberField("incidents", "Инцидентов за 30 д", COUNT_SPEC),
  numberField("fp", "Ложных", { ...PERCENT_SPEC, unit: "%" }),
];

export function ruleRangeChips(r: RuleRanges): FilterChip[] {
  return [
    ordinalChip("level", "уровень", r.level, INCIDENT_LEVEL_LABELS),
    numChip("incidents", "инцидентов", r.incidents),
    numChip("fp", "ложных, %", r.fp),
  ].filter((c): c is FilterChip => c !== null);
}

/** «по фильтрам: уровень ≥ высокий, период 7 дней» — для пустых списков. */
export function filtersSuffix(chips: (FilterChip | null)[]): string {
  const s = chipsText(chips);
  return s ? ` по фильтрам: ${s}` : "";
}
