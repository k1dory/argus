// Область чтения токена triage-session: агент разбора
// читает только свой инцидент, связанные — минимальной сводкой, события —
// только вокруг сущностей своего инцидента. Ограничение живёт на сервере,
// клиент (MCP-агент) его лишь дублирует. Чистые функции — без БД и Next.
import { parseQuery, type Term } from "./search-query";
import { RANGES, type RangeKey } from "./ranges";

/** Срок жизни токена: не больше часа (время одной задачи разбора). */
export const TRIAGE_TTL_MAX_SEC = 60 * 60;
/** Связанные инциденты: окно ±7 дней от инцидента, не больше 20. */
export const TRIAGE_RELATED_WINDOW_DAYS = 7;
export const TRIAGE_RELATED_MAX = 20;
/** Сущности инцидента (субъект, узел, IOC из его событий) — потолок для токена. */
export const TRIAGE_ENTITIES_MAX = 48;
export const TRIAGE_ENTITY_MAX_LEN = 128;
/** Окно поиска событий: от first_ts − 30 дней до «сейчас». */
export const TRIAGE_EVENTS_LOOKBACK_DAYS = 30;
/** Строк поиска на запрос не больше 200: 4 страницы по 50. */
export const TRIAGE_MAX_ROWS = 200;
/** Условий в одном запросе поиска. */
export const TRIAGE_MAX_TERMS = 8;
/** Запросов к API за сессию по умолчанию (ARGUS_TRIAGE_SESSION_REQUESTS). */
export const TRIAGE_SESSION_REQUESTS = 100;
/** Частое значение не якорь: встречается больше чем у стольких разных
 *  субъектов или узлов за всё окно поиска, от first_ts − 30 дней до выпуска,
 *  в events и wazuh_alerts (ARGUS_TRIAGE_ANCHOR_MAX_SPREAD, см. README). */
export const TRIAGE_ANCHOR_MAX_SPREAD = 5;
/** Потолок подсчёта частоты при выпуске сессии, с: не уложился — значения
 *  не якоря, субъект и узел — только в паре (отказ безопасный, не 503). */
export const TRIAGE_SPREAD_TIMEOUT_SEC = 10;

/** Атрибуты событий, значения которых — якоря: IOC и идентификаторы секрета. */
export const ANCHOR_ATTRS = ["domain", "hash", "md5", "sha1", "sha256", "token_id", "secret_id"] as const;
/** Атрибуты-фильтры: сужают выборку рядом с якорем, но сами не якорь — одно
 *  значение у всех событий проекта или кластера. */
export const FILTER_ATTRS = ["project", "namespace", "job"] as const;

/** Вид сущности инцидента — в каком поле поиска она якорь: субъект — в actor,
 *  узел — в node/agent, IP — только в src/dst/srcip, атрибут — в своём attr.*. */
export type TriageEntityKind = "actor" | "node" | "ip" | `attr.${(typeof ANCHOR_ATTRS)[number]}`;
/** weak — частый субъект или узел самого инцидента (root, общий сервер):
 *  якорь только в паре с сущностью другого вида. */
export type TriageEntity = { kind: TriageEntityKind; value: string; weak?: boolean };

/** Обязательная привязка строк поиска (серверный SQL-предикат): строки
 *  только своего субъекта или своих узлов (events), только своих агентов
 *  (alerts). Пусто — поиск ничего не вернёт. */
export type TriageBinding = { actors: string[]; nodes: string[] };

export function isEntityKind(k: unknown): k is TriageEntityKind {
  return k === "actor" || k === "node" || k === "ip" || (typeof k === "string" && k.startsWith("attr.") && (ANCHOR_ATTRS as readonly string[]).includes(k.slice(5)));
}

/** Тип общей сущности со связанным инцидентом — те же имена, что в схеме
 *  вердикта (triage-verdict.schema.json, related[].relation), плюс
 *  same_ioc — общий домен или хеш. */
export type TriageRelation = "same_subject" | "same_node" | "same_remote_ip" | "same_ioc";
export const TRIAGE_RELATIONS: readonly TriageRelation[] = ["same_subject", "same_node", "same_remote_ip", "same_ioc"];

export type TriageScope = {
  /** id сессии (jti): журнал, лимит запросов, отзыв. */
  sessionId: string;
  incidentId: string;
  /** Связанные инциденты и тип связи — посчитаны сервером при выпуске. */
  related: Record<string, TriageRelation>;
  /** Сущности инцидента: субъект, узел, IP/домены/хеши из его событий — с
   *  видом, частые значения (общая инфраструктура) исключены при выпуске. */
  entities: TriageEntity[];
  /** Привязка строк — предикат в каждом запросе поиска сессии. */
  bind: TriageBinding;
  /** Начало окна поиска событий (ISO, UTC) — first_ts − 30 дней. */
  searchFrom: string;
  expiresAt: string;
};

export type IncidentAccess = "own" | "related" | "out_of_scope";

export function incidentAccess(scope: TriageScope, id: string): IncidentAccess {
  if (id === scope.incidentId) return "own";
  if (Object.hasOwn(scope.related, id)) return "related";
  return "out_of_scope";
}

/** Поля минимальной сводки связанного инцидента: без субъекта, узла,
 *  заметки, комментариев и цепочки. */
export const RELATED_FIELDS = ["incident_id", "level", "rule_id", "rule_title", "status", "first_ts", "last_ts", "created_at"] as const;
export type RelatedSummary = { [K in (typeof RELATED_FIELDS)[number]]: string } & { relation: TriageRelation };

export function relatedSummary(row: Record<string, unknown>, relation: TriageRelation): RelatedSummary {
  const out = { relation } as RelatedSummary;
  for (const f of RELATED_FIELDS) out[f] = String(row[f] ?? "");
  return out;
}

/** Поля-фильтры без сущностей: значение любое, но якорем не служат. */
const FILTER_FIELDS: Record<"alerts" | "events", readonly string[]> = {
  events: ["source", "class", "action", "outcome", "dport", "sport", "proto", "severity", ...FILTER_ATTRS.map((a) => `attr.${a}`)],
  alerts: ["rule", "level", "group", "decoder"],
};

/** Вид сущности поля: undefined — поле недоступно, null — фильтр без
 *  сущности. Поле-сущность принимает только значения своего вида из
 *  области — каждый терм, а не хотя бы один: иначе рядом
 *  с якорем actor:"<догадка>" или attr.password:"<догадка>" по total
 *  подтверждали бы исходные данные. */
export function fieldEntityKind(index: "alerts" | "events", field: string): TriageEntityKind | null | undefined {
  if (FILTER_FIELDS[index].includes(field)) return null;
  if (index === "alerts") return field === "agent" ? "node" : field === "srcip" ? "ip" : undefined;
  if (field === "actor" || field === "node") return field;
  if (field === "src" || field === "dst") return "ip";
  return isEntityKind(field) ? field : undefined;
}

/** Сущность области: точное совпадение, без приведения регистра — SQL
 *  сравнивает так же (OwnBot и ownbot — разные субъекты). */
export function findEntity(scope: TriageScope, kind: TriageEntityKind, value: string): TriageEntity | undefined {
  return value === "" ? undefined : scope.entities.find((e) => e.kind === kind && e.value === value);
}

export type TriageSearchRequest = {
  index: "alerts" | "events";
  q: string;
  range: RangeKey;
  from?: string;
  to?: string;
  page: number;
  pageSize: number;
};

export type TriageSearchCheck =
  | { ok: true; from: string; to?: string }
  | { ok: false; status: 400 | 403; error: "out_of_scope" | "invalid_value" | "missing_filter"; detail: string };

const DT_RE = /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}(:\d{2})?$/;
const toMinute = (ms: number) => new Date(ms).toISOString().slice(0, 16);

/** Проверка поиска для токена triage-session. Возвращает границы окна, уже
 *  урезанные до разрешённого: from не раньше first_ts − 30 дней. */
export function checkTriageSearch(scope: TriageScope, req: TriageSearchRequest, now = Date.now()): TriageSearchCheck {
  const bad = (status: 400 | 403, error: "out_of_scope" | "invalid_value" | "missing_filter", detail: string): TriageSearchCheck => ({ ok: false, status, error, detail });
  if (req.page * req.pageSize > TRIAGE_MAX_ROWS) return bad(403, "out_of_scope", `не больше ${TRIAGE_MAX_ROWS} строк на запрос`);
  const terms: Term[] = parseQuery(req.q);
  if (terms.length === 0) return bad(400, "missing_filter", "нужен фильтр по сущности инцидента");
  if (terms.length > TRIAGE_MAX_TERMS) return bad(400, "invalid_value", `не больше ${TRIAGE_MAX_TERMS} условий`);
  const anchors: TriageEntity[] = [];
  for (const t of terms) {
    if (t.negate || t.op !== "=") return bad(400, "invalid_value", "отрицание и сравнения недоступны");
    if (t.mask || t.starInQuotes || (!t.quoted && t.value.includes("*"))) return bad(400, "invalid_value", "маски недоступны");
    // Свободный текст ищет подстроку по всей записи, включая raw: total и
    // наличие строк стали бы оракулом по нередактированным данным. Как и
    // triage/filter.QueryStrict — только равенство по полям (домен — attr.domain).
    if (t.field === null) return bad(400, "invalid_value", "свободный текст недоступен — только поля");
    const kind = fieldEntityKind(req.index, t.field);
    if (kind === undefined) return bad(400, "invalid_value", `поле ${t.field} недоступно`);
    if (kind === null) continue;
    const e = findEntity(scope, kind, t.value);
    if (!e) return bad(403, "out_of_scope", `${t.field}: значение не из сущностей инцидента`);
    anchors.push(e);
  }
  if (anchors.length === 0) return bad(403, "out_of_scope", "нужна хотя бы одна сущность инцидента (actor, node, src/dst, attr.domain …)");
  // Частый субъект или узел (root, общий сервер) — только в паре с сущностью другого вида.
  if (anchors.every((e) => e.weak) && new Set(anchors.map((e) => e.kind)).size < 2) {
    return bad(403, "out_of_scope", "частый субъект или узел — только вместе с другой сущностью инцидента (actor + node, src/dst …)");
  }

  const floor = Date.parse(scope.searchFrom);
  let fromMs: number;
  let toMs: number | undefined;
  if (req.from) {
    if (!DT_RE.test(req.from) || !Number.isFinite(Date.parse(req.from + "Z"))) return bad(400, "invalid_value", "from");
    fromMs = Date.parse(req.from + "Z");
    if (req.to) {
      if (!DT_RE.test(req.to) || !Number.isFinite(Date.parse(req.to + "Z"))) return bad(400, "invalid_value", "to");
      toMs = Date.parse(req.to + "Z");
      if (toMs < fromMs) [fromMs, toMs] = [toMs, fromMs];
    }
  } else {
    fromMs = now - RANGES[req.range].hours * 3600_000;
  }
  if (toMs !== undefined && toMs < floor) return bad(403, "out_of_scope", "окно поиска раньше first_ts − 30 дней");
  fromMs = Math.max(fromMs, floor);
  return { ok: true, from: toMinute(fromMs), ...(toMs !== undefined && { to: toMinute(Math.min(toMs, now)) }) };
}

/** Колонки строк, которых агент не получает никогда (исходный JSON). */
export const TRIAGE_HIDDEN_COLUMNS = ["raw", "full_log"] as const;

export function stripHidden(rows: Record<string, unknown>[]): Record<string, unknown>[] {
  return rows.map((r) => {
    const out = { ...r };
    for (const c of TRIAGE_HIDDEN_COLUMNS) delete out[c];
    return out;
  });
}
