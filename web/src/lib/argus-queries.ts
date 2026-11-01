// Запросы ARGUS-контура: единая схема событий, инциденты, вердикты аналитика,
// здоровье коллекторов. ReplacingMergeTree читаем через argMax по updated_at.
import "server-only";
import { isAlive, RHYTHM_QUANTILE, RHYTHM_WINDOW_DAYS, silenceThresholdSec } from "./shared/source-health";
import crypto from "node:crypto";
import { clampInt, clampPage } from "./shared/limits";
import { chCommand, chQuery as chQueryRaw, ClickHouseError } from "./clickhouse";

/** Серверные лимиты на все запросы консоли к ClickHouse: пользователь консоли
 *  без квот, а скан за 30 дней — полный. Тот же набор, что в search.ts. */
export const CH_LIMITS = { max_execution_time: 20, max_memory_usage: 2_000_000_000 } as const;
export const chQuery = <T,>(sql: string, params: Record<string, string | number> = {}, settings: Record<string, string | number> = {}): Promise<T[]> =>
  chQueryRaw<T>(sql, params, { ...CH_LIMITS, ...settings });

const ENGINE_TIMEOUT_MS = 30_000;
const engineBase = (): string => (process.env.ENGINE_URL ?? "http://localhost:8090").replace(/\/$/, "");

/** Ошибка движка: пользователю — коротко, полный текст — в лог сервера. */
function engineError(scope: string, err: unknown): string {
  console.error(`${scope}:`, err instanceof Error ? err.message : err);
  return "движок недоступен";
}
export { INCIDENT_STATUSES, EXCEPTION_FIELDS, isIncidentStatus, type IncidentStatus } from "./shared/incidents";
import { isIncidentStatus, type IncidentStatus } from "./shared/incidents";
import type { ClosureLabel } from "./shared/closure-label";
import { addrSQL, blockState, GROUP_ROWS_PAGE, GROUPS_PAGE, isSubnetKey, levelOfRank, SCAN_GROUP_RULES, subnetSQL, type BlockRow, type BlockState } from "./shared/scan-groups";
import { AGENT_VERDICT_SESSION_ORDER } from "./shared/triage-verdict";
import { INCIDENT_LEVELS, numConditions, ordinalConditions, timeCondition, type NumRange, type TimeFilter } from "./shared/filters";
import type { IncidentRanges } from "./shared/page-filters";


export type IncidentRow = {
  incident_id: string;
  created_at: string;
  updated_at: string;
  updated_max?: string;
  rule_id: string;
  rule_title: string;
  level: string;
  tags: string[];
  status: IncidentStatus;
  owner: string;
  note: string;
  actor_name: string;
  node: string;
  sources: string[];
  event_count: number;
  first_ts: string;
  last_ts: string;
  pii: number;
  chain: string[];
  enrichment: string[];
  similar: string[];
};

const LATEST = `SELECT * FROM incidents_current`;

export type IncidentFilter = {
  status?: string; level?: string; q?: string; page?: number; pageSize?: number; queue?: "open" | "mine" | "unassigned" | "overdue"; user?: string; groupScans?: boolean;
  /** Диапазоны (lib/shared/page-filters): окно по first_ts, уровень не ниже/не выше, число событий. */
  ranges?: Partial<IncidentRanges>;
};

/** Условия очереди (поиск, статус, уровень, очередь) — общие для списка и групп сканов. */
function incidentConditions(filter: IncidentFilter, params: Record<string, string | number>): string[] {
  const having: string[] = [];
  if (filter.q) {
    having.push(`(positionCaseInsensitiveUTF8(concat(incident_id, ' ', rule_title, ' ', rule_id, ' ', actor_name, ' ', node, ' ', arrayStringConcat(sources, ' ')), {q:String}) > 0)`);
    params.q = filter.q;
  }
  if (isIncidentStatus(filter.status)) {
    having.push("status = {status:String}");
    params.status = filter.status;
  }
  if (filter.level) {
    having.push("level = {level:String}");
    params.level = filter.level;
  }
  // incidents_current — представление над ReplacingMergeTree с ключом incident_id:
  // ни партиций, ни ключа по времени у него нет, условие окна — по агрегированной строке.
  const r = filter.ranges;
  if (r?.time) having.push(...timeCondition("first_ts", r.time, params, "inc_t"));
  if (r?.level) having.push(...ordinalConditions("level", r.level, INCIDENT_LEVELS, params, "inc_lvl"));
  if (r?.events) having.push(...numConditions("event_count", r.events, params, "inc_ev", "UInt64"));
  if (filter.queue === "open") {
    having.push("status NOT IN ('closed', 'false_positive')");
  } else if (filter.queue === "mine") {
    if (!filter.user) throw new Error("Не указан пользователь очереди");
    having.push("owner = {user:String} AND status NOT IN ('closed', 'false_positive')");
    params.user = filter.user;
  } else if (filter.queue === "unassigned") {
    having.push("owner = '' AND status NOT IN ('closed', 'false_positive')");
  } else if (filter.queue === "overdue") {
    // Срок первичной реакции: только ещё не взятые в работу инциденты.
    having.push("status = 'new' AND dateDiff('second', created_at, now()) > multiIf(level = 'critical', 900, level = 'high', 3600, level = 'medium', 14400, 86400)");
  }
  return having;
}

/** Открытый инцидент сканов снаружи с адресом источника — попадает в группу подсети. */
const SCAN_GROUPED = `(rule_id IN {scan_rules:Array(String)} AND status NOT IN ('closed', 'false_positive') AND ${subnetSQL("actor_name")} != '')`;
const scanRulesParam = (): string => `[${SCAN_GROUP_RULES.map((r) => `'${r}'`).join(",")}]`;

export async function incidentsList(
  filter: IncidentFilter = {},
): Promise<{ rows: IncidentRow[]; total: number; page: number; pageSize: number }> {
  const pageSize = clampInt(filter.pageSize, 10, 200, 50);
  let page = clampPage(filter.page);
  const params: Record<string, string | number> = { limit: pageSize, offset: (page - 1) * pageSize };
  const having = incidentConditions(filter, params);
  if (filter.groupScans) {
    // Сканы снаружи показаны группами по подсети (scanGroups) — в очереди их нет.
    having.push(`NOT ${SCAN_GROUPED}`);
    params.scan_rules = scanRulesParam();
  }
  const where = having.length ? "WHERE " + having.join(" AND ") : "";
  const listSQL = `${LATEST} ${where} ORDER BY created_at DESC, incident_id DESC LIMIT {limit:UInt32} OFFSET {offset:UInt32}`;
  const [initialRows, cnt] = await Promise.all([
    chQuery<IncidentRow>(
      listSQL,
      params,
    ),
    chQuery<{ c: string }>(`SELECT count() AS c FROM (${LATEST} ${where})`, params),
  ]);
  const total = Number(cnt[0]?.c ?? 0);
  const lastPage = Math.max(1, Math.ceil(total / pageSize));
  let rows = initialRows;
  if (page > lastPage) {
    page = lastPage;
    rows = total > 0 ? await chQuery<IncidentRow>(listSQL, { ...params, offset: (page - 1) * pageSize }) : [];
  }
  return { rows: rows.map(normalizeIncident), total, page, pageSize };
}

export type ScanGroup = {
  subnet: string; incidents: number; addresses: number; rules: string[];
  first_ts: string; last_ts: string; level: string; unassigned: number;
};

/**
 * Открытые инциденты сканов снаружи (SCAN_GROUP_RULES) по подсети источника под
 * теми же условиями очереди: свёрнутая строка «подсеть: N адресов». Подсеть
 * считается в запросе (subnetSQL) — инциденты и движок не меняются.
 */
export async function scanGroups(filter: IncidentFilter = {}, limit: number = GROUPS_PAGE): Promise<ScanGroup[]> {
  const size = clampInt(limit, 1, 500, GROUPS_PAGE);
  const params: Record<string, string | number> = { scan_rules: scanRulesParam(), limit: size, offset: (clampPage(filter.page) - 1) * size };
  const having = [SCAN_GROUPED, ...incidentConditions(filter, params)];
  const rows = await chQuery<ScanGroup & { level_rank: number | string; incidents: number | string; addresses: number | string; unassigned: number | string }>(
    // Агрегаты под своими именами и переименование снаружи: псевдоним first_ts над
    // min(first_ts) в том же SELECT перекрыл бы колонку внутри агрегата (184).
    `SELECT subnet, incidents, addresses, rules, toString(f) AS first_ts, toString(l) AS last_ts, level_rank, unassigned FROM (
       SELECT ${subnetSQL("actor_name")} AS subnet, count() AS incidents, uniqExact(${addrSQL("actor_name")}) AS addresses,
              arraySort(groupUniqArray(rule_id)) AS rules, min(first_ts) AS f, max(last_ts) AS l,
              max(multiIf(level = 'critical', 4, level = 'high', 3, level = 'medium', 2, 1)) AS level_rank,
              countIf(owner = '') AS unassigned
       FROM (${LATEST} WHERE ${having.join(" AND ")})
       GROUP BY subnet)
     ORDER BY l DESC, subnet LIMIT {limit:UInt32} OFFSET {offset:UInt32}`,
    params,
  );
  return rows.map((r) => ({
    subnet: r.subnet, incidents: Number(r.incidents), addresses: Number(r.addresses), rules: r.rules,
    first_ts: r.first_ts, last_ts: r.last_ts, level: levelOfRank(Number(r.level_rank)), unassigned: Number(r.unassigned),
  }));
}

function groupConditions(subnet: string, filter: IncidentFilter, params: Record<string, string | number>): string[] {
  params.scan_rules = scanRulesParam();
  params.subnet = subnet;
  return [SCAN_GROUPED, `${subnetSQL("actor_name")} = {subnet:String}`, ...incidentConditions(filter, params)];
}

/** Инциденты одной подсети группы сканов как есть, свежие сверху, страницами по 500. */
export async function scanGroupIncidents(subnet: string, filter: IncidentFilter = {}, limit: number = GROUP_ROWS_PAGE): Promise<IncidentRow[]> {
  if (!isSubnetKey(subnet)) return [];
  const size = clampInt(limit, 1, GROUP_ROWS_PAGE + 1, GROUP_ROWS_PAGE);
  const params: Record<string, string | number> = { limit: size, offset: (clampPage(filter.page) - 1) * GROUP_ROWS_PAGE };
  const having = groupConditions(subnet, filter, params);
  const rows = await chQuery<IncidentRow>(
    `${LATEST} WHERE ${having.join(" AND ")} ORDER BY last_ts DESC, incident_id DESC LIMIT {limit:UInt32} OFFSET {offset:UInt32}`,
    params,
  );
  return rows.map(normalizeIncident);
}

/**
 * Статус блока каждого инцидента — по его последней записи response_log (при равном
 * ts запись исполнителя главнее служебной). Ожидание пишется без адреса — тоже в
 * счёт. Блок по адресу общий для инцидентов (респондер хранит активные блоки по IP):
 * если после блока или «уже заблокирован» этот адрес успешно сняли из любого
 * инцидента — блок снят.
 */
export async function incidentBlockStates(ids: string[]): Promise<Record<string, BlockState>> {
  if (ids.length === 0) return {};
  const lit = (xs: string[]) => `[${xs.map((x) => `'${x.replace(/\\/g, "\\\\").replace(/'/g, "\\'")}'`).join(",")}]`;
  const rows = await chQuery<BlockRow & { incident_id: string; ip: string; at: string }>(
    `SELECT incident_id, argMax(executor, (ts, by_exec)) AS executor, argMax(mode, (ts, by_exec)) AS mode,
            argMax(dry_run, (ts, by_exec)) AS dry_run, argMax(ok, (ts, by_exec)) AS ok, argMax(detail, (ts, by_exec)) AS detail,
            argMax(ip, (ts, by_exec)) AS ip, toString(max(ts)) AS at
     FROM (SELECT incident_id, executor, mode, dry_run, ok, detail, ip, ts, executor != 'argus' AS by_exec
           FROM response_log WHERE incident_id IN {ids:Array(String)})
     GROUP BY incident_id`,
    { ids: lit(ids) },
  );
  const out: Record<string, BlockState> = {};
  for (const r of rows) out[r.incident_id] = blockState({ ...r, dry_run: Number(r.dry_run), ok: Number(r.ok) });
  const blocked = rows.filter((r) => (out[r.incident_id] === "blocked" || out[r.incident_id] === "unblock_failed") && r.ip !== "");
  if (blocked.length > 0) {
    const released = await chQuery<{ ip: string; at: string }>(
      `SELECT ip, toString(max(ts)) AS at FROM response_log
       WHERE ip IN {ips:Array(String)} AND endsWith(executor, '.unblock') AND ok = 1 GROUP BY ip`,
      { ips: lit([...new Set(blocked.map((r) => r.ip))]) },
    );
    const at = new Map(released.map((x) => [x.ip, x.at]));
    for (const r of blocked) {
      const u = at.get(r.ip);
      if (u && u > r.at) out[r.incident_id] = "released";
    }
  }
  return out;
}

export async function incidentGet(id: string): Promise<IncidentRow | null> {
  const rows = await chQuery<IncidentRow>(
    `${LATEST} WHERE incident_id = {id:String}`,
    { id },
  );
  return rows[0] ? normalizeIncident(rows[0]) : null;
}

function normalizeIncident(r: IncidentRow): IncidentRow {
  return { ...r, event_count: Number(r.event_count), pii: Number(r.pii) };
}

export class IncidentWorkflowError extends Error {}

export async function incidentTransition(input: {
  id: string; kind: "take" | "assign" | "status"; status?: IncidentStatus; owner?: string; reason?: string; actor: string; role: "viewer" | "analyst" | "admin";
  /** Ответ человека — только при завершении; движок отклонит переход без него. */
  label?: ClosureLabel;
}): Promise<void> {
  // id — в пути, не в теле: движок разбирает тело с DisallowUnknownFields
  // (workflowRequest: actor, role, kind, status, owner, reason, label), и лишнее поле
  // превращало каждое «Взять», «Назначить» и смену статуса в 400.
  const { id, ...body } = input;
  const r = await fetch(`${engineBase()}/incidents/${encodeURIComponent(id)}/workflow`, {
    method: "POST", cache: "no-store", headers: engineHeaders(), signal: AbortSignal.timeout(ENGINE_TIMEOUT_MS),
    body: JSON.stringify(body),
  });
  if (!r.ok) {
    const body = await r.json().catch(() => ({})) as { error?: string };
    if (r.status === 400 || r.status === 404 || r.status === 409) throw new IncidentWorkflowError(body.error || "Переход отклонён");
    throw new Error(`engine workflow: ${r.status}`);
  }
}

export type IncidentComment = {
  comment_id: string;
  incident_id: string;
  created_at: string;
  author: string;
  body: string;
};

export async function incidentComments(id: string, limit = 200): Promise<IncidentComment[]> {
  const rows = await chQuery<IncidentComment>(
    `SELECT comment_id, incident_id, created_at, author, body
     FROM incident_comments WHERE incident_id = {id:String}
     ORDER BY created_at DESC, comment_id DESC LIMIT 1 BY comment_id LIMIT {limit:UInt32}`,
    { id, limit: Math.min(10_000, Math.max(1, Math.floor(limit))) },
  );
  return rows.reverse();
}

/** Комментарий с заданным comment_id (идемпотентная запись агента) или с новым UUID. */
export async function addIncidentComment(id: string, author: string, body: string, opts: { commentId?: string } = {}): Promise<void> {
  // JSONEachRow экранирует переводы строк Markdown: String query-параметр
  // ClickHouse отклоняет сырые многострочные значения.
  const row = {
    comment_id: opts.commentId ?? crypto.randomUUID(), incident_id: id,
    created_at: new Date().toISOString().replace("T", " ").replace("Z", ""),
    author, body,
  };
  // Токен дедупликации — страховка от двойной вставки при повторе с тем же
  // comment_id (действует, если у таблицы включено окно дедупликации); дубли
  // по comment_id в любом случае схлопываются при чтении (incidentComments).
  const settings: Record<string, string | number> = opts.commentId ? { insert_deduplicate: 1, insert_deduplication_token: `comment:${opts.commentId}` } : {};
  await chCommand(`INSERT INTO incident_comments FORMAT JSONEachRow\n${JSON.stringify(row)}`, {}, settings);
}

/** Есть ли комментарий с таким comment_id у инцидента (повтор записи агента). */
export async function incidentCommentExists(id: string, commentId: string): Promise<boolean> {
  const rows = await chQuery<{ c: string | number }>(
    `SELECT count() AS c FROM incident_comments WHERE incident_id = {id:String} AND comment_id = {cid:UUID}`,
    { id, cid: commentId },
  );
  return Number(rows[0]?.c ?? 0) > 0;
}


export type IncidentStateEvent = {
  event_id: string;
  revision: number;
  changed_at: string;
  actor: string;
  kind: string;
  status: IncidentStatus;
  owner: string;
  reason: string;
  /** Метка ответа (миграции 0033, 0036); у переходов без завершения и у автоматики пустая. */
  disposition: string;
  escalate: boolean | null;
  severity_level: number | null;
  severity_correct: boolean | null;
  attack_tactic: string;
  attack_technique: string;
  attack_version: string;
  ops_cause: string;
  ops_act_now: boolean | null;
  ops_urgency: number | null;
  ops_action: string;
  blind: boolean;
  labeled_by_human: boolean;
};

export async function incidentStateHistory(id: string, limit = 200): Promise<IncidentStateEvent[]> {
  const rows = await chQuery<IncidentStateEvent>(
    `SELECT event_id, revision, changed_at, actor, kind, status, owner, reason,
            disposition, escalate, severity_level, severity_correct, attack_tactic, attack_technique, attack_version,
            ops_cause, ops_act_now, ops_urgency, ops_action, blind, labeled_by_human
     FROM incident_state_events WHERE incident_id = {id:String}
     ORDER BY revision DESC LIMIT {limit:UInt32}`, { id, limit: Math.min(10_000, Math.max(1, Math.floor(limit))) },
  );
  return rows.reverse().map((row) => ({ ...row, revision: Number(row.revision) }));
}

/** Метка ответа человека для выгрузки (обучение, доля ложных срабатываний правила). */
export type { LabelCursor } from "./label-cursor";
import type { LabelCursor } from "./label-cursor";

export type IncidentLabelRow = {
  event_id: string; incident_id: string; changed_at: string; actor: string; status: IncidentStatus;
  disposition: string; escalate: boolean | null; severity_level: number | null; severity_correct: boolean | null;
  attack_tactic: string; attack_technique: string; attack_version: string;
  ops_cause: string; ops_act_now: boolean | null; ops_urgency: number | null; ops_action: string; blind: boolean; reason: string;
  rule_id: string; rule_title: string; level: string; tags: string[];
};

/** Ответы людей при завершении с `since` (включительно), по (changed_at, incident_id, event_id);
 *  after — строго после этой позиции (продолжение выгрузки). Только
 *  labeled_by_human: автозакрытия (kind auto_close) пишут тот же статус closed и
 *  без этого фильтра выдавались бы за ответ человека. Повторное завершение
 *  одного инцидента — отдельная строка (переоткрытия в консоли нет, но журнал
 *  append-only). Правило, уровень и теги — последняя версия инцидента.
 *  max_result_rows консоли — 20000 (MAX 100000): порция до limit поднимает его на запрос. */
/** since → граница миллисекундной точности и признак ненулевого остатка мельче мс. */
function sinceBound(since: string): { since: string; since_sub_ms: number } {
  const frac = /\.(\d+)/.exec(since)?.[1] ?? "";
  return { since: since.replace(/\.(\d{1,3})\d*/, ".$1"), since_sub_ms: /[1-9]/.test(frac.slice(3)) ? 1 : 0 };
}

export async function incidentLabels(since: string, limit: number, after?: LabelCursor): Promise<IncidentLabelRow[]> {
  return chQuery<IncidentLabelRow>(
    `WITH labels AS (
       SELECT event_id, incident_id, changed_at, actor, status, disposition, escalate,
              severity_level, severity_correct, attack_tactic, attack_technique, attack_version,
              ops_cause, ops_act_now, ops_urgency, ops_action, blind, reason
       FROM incident_state_events
       WHERE labeled_by_human AND kind = 'status' AND status IN ('closed', 'false_positive')
         -- changed_at — DateTime64(3). Доли мельче миллисекунды в since не округляются
         -- вниз: при ненулевом остатке граница строгая. Точность 9 не годится — её
         -- диапазон кончается в 2262 году, а since проверен лишь как дата ISO.
         AND (changed_at > parseDateTime64BestEffort({since:String}, 3, 'UTC')
              OR (NOT {since_sub_ms:UInt8} AND changed_at = parseDateTime64BestEffort({since:String}, 3, 'UTC')))
         AND (changed_at, incident_id, toString(event_id))
             > (parseDateTime64BestEffort({after_ts:String}, 3, 'UTC'), {after_inc:String}, {after_id:String})
       ORDER BY changed_at, incident_id, toString(event_id) LIMIT {limit:UInt32}
     )
     SELECT l.*, i.rule_id, i.rule_title, i.level, i.tags
     FROM labels AS l
     LEFT JOIN (
       SELECT incident_id, argMax(rule_id, updated_at) AS rule_id, argMax(rule_title, updated_at) AS rule_title,
              argMax(level, updated_at) AS level, argMax(tags, updated_at) AS tags
       FROM incidents WHERE incident_id IN (SELECT incident_id FROM labels) GROUP BY incident_id
     ) AS i USING incident_id
     ORDER BY l.changed_at, l.incident_id, toString(l.event_id)`,
    { ...sinceBound(since), limit, after_ts: after?.changedAt ?? "1970-01-01 00:00:00.000", after_inc: after?.incidentId ?? "", after_id: after?.eventId ?? "" },
    { max_result_rows: Math.max(limit, 1) },
  );
}

export type IncidentClosure = { incident_id: string; actor: string; kind: string; changed_at: string; reason: string };

export async function incidentClosuresFor(ids: string[]): Promise<Record<string, IncidentClosure>> {
  if (!ids.length) return {};
  const placeholders = ids.map((_, i) => `{closure${i}:String}`).join(", ");
  const params = Object.fromEntries(ids.map((id, i) => [`closure${i}`, id]));
  const rows = await chQuery<IncidentClosure>(
    `SELECT incident_id, argMax(actor, revision) AS actor, argMax(kind, revision) AS kind,
            argMax(changed_at, revision) AS changed_at, argMax(reason, revision) AS reason
     FROM incident_state_events
     WHERE incident_id IN (${placeholders}) AND status IN ('closed', 'false_positive')
     GROUP BY incident_id`, params,
  );
  return Object.fromEntries(rows.map((row) => [row.incident_id, row]));
}

export async function incidentFirstResponse(id: string): Promise<string | null> {
	const rows = await chQuery<{ responded_at: string }>(
		`SELECT toString(min(changed_at)) AS responded_at
		 FROM incident_state_events WHERE incident_id = {id:String} AND kind = 'take'
		 GROUP BY incident_id`, { id },
	);
	return rows[0]?.responded_at ?? null;
}

export type VerdictRow = {
  missing?: string;
  actions?: string[];
  decision_json?: string;
  confidence_kind?: string;
  shown_reason?: string;
  incident_id: string;
  evaluated_at: string;
  profile: string;
  model: string;
  summary_ru: string;
  evidence: string[];
  first_action: string;
  confidence: number;
  shown: number;
  tokens: number;
  latency_ms: number;
  error: string;
};

export async function verdictGet(id: string): Promise<VerdictRow | null> {
  const rows = await chQuery<VerdictRow>(
    `SELECT * FROM incident_verdicts WHERE incident_id = {id:String}
     ORDER BY evaluated_at DESC LIMIT 1`,
    { id },
  );
  if (!rows[0]) return null;
  return { ...rows[0], confidence: Number(rows[0].confidence), shown: Number(rows[0].shown) };
}

export async function verdictsFor(ids: string[]): Promise<Record<string, VerdictRow>> {
  if (ids.length === 0) return {};
  // Отдельный String-параметр на каждый ID: значение параметра ClickHouse
  // не принимает сырые переводы строк, поэтому список в одной строке ломал ленту.
  const params = Object.fromEntries(ids.map((id, i) => [`id${i}`, id]));
  const placeholders = ids.map((_, i) => `{id${i}:String}`).join(", ");
  const rows = await chQuery<VerdictRow>(
    `SELECT incident_id, argMax(summary_ru, evaluated_at) AS summary_ru, argMax(shown, evaluated_at) AS shown,
            argMax(confidence, evaluated_at) AS confidence, argMax(profile, evaluated_at) AS profile,
            argMax(model, evaluated_at) AS model, argMax(error, evaluated_at) AS error,
            max(evaluated_at) AS evaluated_max, argMax(first_action, evaluated_at) AS first_action,
            argMax(evidence, evaluated_at) AS evidence, argMax(tokens, evaluated_at) AS tokens,
            argMax(latency_ms, evaluated_at) AS latency_ms
     FROM incident_verdicts WHERE incident_id IN (${placeholders}) GROUP BY incident_id`,
    params,
  );
  const out: Record<string, VerdictRow> = {};
  for (const r of rows) {
    const rr = r as VerdictRow & { evaluated_max?: string };
    out[r.incident_id] = { ...r, evaluated_at: rr.evaluated_max ?? r.evaluated_at, confidence: Number(r.confidence), shown: Number(r.shown) };
  }
  return out;
}

export type IncidentStats = { total: number; open: number; escalated: number; pii: number };

export async function incidentStats(): Promise<IncidentStats> {
  const [r] = await chQuery<{ total: string; open: string; escalated: string; pii: string }>(
    `SELECT count() AS total,
            countIf(status NOT IN ('closed','false_positive')) AS open,
            countIf(status = 'escalated') AS escalated,
            countIf(pii = 1) AS pii
     FROM (${LATEST})`,
  );
  return { total: Number(r?.total ?? 0), open: Number(r?.open ?? 0), escalated: Number(r?.escalated ?? 0), pii: Number(r?.pii ?? 0) };
}

/* ===== Источники ===== */

export type SourceHealth = {
  source: string;
  source_class: string;
  events_1h: number;
  eps_60s: number;
  last_ts: string;
  pii_share: number;
  alive: number;
  /** Событий за окно ритма (RHYTHM_WINDOW_DAYS) по heartbeat коллектора; источник мимо коллектора — за час. */
  events_window: number;
  /** Ритм: типичный разрыв между пачками событий, с (взвешенный по длительности квантиль RHYTHM_QUANTILE); null — мало данных. */
  rhythm_sec: number | null;
  /** Порог тишины для этого источника, с (max(5 мин, 3 × ритм)). */
  silence_threshold_sec: number;
  /** Секунд с последнего события на момент запроса. */
  silent_for_sec: number;
};

/** Сколько замолчавших источников (тише часа) показывать; остальные — счётчиком omitted. */
export const STALE_SOURCES_LIMIT = 2000;

export type SourcesReport = {
  sources: SourceHealth[];
  /** Замолчавших источников сверх STALE_SOURCES_LIMIT (самые давно молчащие), в sources не вошли. */
  omitted: number;
};

/** Условие запросов к p_source_last: все активные парты events уже с проекцией.
 *  force_optimize_projection этого не гарантирует — пока MATERIALIZE идёт, оптимизатор
 *  берёт проекцию из новых партов и сырые строки из старых, и запрос сканирует историю.
 *  Скалярный подзапрос к system.parts (строка на парт) вычисляется до выбора партов: не
 *  готово — WHERE 0, проекция не применяется, force_optimize_projection даёт
 *  PROJECTION_NOT_USED без чтения events. Пустые парты (rows = 0) не считаются: DELETE
 *  оставляет активный парт без строк и без файлов проекции, сканировать в нём нечего,
 *  а без этого исключения список молчащих источников пропадал до ближайшего слияния. */
const SOURCE_LAST_READY = `(SELECT count() FROM system.parts
         WHERE database = currentDatabase() AND table = 'events' AND active AND rows > 0
           AND NOT has(projections, 'p_source_last')) = 0`;
const PROJECTION_NOT_USED = 584;

/** Ритм по журналу heartbeat (collector_health_log) — единственное место расчёта, тесты гоняют его на живом ClickHouse.
 *  Разрывы между соседними активными минутами (минутами с событиями) за окно; самый длинный разрыв отбрасывается —
 *  одиночный сбой или простой не растягивает ритм непрерывного источника на месяц; квантиль RHYTHM_QUANTILE
 *  взвешен длительностью разрыва: это доля времени, а не доля разрывов. Поэтому у пачечного источника (CI 15 минут
 *  раз в сутки: 14 разрывов по минуте и один суточный) ритм — сутки, а не минута, как у квантиля по числу разрывов.
 *  Меньше двух разрывов — 0 (мало данных). */
const RHYTHM_GAPS = `arrayPopBack(arraySort(arrayMap(x -> toUInt64(x), arraySlice(arrayDifference(arraySort(groupArrayIf(toUnixTimestamp(seen_at), events_1m > 0))), 2))))`;

export async function sourcesHealthReport(): Promise<SourcesReport> {
  // Счётчики «за час», доля ПДн и класс — по таблице событий за последний час
  // (minmax-индекс по received_at). Ритм — по журналу heartbeat коллектора
  // collector_health_log (строка на источник в минуту, ORDER BY (source, seen_at)):
  // квантиль считается в ClickHouse, массивы минут в консоль не едут.
  // Замолчавшие источники — по агрегатной проекции events p_source_last (миграция
  // 0031: строка на источник в каждом парте), поэтому в списке остаются и те, кто
  // пишет в events мимо коллектора и heartbeat не имеет (телеметрия движка
  // argus.system): упавший движок виден как «молчит», а не пропадает через час.
  // Скан сырых events за окно здесь недопустим — сотни миллионов строк на каждую
  // загрузку. Пока проекция есть не во всех партах (миграция идёт), запрос не читает
  // events (SOURCE_LAST_READY) и список строится по heartbeat, как в rc27. Прочие ошибки
  // не маскируются пустым результатом: маршрут отвечает 503.
  type Num = number | string; // ClickHouse JSON: UInt32/Float64 приходят числами, count() — строкой
  type Hour = { source: string; source_class: string; events_1h: Num; eps_60s: Num; last_ts: string; last_sec: Num; pii_share: Num | null; now_sec: Num };
  type Rhythm = { source: string; events_window: Num; gap_q: Num | null; last_sec: Num; now_sec: Num };
  type Stale = { source: string; source_class: string; last_ts: string; last_sec: Num; stale_total: Num; now_sec?: Num };
  const days = RHYTHM_WINDOW_DAYS;
  const [hour, rhythm, staleRows] = await Promise.all([
    chQuery<Hour>(
      `SELECT source, any(source_class) AS source_class, count() AS events_1h,
              countIf(received_at >= now() - INTERVAL 60 SECOND) AS eps_60s,
              max(received_at) AS last_ts, toUnixTimestamp(max(received_at)) AS last_sec,
              round(100 * avg(pii), 1) AS pii_share, toUnixTimestamp(now()) AS now_sec
       FROM events WHERE received_at >= now() - INTERVAL 1 HOUR
       GROUP BY source ORDER BY events_1h DESC, source`,
    ),
    chQuery<Rhythm>(
      `SELECT source, events_window, arrayReduce('quantileExactWeighted({q:Float64})', gaps, gaps) AS gap_q, last_sec, now_sec
       FROM (
         SELECT source, sum(events_1m) AS events_window, ${RHYTHM_GAPS} AS gaps,
                toUnixTimestamp(maxIf(seen_at, events_1m > 0)) AS last_sec, toUnixTimestamp(now()) AS now_sec
         FROM collector_health_log WHERE seen_at >= now() - INTERVAL {days:UInt32} DAY
         GROUP BY source HAVING countIf(events_1m > 0) > 0
       )`,
      { q: RHYTHM_QUANTILE, days },
    ),
    chQuery<Stale>(
      `SELECT source, any(source_class) AS source_class, max(received_at) AS last_ts,
              toUnixTimestamp(max(received_at)) AS last_sec, count() OVER () AS stale_total, toUnixTimestamp(now()) AS now_sec
       FROM events WHERE ${SOURCE_LAST_READY} GROUP BY source
       HAVING last_ts >= now() - INTERVAL {days:UInt32} DAY AND last_ts < now() - INTERVAL 1 HOUR
       ORDER BY last_ts DESC, source LIMIT {lim:UInt32}
       SETTINGS force_optimize_projection = 1`,
      { days, lim: STALE_SOURCES_LIMIT },
    ).catch((err: unknown) => {
      if (!(err instanceof ClickHouseError) || err.code !== PROJECTION_NOT_USED) throw err;
      console.error("sourcesHealth: проекция p_source_last ещё не во всех партах, замолчавшие — по heartbeat");
      return null;
    }),
  ]);
  const byHour = new Map(hour.map((r) => [r.source, r]));
  const byRhythm = new Map(rhythm.map((r) => [r.source, r]));
  // Замолчавшие — объединение двух множеств: проекция (все писатели events) и
  // источники с heartbeat, у которых нет событий за час. Итог и omitted считаются по
  // уникальному объединению ДО обрезки выдачи, иначе на пределе:
  //  - heartbeat-only старше границы списка пропадал из счёта;
  //  - источник за LIMIT проекции с heartbeat считался дважды (в stale_total и как heartbeat).
  // Имена за LIMIT проекция не вернула; heartbeat-кандидатов, которых нет среди её строк,
  // проверяем той же проекцией точечно (source IN — ключ агрегатной проекции, полного
  // скана нет): найденные уже сосчитаны в stale_total, ненайденные — heartbeat-only.
  // Без проекции (миграция идёт) — только heartbeat, как в rc27. Отказ этого запроса
  // пробрасывается: без него неизвестно, кто из кандидатов уже в stale_total, и
  // omitted был бы выдуман.
  const proj = (staleRows ?? []).filter((r) => !byHour.has(r.source));
  const projDropped = (staleRows ?? []).length - proj.length; // замолчали час назад и уже снова пишут
  const projTotal = staleRows ? Math.max(0, Number(staleRows[0]?.stale_total ?? 0) - projDropped) : 0;
  const projTruncated = staleRows !== null && Number(staleRows[0]?.stale_total ?? 0) > staleRows.length;
  const inProj = new Set((staleRows ?? []).map((r) => r.source));
  const hbStale = rhythm.filter((r) => !byHour.has(r.source) && !inProj.has(r.source));
  let beyondLimit: Stale[] = [];
  if (projTruncated && hbStale.length > 0) {
    type Named = Omit<Stale, "stale_total">;
    beyondLimit = (await chQuery<Named>(
      `SELECT source, any(source_class) AS source_class, max(received_at) AS last_ts,
              toUnixTimestamp(max(received_at)) AS last_sec, toUnixTimestamp(now()) AS now_sec
       FROM events WHERE source IN {names:Array(String)} AND ${SOURCE_LAST_READY} GROUP BY source
       HAVING last_ts >= now() - INTERVAL {days:UInt32} DAY AND last_ts < now() - INTERVAL 1 HOUR
       SETTINGS force_optimize_projection = 1`,
      // Array(String) параметром — литерал массива (как ids в actors.ts).
      { names: `[${hbStale.map((r) => `'${r.source.replace(/\\/g, "\\\\").replace(/'/g, "\\'")}'`).join(",")}]`, days },
    )).map((r) => ({ ...r, stale_total: 0 }));
  }
  const inBeyond = new Set(beyondLimit.map((r) => r.source));
  const heartbeatOnly: Stale[] = hbStale
    .filter((r) => !inBeyond.has(r.source))
    .map((r) => ({
      source: r.source, source_class: "", last_sec: r.last_sec, stale_total: 0,
      last_ts: new Date(Number(r.last_sec) * 1000).toISOString().slice(0, 19).replace("T", " "),
    }));
  // Порядок детерминирован: от недавно замолчавших к давним, при равенстве — по имени.
  const candidates = [...proj, ...beyondLimit, ...heartbeatOnly]
    .sort((x, y) => Number(y.last_sec) - Number(x.last_sec) || x.source.localeCompare(y.source));
  const staleShown = candidates.slice(0, STALE_SOURCES_LIMIT);
  // Объединение: проекция целиком (stale_total, включая имена за LIMIT) + heartbeat-only.
  const unionTotal = Math.max(projTotal, proj.length + beyondLimit.length) + heartbeatOnly.length;
  const omitted = Math.max(0, unionTotal - staleShown.length);
  const byStale = new Map(staleShown.map((r) => [r.source, r]));
  // «Сейчас» — по часам ClickHouse, как last_sec: часы Node на другой машине (или в
  // контейнере) могут расходиться с базой, и silent_for_sec сдвинулся бы на разницу.
  // Date.now() — только если ни один запрос не вернул строк (тогда и источников нет).
  const chNow = [hour[0]?.now_sec, rhythm[0]?.now_sec, staleRows?.[0]?.now_sec, beyondLimit[0]?.now_sec]
    .map((v) => Number(v)).find((v) => Number.isFinite(v) && v > 0);
  const sources = [...hour.map((r) => r.source), ...staleShown.map((r) => r.source)].map((source) => {
    const h = byHour.get(source), rh = byRhythm.get(source), st = byStale.get(source);
    const now = Number(h?.now_sec ?? rh?.now_sec ?? st?.now_sec ?? chNow ?? Math.floor(Date.now() / 1000));
    // Последнее событие: таблица событий точнее heartbeat (минутная гранулярность).
    const last = Number(h?.last_sec ?? st?.last_sec ?? rh?.last_sec ?? now);
    const lastTs = h?.last_ts ?? st?.last_ts ?? "";
    // Меньше двух разрывов — квантиль пустого массива (0/nan/null): ритм неизвестен.
    const gapQ = rh?.gap_q == null ? NaN : Number(rh.gap_q);
    const rhythmSec = Number.isFinite(gapQ) && gapQ > 0 ? Math.max(60, gapQ) : null;
    const threshold = silenceThresholdSec(rhythmSec);
    return {
      source, source_class: h?.source_class ?? st?.source_class ?? "", last_ts: lastTs,
      events_1h: Number(h?.events_1h ?? 0), eps_60s: Number(h?.eps_60s ?? 0), pii_share: Number(h?.pii_share) || 0,
      events_window: Number(rh?.events_window ?? h?.events_1h ?? 0), rhythm_sec: rhythmSec, silence_threshold_sec: threshold,
      silent_for_sec: Math.max(0, now - last), alive: isAlive(now, last, threshold) ? 1 : 0,
    };
  });
  return { sources, omitted };
}

/** Только список (страница и тесты, которым не нужен счётчик omitted). */
export async function sourcesHealth(): Promise<SourceHealth[]> {
  return (await sourcesHealthReport()).sources;
}

export type EventRow = {
  ts: string;
  received_at: string;
  source: string;
  action: string;
  outcome: string;
  severity: number;
  actor_name: string;
  object: string;
  node: string;
  src_ip: string;
  dst_ip: string;
  dst_port: number;
  pii: number;
};

/** Лента «Источников»: окно по received_at (minmax-индекс idx_received_at, 0028) и порог серьёзности. */
export type RecentFilters = { time?: TimeFilter; severity?: NumRange };

export async function eventsRecent(source?: string, limit = 60, f: RecentFilters = {}): Promise<EventRow[]> {
  const params: Record<string, string | number> = { limit };
  const conds = timeCondition("received_at", f.time ?? { range: "24h" }, params, "rcv");
  if (source) {
    conds.push("source = {source:String}");
    params.source = source;
  }
  if (f.severity) conds.push(...numConditions("severity", f.severity, params, "sev", "UInt8"));
  const where = conds.join(" AND ");
  return chQuery<EventRow>(
    `SELECT ts, received_at, source, action, outcome, severity, actor_name, object, node, src_ip, dst_ip, dst_port, pii
     FROM events WHERE ${where} ORDER BY received_at DESC, ts DESC LIMIT {limit:UInt32}`,
    params,
  );
}

/* ===== Правила движка (HTTP engine) ===== */

export type EngineRule = {
  ID: string;
  Title: string;
  Level: string;
  File: string;
  Tags: string[];
  Threshold: boolean;
  Profile: string;
};

/** Заголовки запросов к движку: все ручки, кроме /healthz, требуют X-Argus-Token. */
const engineAuth = (): Record<string, string> =>
  process.env.ENGINE_TOKEN ? { "X-Argus-Token": process.env.ENGINE_TOKEN } : {};
const engineHeaders = (): Record<string, string> => ({ "Content-Type": "application/json", ...engineAuth() });

export async function engineRules(): Promise<{ rules: EngineRule[]; health: Record<string, unknown> | null; error: string | null }> {
  const base = engineBase();
  try {
    const [r, h] = await Promise.all([
      fetch(base + "/rules", { cache: "no-store", headers: engineAuth(), signal: AbortSignal.timeout(ENGINE_TIMEOUT_MS) }),
      fetch(base + "/healthz", { cache: "no-store", signal: AbortSignal.timeout(ENGINE_TIMEOUT_MS) }),
    ]);
    if (!r.ok) throw new Error(`engine ${r.status}`);
    return { rules: (await r.json()) as EngineRule[], health: h.ok ? await h.json() : null, error: null };
  } catch (err) {
    return { rules: [], health: null, error: engineError("engine.rules", err) };
  }
}

/* ===== Обзор SIEM: события по классам источников ===== */

export type ClassCount = { source_class: string; count: number; sources: number };

export async function eventsByClass(hours: number): Promise<ClassCount[]> {
  const rows = await chQuery<{ source_class: string; cnt: string; sources: string }>(
    `SELECT source_class, count() AS cnt, uniqExact(source) AS sources
     FROM events WHERE received_at >= now() - INTERVAL {hours:UInt32} HOUR
     GROUP BY source_class ORDER BY cnt DESC`,
    { hours },
  );
  return rows.map((r) => ({ source_class: r.source_class, count: Number(r.cnt), sources: Number(r.sources) }));
}


/* ===== Исключения из правил (обратная связь «ложное срабатывание») ===== */


export type ExceptionRow = {
  rule_id: string;
  field: string;
  value: string;
  reason: string;
  incident_id: string;
  created_by: string;
  created_at: string;
};

export async function addException(x: Omit<ExceptionRow, "created_at">): Promise<void> {
  await chCommand(
    `INSERT INTO rule_exceptions (rule_id, field, value, reason, incident_id, created_by, active)
     SELECT {rule:String}, {field:String}, {value:String}, {reason:String}, {inc:String}, {by:String}, 1`,
    { rule: x.rule_id, field: x.field, value: x.value, reason: x.reason, inc: x.incident_id, by: x.created_by },
  );
}

export async function deactivateException(ruleId: string, field: string, value: string, by: string): Promise<void> {
  await chCommand(
    `INSERT INTO rule_exceptions (rule_id, field, value, reason, incident_id, created_by, active)
     SELECT {rule:String}, {field:String}, {value:String}, 'снято', '', {by:String}, 0`,
    { rule: ruleId, field, value, by },
  );
}

export async function listExceptions(): Promise<ExceptionRow[]> {
  // max(created_at) нельзя назвать created_at — алиас попадает внутрь argMax
  const rows = await chQuery<ExceptionRow & { created_max: string }>(
    `SELECT rule_id, field, value, argMax(reason, created_at) AS reason, argMax(incident_id, created_at) AS incident_id,
            argMax(created_by, created_at) AS created_by, max(created_at) AS created_max
     FROM rule_exceptions GROUP BY rule_id, field, value HAVING argMax(active, created_at) = 1
     ORDER BY created_max DESC LIMIT 200`,
  );
  return rows.map((r) => ({ ...r, created_at: r.created_max }));
}

/* ===== Журнал действий оператора ===== */

/** Запись в журнал действий. strict — ошибка записи прерывает действие
 *  (для переключений вроде включения IPS, которые без аудита недопустимы). */
export async function audit(user: string, action: string, target: string, detail = "", opts: { strict?: boolean } = {}): Promise<void> {
  try {
    await chCommand(
      `INSERT INTO console_audit (user, action, target, detail)
       SELECT {user:String}, {action:String}, {target:String}, {detail:String}`,
      { user, action, target, detail: detail.slice(0, 2000) },
    );
  } catch (err) {
    console.error("audit:", err instanceof Error ? err.message : err);
    if (opts.strict) throw new Error("журнал действий недоступен — действие отменено");
  }
}

/* ===== Отзыв сессий разбора (triage-session) ===== */

/** Записать отзыв: без записи сессию не отзываем — иначе после рестарта
 *  консоли токен снова действовал бы. */
export async function saveTriageRevocation(sessionId: string, incidentId: string, expiresAt: string): Promise<void> {
  await chCommand(
    `INSERT INTO triage_session_revocations (session_id, incident_id, expires_at)
     SELECT {sid:String}, {inc:String}, parseDateTimeBestEffort({exp:String})`,
    { sid: sessionId, inc: incidentId, exp: expiresAt },
  );
}

/* ===== Отметки вердиктов разбора и вердикты агента ===== */

// Победитель определяется не порядком видимости строк и не now64(3), а
// дедупликацией вставки ClickHouse: claim по (incident_id, epoch) пишется с
// insert_deduplication_token, и сервер при добавлении куска проверяет токен под
// блокировкой таблицы — вторая вставка с тем же токеном молча отбрасывается.
// Это атомарное «создать, если нет» между любыми процессами; победитель
// неизменяем. epoch — поколение инцидента: число строк reopened в журнале
// (не время: now64(3) бывает равным у двух снятий или меньшим после отката
// часов, а счётчик строк только растёт — журнал без TTL и удалений). После
// снятия отметки человеком токен новый, claim возможен снова.

export type TriageVerdictState = "reopened";

/** Журнал triage_verdicts: сейчас пишет только снятие отметки человеком
 *  (reopened). Отметки принятых вердиктов живут в triage_verdict_claims_v2. */
export async function saveTriageVerdict(input: { incidentId: string; state: TriageVerdictState; sessionId: string; actor: string }): Promise<void> {
  await chCommand(
    `INSERT INTO triage_verdicts (incident_id, state, session_id, actor, updated_at)
     VALUES ({inc:String}, {state:String}, {sid:String}, {actor:String}, now64(3))`,
    { inc: input.incidentId, state: input.state, sid: input.sessionId, actor: input.actor },
  );
}

/** Поколение инцидента: число reopened в журнале (0 — снятий не было). */
export async function triageVerdictEpoch(incidentId: string): Promise<number> {
  const rows = await chQuery<{ e: string | number }>(
    `SELECT count() AS e FROM triage_verdicts WHERE incident_id = {inc:String} AND state = 'reopened'`,
    { inc: incidentId },
  );
  return Number(rows[0]?.e ?? 0);
}

async function claimOwner(incidentId: string, epoch: number): Promise<string | null> {
  const rows = await chQuery<{ session_id: string }>(
    `SELECT session_id FROM triage_verdict_claims_v2 WHERE incident_id = {inc:String} AND epoch = {epoch:Int64}
     ORDER BY claimed_at, session_id LIMIT 1`,
    { inc: incidentId, epoch },
  );
  return rows[0]?.session_id ?? null;
}

/** Сессия, владеющая отметкой текущей эпохи инцидента (null — отметки нет). */
export async function triageVerdictWinner(incidentId: string): Promise<string | null> {
  return claimOwner(incidentId, await triageVerdictEpoch(incidentId));
}

/** Атомарно занять отметку вердикта инцидента и вернуть сессию-победителя (свою
 *  или чужую). Вставка с тем же токеном отбрасывается сервером, поэтому после её
 *  возврата кусок победителя уже виден, и чтение отдаёт одного и того же
 *  победителя всем участникам гонки. Бросает ошибку, если за время claim человек
 *  снял отметку (reopened): вызывающий повторяет запрос. */
export async function claimTriageVerdict(input: { incidentId: string; sessionId: string; actor: string }): Promise<string> {
  const epoch = await triageVerdictEpoch(input.incidentId);
  const existing = await claimOwner(input.incidentId, epoch);
  if (existing !== null) return existing;
  await chCommand(
    `INSERT INTO triage_verdict_claims_v2 (incident_id, epoch, session_id, actor, claimed_at)
     VALUES ({inc:String}, {epoch:Int64}, {sid:String}, {actor:String}, now64(3))`,
    { inc: input.incidentId, epoch, sid: input.sessionId, actor: input.actor },
    { insert_deduplicate: 1, insert_deduplication_token: `triage-claim:${input.incidentId}:${epoch}` },
  );
  const winner = await claimOwner(input.incidentId, epoch);
  if (winner === null) throw new Error("отметка записана, но не читается");
  if ((await triageVerdictEpoch(input.incidentId)) !== epoch) throw new Error("отметка снята во время записи");
  return winner;
}

export type TriageClaim = { incident_id: string; session_id: string; claimed_at: string };

/** Действующая отметка инцидента (claim текущей эпохи) или null. */
export async function triageVerdictClaim(incidentId: string): Promise<TriageClaim | null> {
  const rows = await chQuery<TriageClaim>(
    `SELECT c.incident_id AS incident_id, argMin(c.session_id, (c.claimed_at, c.session_id)) AS session_id,
            toString(min(c.claimed_at)) AS claimed_at
     FROM triage_verdict_claims_v2 AS c
     WHERE c.incident_id = {inc:String}
       AND c.epoch = (SELECT toInt64(count()) FROM triage_verdicts WHERE incident_id = {inc:String} AND state = 'reopened')
     GROUP BY c.incident_id`,
    { inc: incidentId },
  );
  return rows[0] ?? null;
}

export type AgentVerdictRow = {
  incident_id: string;
  session_id: string;
  agent: string;
  created_at: string;
  verdict: string;
  confidence: number;
  human_needed: number;
  verdict_json: string;
  markdown: string;
};

/** Записать вердикт агента (документ и Markdown). JSONEachRow: String-параметр
 *  ClickHouse не принимает сырые переводы строк Markdown. */
export async function saveAgentVerdict(row: Omit<AgentVerdictRow, "created_at">): Promise<void> {
  const created_at = new Date().toISOString().replace("T", " ").replace("Z", "");
  // Одна сессия — один вердикт: токен дедупликации по session_id (если у таблицы
  // включено окно дедупликации), а при чтении всегда берётся самая ранняя строка сессии.
  await chCommand(`INSERT INTO agent_verdicts FORMAT JSONEachRow\n${JSON.stringify({ ...row, created_at })}`, {}, { insert_deduplicate: 1, insert_deduplication_token: `agent-verdict:${row.incident_id}:${row.session_id}` });
}

/** Одна строка на сессию — самая ранняя, при равном времени — по документу:
 *  параллельные записи одной сессии читают одного и того же победителя. */
// ClickHouse подставляет псевдонимы SELECT вместо одноимённых колонок во всём запросе:
// `argMin(verdict_json, (created_at, verdict_json)) AS verdict_json` превращается в агрегат
// внутри агрегата (ILLEGAL_AGGREGATION, замечено на стенде). Поэтому запросы идут с
// prefer_column_name_to_alias = 1, а агрегат по created_at назван first_created.
const AGENT_VERDICT_COLS = `incident_id, session_id, argMin(agent, ${AGENT_VERDICT_SESSION_ORDER}) AS agent, toString(min(created_at)) AS first_created,
  argMin(verdict, ${AGENT_VERDICT_SESSION_ORDER}) AS verdict, argMin(confidence, ${AGENT_VERDICT_SESSION_ORDER}) AS confidence, argMin(human_needed, ${AGENT_VERDICT_SESSION_ORDER}) AS human_needed,
  argMin(verdict_json, ${AGENT_VERDICT_SESSION_ORDER}) AS verdict_json, argMin(markdown, ${AGENT_VERDICT_SESSION_ORDER}) AS markdown`;

const AGENT_VERDICT_SETTINGS = { prefer_column_name_to_alias: 1 };

/** Вердикты агентов по инциденту, новые первыми. */
export async function agentVerdictsFor(incidentId: string, limit = 20): Promise<AgentVerdictRow[]> {
  const rows = await chQuery<AgentVerdictRow>(
    `SELECT ${AGENT_VERDICT_COLS} FROM agent_verdicts WHERE incident_id = {inc:String}
     GROUP BY incident_id, session_id ORDER BY first_created DESC LIMIT {limit:UInt32}`,
    { inc: incidentId, limit: clampInt(limit, 1, 200, 20) },
    AGENT_VERDICT_SETTINGS,
  );
  return rows.map(agentVerdictRow);
}

/** Вердикт сессии разбора, если она его уже записала (одна сессия — один вердикт). */
export async function agentVerdictBySession(incidentId: string, sessionId: string): Promise<AgentVerdictRow | null> {
  const rows = await chQuery<AgentVerdictRow>(
    `SELECT ${AGENT_VERDICT_COLS} FROM agent_verdicts WHERE incident_id = {inc:String} AND session_id = {sid:String}
     GROUP BY incident_id, session_id LIMIT 1`,
    { inc: incidentId, sid: sessionId },
    AGENT_VERDICT_SETTINGS,
  );
  return rows[0] ? agentVerdictRow(rows[0]) : null;
}

/** Строка ClickHouse → AgentVerdictRow: first_created → created_at, числа — числами. */
function agentVerdictRow(r: AgentVerdictRow & { first_created?: string }): AgentVerdictRow {
  const { first_created, ...rest } = r;
  return { ...rest, created_at: first_created ?? r.created_at, confidence: Number(r.confidence), human_needed: Number(r.human_needed) };
}

/** Ещё не истёкшие отзывы: jti → срок токена (мс). */
export async function triageRevocations(): Promise<Map<string, number>> {
  const rows = await chQuery<{ session_id: string; exp: string | number }>(
    `SELECT session_id, toUnixTimestamp(max(expires_at)) AS exp FROM triage_session_revocations
     WHERE expires_at > now() GROUP BY session_id`,
  );
  return new Map(rows.map((r) => [r.session_id, Number(r.exp) * 1000]));
}

export type AuditRow = { ts: string; user: string; action: string; target: string; detail: string };

export async function auditTail(limit = 100): Promise<AuditRow[]> {
  return chQuery<AuditRow>(`SELECT ts, user, action, target, detail FROM console_audit ORDER BY ts DESC LIMIT {limit:UInt32}`, { limit });
}

/* ===== Ложные срабатывания по правилам (30 дней) ===== */

export type RuleFP = { rule_id: string; total: number; false_positive: number; closed: number };

export async function rulesFalsePositives(): Promise<Record<string, RuleFP>> {
  const rows = await chQuery<{ rule_id: string; total: string; fp: string; closed: string }>(
    `SELECT rule_id, count() AS total, countIf(status = 'false_positive') AS fp, countIf(status = 'closed') AS closed
     FROM (${LATEST}) WHERE created_at >= now() - INTERVAL 30 DAY GROUP BY rule_id`,
  );
  const out: Record<string, RuleFP> = {};
  for (const r of rows) out[r.rule_id] = { rule_id: r.rule_id, total: Number(r.total), false_positive: Number(r.fp), closed: Number(r.closed) };
  return out;
}

/* ===== Лицензионный учёт: пиковый EPS по дням, глубина хранения ===== */

export type LicenseStats = { peak_eps_30d: number; avg_eps_7d: number; events_30d: number; retention_days: number; sources: number };

export async function licenseStats(): Promise<LicenseStats> {
  const [peak] = await chQuery<{ peak: string; avg7: string; total30: string; sources: string }>(
    `SELECT round(max(m) / 60) AS peak, round(avgIf(m, seen_at >= now() - INTERVAL 7 DAY) / 60, 2) AS avg7,
            sum(m) AS total30, uniqExact(source) AS sources
     FROM (SELECT source, seen_at, sum(events_1m) AS m FROM collector_health_log
           WHERE seen_at >= now() - INTERVAL 30 DAY GROUP BY source, seen_at)`,
  );
  return {
    peak_eps_30d: Number(peak?.peak ?? 0),
    avg_eps_7d: Number(peak?.avg7 ?? 0),
    events_30d: Number(peak?.total30 ?? 0),
    retention_days: 180,
    sources: Number(peak?.sources ?? 0),
  };
}

/* ===== Переразбор инцидента движком ===== */


export async function requestReanalyze(id: string): Promise<string | null> {
  try {
    const r = await fetch(`${engineBase()}/incidents/${encodeURIComponent(id)}/analyze`, { method: "POST", cache: "no-store", headers: engineHeaders(), signal: AbortSignal.timeout(ENGINE_TIMEOUT_MS) });
    if (!r.ok) return `движок ответил ${r.status}`;
    return null;
  } catch (err) {
    return engineError("engine.reanalyze", err);
  }
}

/* ===== Обратный канал: блокировка/разблокировка адреса через движок ===== */

export type RespondResult = { error?: string; warning?: string; until?: string; results?: { executor: string; ok: boolean; detail: string }[] };

async function engineRespond(url: string, body: unknown, scope: string): Promise<RespondResult> {
  try {
    const r = await fetch(url, {
      method: "POST", cache: "no-store", headers: engineHeaders(),
      body: JSON.stringify(body), signal: AbortSignal.timeout(ENGINE_TIMEOUT_MS),
    });
    const text = await r.text();
    let parsed: RespondResult = {};
    try {
      parsed = JSON.parse(text) as RespondResult;
    } catch {
      /* не JSON — ниже подставим статус */
    }
    if (!r.ok) {
      console.error(`${scope}: ${r.status} ${text.slice(0, 300)}`);
      // 422 — движок объясняет отказ (адрес в allowlist, нет активной блокировки), 503 — журнал
      // реагирования недоступен и решение не применено: оба текста движка — это пользователю
      return { error: (r.status === 422 || r.status === 503) && parsed.error ? parsed.error : `движок ответил ${r.status}` };
    }
    return parsed;
  } catch (err) {
    return { error: engineError(scope, err) };
  }
}

export async function requestBlockIp(id: string, ip: string, reason: string, user: string): Promise<RespondResult> {
  return engineRespond(`${engineBase()}/incidents/${encodeURIComponent(id)}/respond`, { action: "block_ip", ip, reason, user }, "engine.block_ip");
}

/** POST /respond/unblock {ip, user, reason} → 200 {results:[…]} | 422 {error}. */
export async function requestUnblockIp(ip: string, user: string, reason: string): Promise<RespondResult> {
  return engineRespond(`${engineBase()}/respond/unblock`, { ip, user, reason }, "engine.unblock_ip");
}

/** POST /respond/exclude {ip, ttl, user, reason} → 200 {ip, until} | 503 {error}: исключить адрес из автоблокировки на срок. */
export async function requestExcludeIp(ip: string, ttl: string, user: string, reason: string): Promise<RespondResult> {
  return engineRespond(`${engineBase()}/respond/exclude`, { ip, ttl, user, reason }, "engine.exclude_ip");
}

/** POST /respond/exclude/revoke {ip, user, reason} → 200 | 422 {error} (адрес не исключён). */
export async function requestRevokeExclusion(ip: string, user: string, reason: string): Promise<RespondResult> {
  return engineRespond(`${engineBase()}/respond/exclude/revoke`, { ip, user, reason }, "engine.exclude_revoke");
}

export { blockCandidates, publicIpsFromChain } from "./shared/respond";
import { blockCandidatesForIncident } from "./shared/respond";

/** Свои сети из INTERNAL_NETS (те же, что у коллектора для attrs.scope и у движка в allowlist). */
export function ownNets(): string[] {
  return (process.env.INTERNAL_NETS ?? "").split(",").map((s) => s.trim()).filter(Boolean);
}

/** Кандидаты на блокировку с учётом собственных сетей инсталляции. */
export function blockCandidatesFor(inc: { actor_name: string; chain: string[]; tags?: string[] }): string[] {
  // Инцидент эксплуатации — не повод блокировать: кнопок нет, и blockIpAction их не примет.
  return blockCandidatesForIncident(inc, ownNets());
}

/* ===== Реагирование: режим IPS/IDS и журнал ответов ===== */

export { RESPOND_MODES, isRespondMode, type RespondMode } from "./shared/respond";
import { isRespondMode, type RespondMode, type RespondModeFrom } from "./shared/respond";

export type RespondStatus = {
  mode: RespondMode;
  mode_from: RespondModeFrom;
  enabled: boolean;
  ttl: string;
  allowlist: string[];
  active: { ip: string; incident: string; until: string; manual?: boolean; executors?: string[] }[];
  /** адреса, исключённые оператором из автоблокировки до until */
  excluded: { ip: string; since: string; until: string; actor: string; reason: string }[];
  config_errors: string[];
  pending: number;
  /** что записано из консоли (console_settings), даже если движок ещё не применил */
  requested: RespondMode | "" | null;
  error?: string;
};

export async function respondStatus(): Promise<RespondStatus> {
  const base = engineBase();
  const requested = await chQuery<{ value: string }>(
    `SELECT argMax(value, updated_at) AS requested_value FROM console_settings WHERE key = 'respond_mode' GROUP BY key`,
  ).then((r) => (r[0] ? ((r[0] as unknown as { requested_value: string }).requested_value as RespondMode | "") : null)).catch(() => null);
  const empty: RespondStatus = { mode: "simulate", mode_from: "config", enabled: false, ttl: "", allowlist: [], active: [], excluded: [], config_errors: [], pending: 0, requested };
  try {
    const r = await fetch(`${base}/respond/status`, { cache: "no-store", headers: engineAuth(), signal: AbortSignal.timeout(3000) });
    if (!r.ok) throw new Error(`engine ${r.status}`);
    const j = (await r.json()) as Partial<RespondStatus>;
    if (!isRespondMode(j.mode)) return { ...empty, error: `движок вернул неизвестный режим ${JSON.stringify(j.mode)}` };
    // Go отдаёт nil-срезы как null — нормализуем, чтобы страница не падала на .length
    return {
      mode: j.mode,
      mode_from: j.mode_from === "console" ? "console" : "config",
      enabled: Boolean(j.enabled),
      ttl: j.ttl ?? "",
      allowlist: j.allowlist ?? [],
      active: j.active ?? [],
      excluded: j.excluded ?? [],
      config_errors: j.config_errors ?? [],
      pending: Number(j.pending ?? 0),
      requested,
    };
  } catch (e) {
    return { ...empty, error: engineError("engine.respond_status", e) };
  }
}

/** Переключение режима из консоли: движок читает console_settings каждый цикл. */
export async function setRespondMode(mode: RespondMode | "", user: string): Promise<void> {
  await chCommand(
    `INSERT INTO console_settings (key, value, updated_at, updated_by) VALUES ('respond_mode', {mode:String}, now(), {user:String})`,
    { mode, user },
  );
}

export type ResponseLogRow = {
  ts: string; incident_id: string; rule_id: string; ip: string; mode: string; executor: string;
  dry_run: number; ok: number; detail: string; reason: string; actor: string;
};

export async function responseLog(opts: { incidentId?: string; limit?: number } = {}): Promise<ResponseLogRow[]> {
  const conds = ["1"];
  const params: Record<string, string | number> = { limit: Math.min(500, opts.limit ?? 50) };
  if (opts.incidentId) {
    conds.push("incident_id = {id:String}");
    params.id = opts.incidentId;
  }
  const rows = await chQuery<ResponseLogRow>(
    `SELECT toString(ts) AS ts, incident_id, rule_id, ip, mode, executor, dry_run, ok, detail, reason, actor
     FROM response_log WHERE ${conds.join(" AND ")} ORDER BY ts DESC LIMIT {limit:UInt32}`,
    params,
  );
  return rows.map((r) => ({ ...r, dry_run: Number(r.dry_run), ok: Number(r.ok) }));
}
