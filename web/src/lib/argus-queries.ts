// Запросы ARGUS-контура: единая схема событий, инциденты, вердикты аналитика,
// здоровье коллекторов. ReplacingMergeTree читаем через argMax по updated_at.
import "server-only";
import crypto from "node:crypto";
import { clampInt, clampPage } from "./shared/limits";
import { chCommand, chQuery as chQueryRaw } from "./clickhouse";

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

export async function incidentsList(
  filter: { status?: string; level?: string; q?: string; page?: number; pageSize?: number; queue?: "open" | "mine" | "unassigned" | "overdue"; user?: string } = {},
): Promise<{ rows: IncidentRow[]; total: number; page: number; pageSize: number }> {
  const having: string[] = [];
  const pageSize = clampInt(filter.pageSize, 10, 200, 50);
  let page = clampPage(filter.page);
  const params: Record<string, string | number> = { limit: pageSize, offset: (page - 1) * pageSize };
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
}): Promise<void> {
  const r = await fetch(`${engineBase()}/incidents/${encodeURIComponent(input.id)}/workflow`, {
    method: "POST", cache: "no-store", headers: engineHeaders(), signal: AbortSignal.timeout(ENGINE_TIMEOUT_MS),
    body: JSON.stringify(input),
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
};

export async function incidentStateHistory(id: string, limit = 200): Promise<IncidentStateEvent[]> {
  const rows = await chQuery<IncidentStateEvent>(
    `SELECT event_id, revision, changed_at, actor, kind, status, owner, reason
     FROM incident_state_events WHERE incident_id = {id:String}
     ORDER BY revision DESC LIMIT {limit:UInt32}`, { id, limit: Math.min(10_000, Math.max(1, Math.floor(limit))) },
  );
  return rows.reverse().map((row) => ({ ...row, revision: Number(row.revision) }));
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
};

export async function sourcesHealth(): Promise<SourceHealth[]> {
  const rows = await chQuery<SourceHealth>(
    `SELECT source, any(source_class) AS source_class, count() AS events_1h,
            countIf(received_at >= now() - INTERVAL 60 SECOND) AS eps_60s,
            max(received_at) AS last_ts,
            round(100 * avg(pii), 1) AS pii_share,
            if(max(received_at) >= now() - INTERVAL 5 MINUTE, 1, 0) AS alive
     FROM events WHERE received_at >= now() - INTERVAL 1 HOUR
     GROUP BY source ORDER BY events_1h DESC`,
  );
  return rows.map((r) => ({ ...r, events_1h: Number(r.events_1h), eps_60s: Number(r.eps_60s), pii_share: Number(r.pii_share), alive: Number(r.alive) }));
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

export async function eventsRecent(source?: string, limit = 60): Promise<EventRow[]> {
  const params: Record<string, string | number> = { limit };
  let where = "received_at >= now() - INTERVAL 24 HOUR";
  if (source) {
    where += " AND source = {source:String}";
    params.source = source;
  }
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
const AGENT_VERDICT_COLS = `incident_id, session_id, argMin(agent, (created_at, verdict_json)) AS agent, toString(min(created_at)) AS created_at,
  argMin(verdict, (created_at, verdict_json)) AS verdict, argMin(confidence, (created_at, verdict_json)) AS confidence, argMin(human_needed, (created_at, verdict_json)) AS human_needed,
  argMin(verdict_json, (created_at, verdict_json)) AS verdict_json, argMin(markdown, (created_at, verdict_json)) AS markdown`;

/** Вердикты агентов по инциденту, новые первыми. */
export async function agentVerdictsFor(incidentId: string, limit = 20): Promise<AgentVerdictRow[]> {
  const rows = await chQuery<AgentVerdictRow>(
    `SELECT ${AGENT_VERDICT_COLS} FROM agent_verdicts WHERE incident_id = {inc:String}
     GROUP BY incident_id, session_id ORDER BY created_at DESC LIMIT {limit:UInt32}`,
    { inc: incidentId, limit: clampInt(limit, 1, 200, 20) },
  );
  return rows.map((r) => ({ ...r, confidence: Number(r.confidence), human_needed: Number(r.human_needed) }));
}

/** Вердикт сессии разбора, если она его уже записала (одна сессия — один вердикт). */
export async function agentVerdictBySession(incidentId: string, sessionId: string): Promise<AgentVerdictRow | null> {
  const rows = await chQuery<AgentVerdictRow>(
    `SELECT ${AGENT_VERDICT_COLS} FROM agent_verdicts WHERE incident_id = {inc:String} AND session_id = {sid:String}
     GROUP BY incident_id, session_id LIMIT 1`,
    { inc: incidentId, sid: sessionId },
  );
  return rows[0] ? { ...rows[0], confidence: Number(rows[0].confidence), human_needed: Number(rows[0].human_needed) } : null;
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

export type RespondResult = { error?: string; results?: { executor: string; ok: boolean; detail: string }[] };

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
      // 422 — движок объясняет отказ (адрес в allowlist, нет активной блокировки): это пользователю
      return { error: r.status === 422 && parsed.error ? parsed.error : `движок ответил ${r.status}` };
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

export { publicIpsFromChain } from "./shared/respond";

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
  const empty: RespondStatus = { mode: "simulate", mode_from: "config", enabled: false, ttl: "", allowlist: [], active: [], config_errors: [], pending: 0, requested };
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
