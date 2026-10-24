import { chCommand, chQuery, RANGES, type RangeKey } from "./clickhouse";
import { clampInt, clampLevel, clampPage } from "./shared/limits";

// Заглушённые правила исключаются из всех витрин алертов (борьба с шумом);
// витрина CVE намеренно не фильтруется — уязвимость не «шум».
const NOT_MUTED = `rule_id NOT IN (
  SELECT rule_id FROM console_rule_mutes GROUP BY rule_id HAVING argMax(muted, updated_at) = 1
)`;

/** Предел точек/строк любой витрины: страница не должна тащить больше, чем покажет. */
const MAX_SERIES_POINTS = 2000;
const MAX_LIST_ROWS = 1000;

export type OverviewStats = {
  total: number;
  critical: number;
  agents: number;
  compliance: number | null;
};

export async function overviewStats(range: RangeKey): Promise<OverviewStats> {
  const { hours } = RANGES[range];
  const [alerts] = await chQuery<{ total: string; critical: string; agents: string }>(
    `SELECT count() AS total,
            countIf(rule_level >= 12) AS critical,
            uniqExactIf(agent_id, agent_id != '') AS agents
     FROM wazuh_alerts
     WHERE timestamp >= now() - INTERVAL {hours:UInt32} HOUR AND ${NOT_MUTED}`,
    { hours },
  );
  // «Неизвестно» (SCA/API недоступны) не считается ни нарушением, ни соответствием.
  const known = (await hasVerdictStatus()) ? "status != 'unknown'" : "1";
  const compliance = await chQuery<{ pct: number | null }>(
    `SELECT round(100 * avgIf(compliant, ${known}), 1) AS pct
     FROM policy_verdicts
     WHERE evaluated_at = (SELECT max(evaluated_at) FROM policy_verdicts)
     LIMIT 1`,
  );
  return {
    total: Number(alerts?.total ?? 0),
    critical: Number(alerts?.critical ?? 0),
    agents: Number(alerts?.agents ?? 0),
    compliance: compliance.length > 0 && compliance[0].pct != null && Number.isFinite(Number(compliance[0].pct)) ? Number(compliance[0].pct) : null,
  };
}

export type SeriesPoint = { bucket: string; low: number; high: number; critical: number };

export async function alertsSeries(range: RangeKey): Promise<SeriesPoint[]> {
  const { hours, bucketMinutes } = RANGES[range];
  const rows = await chQuery<{ bucket: string; low: string; high: string; critical: string }>(
    `SELECT toStartOfInterval(timestamp, INTERVAL {bucket:UInt32} MINUTE) AS bucket,
            countIf(rule_level < 7) AS low,
            countIf(rule_level >= 7 AND rule_level < 12) AS high,
            countIf(rule_level >= 12) AS critical
     FROM wazuh_alerts
     WHERE timestamp >= now() - INTERVAL {hours:UInt32} HOUR AND ${NOT_MUTED}
     GROUP BY bucket ORDER BY bucket LIMIT {limit:UInt32}`,
    { hours, bucket: bucketMinutes, limit: MAX_SERIES_POINTS },
  );
  return rows.map((r) => ({
    bucket: r.bucket,
    low: Number(r.low),
    high: Number(r.high),
    critical: Number(r.critical),
  }));
}

export type TopRule = { ruleId: number; description: string; level: number; count: number };

export async function topRules(range: RangeKey, limit = 8): Promise<TopRule[]> {
  const { hours } = RANGES[range];
  const rows = await chQuery<{ rule_id: number; description: string; level: number; cnt: string }>(
    `SELECT rule_id, any(rule_description) AS description, max(rule_level) AS level, count() AS cnt
     FROM wazuh_alerts
     WHERE timestamp >= now() - INTERVAL {hours:UInt32} HOUR AND ${NOT_MUTED}
     GROUP BY rule_id ORDER BY cnt DESC LIMIT {limit:UInt32}`,
    { hours, limit: clampInt(limit, 1, 100, 8) },
  );
  return rows.map((r) => ({
    ruleId: r.rule_id,
    description: r.description,
    level: r.level,
    count: Number(r.cnt),
  }));
}

export type TacticCount = { tactic: string; count: number };

export async function topTactics(range: RangeKey, limit = 8): Promise<TacticCount[]> {
  const { hours } = RANGES[range];
  const rows = await chQuery<{ tactic: string; cnt: string }>(
    `SELECT tactic, count() AS cnt
     FROM wazuh_alerts ARRAY JOIN mitre_tactics AS tactic
     WHERE timestamp >= now() - INTERVAL {hours:UInt32} HOUR AND ${NOT_MUTED}
     GROUP BY tactic ORDER BY cnt DESC LIMIT {limit:UInt32}`,
    { hours, limit: clampInt(limit, 1, 100, 8) },
  );
  return rows.map((r) => ({ tactic: r.tactic, count: Number(r.cnt) }));
}

export type AlertRow = {
  timestamp: string;
  agent_name: string;
  rule_id: number;
  rule_level: number;
  rule_description: string;
  srcip: string;
  location: string;
};

export type AlertSort = "ts" | "level";
export type AlertDir = "asc" | "desc";

export type AlertFilters = {
  range: RangeKey;
  minLevel?: number;
  agent?: string;
  search?: string;
  showMuted?: boolean;
  page?: number;
  sort?: AlertSort;
  dir?: AlertDir;
};

/** Строк на странице журнала алертов. */
export const ALERTS_PAGE_SIZE = 100;
/** Потолок страниц журнала: глубже — поиск с точным интервалом. */
export const ALERTS_MAX_PAGE = 100;

export const parseAlertSort = (v: unknown): AlertSort => (v === "level" ? "level" : "ts");
export const parseAlertDir = (v: unknown): AlertDir => (v === "asc" ? "asc" : "desc");

function alertsWhere(filters: AlertFilters): { where: string; params: Record<string, string | number> } {
  const { hours } = RANGES[filters.range];
  const conditions = ["timestamp >= now() - INTERVAL {hours:UInt32} HOUR"];
  if (!filters.showMuted) conditions.push(NOT_MUTED);
  const params: Record<string, string | number> = { hours };
  const minLevel = clampLevel(filters.minLevel ?? 0);
  if (minLevel > 0) {
    conditions.push("rule_level >= {minLevel:UInt8}");
    params.minLevel = minLevel;
  }
  if (filters.agent) {
    conditions.push("agent_name = {agent:String}");
    params.agent = filters.agent.slice(0, 128);
  }
  if (filters.search) {
    conditions.push("positionCaseInsensitive(rule_description, {search:String}) > 0");
    params.search = filters.search.slice(0, 200);
  }
  return { where: conditions.join(" AND "), params };
}

export type AlertsPage = { rows: AlertRow[]; total: number; page: number; pageSize: number; pages: number };

/** Страница журнала: сортировка только по белому списку колонок, page/level — клампы. */
export async function alertsList(filters: AlertFilters): Promise<AlertsPage> {
  const { where, params } = alertsWhere(filters);
  const page = Math.min(ALERTS_MAX_PAGE, clampPage(filters.page ?? 1));
  const sort = parseAlertSort(filters.sort);
  const dir = parseAlertDir(filters.dir) === "asc" ? "ASC" : "DESC";
  const orderBy = sort === "level" ? `rule_level ${dir}, timestamp DESC` : `timestamp ${dir}`;
  const [rows, count] = await Promise.all([
    chQuery<AlertRow>(
      `SELECT timestamp, agent_name, rule_id, rule_level, rule_description, srcip, location
       FROM wazuh_alerts
       WHERE ${where}
       ORDER BY ${orderBy} LIMIT {limit:UInt32} OFFSET {offset:UInt32}`,
      { ...params, limit: ALERTS_PAGE_SIZE, offset: (page - 1) * ALERTS_PAGE_SIZE },
    ),
    chQuery<{ total: string }>(`SELECT count() AS total FROM wazuh_alerts WHERE ${where}`, params),
  ]);
  const total = Number(count[0]?.total ?? 0);
  return { rows, total, page, pageSize: ALERTS_PAGE_SIZE, pages: Math.max(1, Math.min(ALERTS_MAX_PAGE, Math.ceil(total / ALERTS_PAGE_SIZE))) };
}

export async function agentNames(range: RangeKey): Promise<string[]> {
  const { hours } = RANGES[range];
  const rows = await chQuery<{ agent_name: string }>(
    `SELECT DISTINCT agent_name FROM wazuh_alerts
     WHERE timestamp >= now() - INTERVAL {hours:UInt32} HOUR AND agent_name != ''
     ORDER BY agent_name LIMIT {limit:UInt32}`,
    { hours, limit: MAX_LIST_ROWS },
  );
  return rows.map((r) => r.agent_name);
}

/** pass — соблюдено, fail — нарушение, unknown — проверка не выполнена (SCA/API недоступны, причина в violations). */
export type VerdictStatus = "pass" | "fail" | "unknown";

export type VerdictRow = {
  evaluated_at: string;
  entity_type: string;
  entity_id: string;
  entity_name: string;
  policy: string;
  compliant: number;
  violations: string[];
  status: VerdictStatus;
};

// Колонка status появилась у policyd позже таблицы: на старом стенде её нет,
// и запрос деградирует к compliant без ошибки. Проверка — раз на процесс.
let verdictStatusColumn: Promise<boolean> | null = null;
function hasVerdictStatus(): Promise<boolean> {
  verdictStatusColumn ??= chQuery<{ n: string }>(
    `SELECT count() AS n FROM system.columns
     WHERE database = currentDatabase() AND table = 'policy_verdicts' AND name = 'status'`,
  )
    .then((r) => Number(r[0]?.n ?? 0) > 0)
    .catch((e) => {
      verdictStatusColumn = null;
      throw e;
    });
  return verdictStatusColumn;
}

export function verdictStatusOf(compliant: number, status?: string | null): VerdictStatus {
  if (status === "pass" || status === "fail" || status === "unknown") return status;
  return Number(compliant) === 1 ? "pass" : "fail";
}

export type VerdictSummary = { total: number; failed: number; unknown: number; evaluatedAt: string | null };

export async function latestVerdictsSummary(): Promise<VerdictSummary> {
  const withStatus = await hasVerdictStatus();
  const unknown = withStatus ? "status = 'unknown'" : "0";
  const failed = withStatus ? "status = 'fail' OR (status = '' AND compliant = 0)" : "compliant = 0";
  const [row] = await chQuery<{ total: string; failed: string; unknown: string; evaluated_max: string }>(
    `SELECT count() AS total, countIf(${failed}) AS failed, countIf(${unknown}) AS unknown,
            max(evaluated_at) AS evaluated_max
     FROM policy_verdicts
     WHERE evaluated_at = (SELECT max(evaluated_at) FROM policy_verdicts)`,
  );
  return { total: Number(row?.total ?? 0), failed: Number(row?.failed ?? 0), unknown: Number(row?.unknown ?? 0), evaluatedAt: Number(row?.total ?? 0) ? row.evaluated_max : null };
}

export async function latestVerdicts(page = 1): Promise<VerdictRow[]> {
  const withStatus = await hasVerdictStatus();
  const statusExpr = withStatus ? "status" : "if(compliant = 1, 'pass', 'fail')";
  const rows = await chQuery<Omit<VerdictRow, "status"> & { status: string }>(
    `SELECT evaluated_at, entity_type, entity_id, entity_name, policy, compliant, violations, ${statusExpr} AS status
     FROM policy_verdicts
     WHERE evaluated_at = (SELECT max(evaluated_at) FROM policy_verdicts)
     ORDER BY status = 'fail' DESC, status = 'unknown' DESC, entity_name, policy, entity_id
     LIMIT {limit:UInt32} OFFSET {offset:UInt32}`,
    { limit: MAX_LIST_ROWS, offset: (clampPage(page) - 1) * MAX_LIST_ROWS },
  );
  return rows.map((r) => ({ ...r, compliant: Number(r.compliant), status: verdictStatusOf(Number(r.compliant), r.status) }));
}

export type AgentSummary = {
  agent_name: string;
  alerts: number;
  critical: number;
  rules: number;
  last_alert: string;
};

export async function agentsSummary(range: RangeKey): Promise<AgentSummary[]> {
  const { hours } = RANGES[range];
  const rows = await chQuery<{
    agent_name: string;
    alerts: string;
    critical: string;
    rules: string;
    last_alert: string;
  }>(
    `SELECT agent_name,
            count() AS alerts,
            countIf(rule_level >= 12) AS critical,
            uniqExact(rule_id) AS rules,
            max(timestamp) AS last_alert
     FROM wazuh_alerts
     WHERE timestamp >= now() - INTERVAL {hours:UInt32} HOUR AND agent_name != ''
       AND ${NOT_MUTED}
     GROUP BY agent_name ORDER BY alerts DESC LIMIT {limit:UInt32}`,
    { hours, limit: MAX_LIST_ROWS },
  );
  return rows.map((r) => ({
    agent_name: r.agent_name,
    alerts: Number(r.alerts),
    critical: Number(r.critical),
    rules: Number(r.rules),
    last_alert: r.last_alert,
  }));
}

/* ===== Мьюты правил (шумоподавление) ===== */

export async function setRuleMuted(ruleId: number, muted: boolean): Promise<void> {
  await chCommand(
    `INSERT INTO console_rule_mutes (rule_id, muted, updated_at)
     SELECT {ruleId:UInt32}, {muted:UInt8}, now()`,
    { ruleId, muted: muted ? 1 : 0 },
  );
}

export async function mutedRuleIds(): Promise<number[]> {
  const rows = await chQuery<{ rule_id: number }>(
    `SELECT rule_id FROM console_rule_mutes
     GROUP BY rule_id HAVING argMax(muted, updated_at) = 1 LIMIT {limit:UInt32}`,
    { limit: MAX_LIST_ROWS },
  );
  return rows.map((r) => r.rule_id);
}

export type MutedRule = { rule_id: number; description: string };

export async function mutedRulesList(): Promise<MutedRule[]> {
  return chQuery<MutedRule>(
    `SELECT m.rule_id AS rule_id, coalesce(any(d.description), '') AS description
     FROM (SELECT rule_id FROM console_rule_mutes
           GROUP BY rule_id HAVING argMax(muted, updated_at) = 1) AS m
     LEFT JOIN (SELECT rule_id, any(rule_description) AS description
                FROM wazuh_alerts GROUP BY rule_id) AS d USING (rule_id)
     GROUP BY m.rule_id ORDER BY m.rule_id LIMIT {limit:UInt32}`,
    { limit: MAX_LIST_ROWS },
  );
}

/* ===== Уязвимости (CVE из vulnerability-detector) ===== */

export type VulnRow = {
  cve: string;
  severity: string;
  score: number;
  pkg: string;
  pkg_version: string;
  agent_name: string;
  status: string;
  last_seen: string;
};

export const VULN_LIMIT = 300;

export async function vulnList(): Promise<VulnRow[]> {
  const rows = await chQuery<VulnRow>(
    `SELECT vuln_cve AS cve,
            argMax(vuln_severity, timestamp) AS severity,
            argMax(vuln_score, timestamp) AS score,
            vuln_package AS pkg,
            argMax(vuln_package_version, timestamp) AS pkg_version,
            agent_name,
            argMax(vuln_status, timestamp) AS status,
            max(timestamp) AS last_seen
     FROM wazuh_alerts
     WHERE vuln_cve != '' AND timestamp >= now() - INTERVAL 30 DAY
     GROUP BY cve, pkg, agent_name
     ORDER BY score DESC, cve
     LIMIT {limit:UInt32}`,
    { limit: VULN_LIMIT },
  );
  return rows.map((r) => ({ ...r, score: Number(r.score) }));
}

/* ===== MITRE ATT&CK ===== */

export type TechniqueCount = { id: string; technique: string; count: number };

export async function topTechniques(range: RangeKey, limit = 20): Promise<TechniqueCount[]> {
  const { hours } = RANGES[range];
  // Массивы id и technique у Wazuh параллельны; arrayResize страхует
  // от рассинхрона длин (arrayZip падает на неравных массивах).
  const rows = await chQuery<{ id: string; technique: string; cnt: string }>(
    `SELECT t.1 AS id, t.2 AS technique, count() AS cnt
     FROM wazuh_alerts
     ARRAY JOIN arrayZip(mitre_ids, arrayResize(mitre_techniques, length(mitre_ids), '')) AS t
     WHERE timestamp >= now() - INTERVAL {hours:UInt32} HOUR
       AND length(mitre_ids) > 0 AND ${NOT_MUTED}
     GROUP BY id, technique ORDER BY cnt DESC LIMIT {limit:UInt32}`,
    { hours, limit: clampInt(limit, 1, 200, 20) },
  );
  return rows.map((r) => ({ id: r.id, technique: r.technique, count: Number(r.cnt) }));
}
