import "server-only";

// Метрики слепой выборки (web/src/lib/shared/blind-metrics.ts). Только завершённые
// инциденты: последняя закрывающая метка человека попадает в окно, и сейчас
// инцидент closed / false_positive в incidents_current. Вердикт агента — вердикт
// последней сессии разбора, начатой не позже этой метки (одна сессия — один вердикт,
// как в карточке). Ответы DevOps (правила ops.*, без disposition) входят в число ответов
// и в долю ложных (ops_cause = false_positive), в согласие с агентом — нет. Запрос
// уходит без настроек, даже без умолчания консоли (max_execution_time: null), и
// исполним от argus_ro: его политики argus_ro_blind скрывают только незавершённые
// слепые инциденты, а они сюда не входят.
import { ForbiddenError, requirePageSession, type Session } from "./auth";
import { chQuery } from "./clickhouse";
import { ROLE_RANK } from "./shared/incidents";
import { chTs } from "./shared/log-query";
import { AGENT_VERDICT_SESSION_ORDER } from "./shared/triage-verdict";
import { AGREEMENT_WINDOWS, VERDICT_DISPOSITION, assembleAgreement, type AgreementSqlRow, type AgreementWindow } from "./shared/blind-metrics";

const VERDICTS = Object.keys(VERDICT_DISPOSITION).map((v) => `'${v}'`).join(", ");
const DISPOSITIONS = Object.values(VERDICT_DISPOSITION).map((v) => `'${v}'`).join(", ");

export const AGREEMENT_SQL = `WITH
  closes AS (
    SELECT incident_id,
           argMax(disposition, (changed_at, revision)) AS disposition,
           argMax(ops_cause, (changed_at, revision)) AS ops_cause,
           argMax(blind, (changed_at, revision)) AS blind,
           max(changed_at) AS closed_at
    FROM incident_state_events
    WHERE labeled_by_human AND kind = 'status' AND status IN ('closed', 'false_positive')
    GROUP BY incident_id
    HAVING closed_at >= parseDateTime64BestEffort({from:String}, 3, 'UTC')
       AND closed_at < parseDateTime64BestEffort({to:String}, 3, 'UTC')
       AND (disposition != '' OR ops_cause != '')
  ),
  done AS (
    SELECT incident_id, rule_id, rule_title
    FROM incidents_current
    WHERE incident_id IN (SELECT incident_id FROM closes) AND status IN ('closed', 'false_positive')
  ),
  sessions AS (
    -- Вердикт сессии — как в карточке (agentVerdictsFor): самая ранняя строка сессии.
    -- Псевдонимы не совпадают с колонками, поэтому prefer_column_name_to_alias, которую
    -- профиль argus_ro передать не позволил бы, не нужна.
    SELECT incident_id AS session_incident, session_id AS session,
           min(created_at) AS session_created,
           argMin(verdict, ${AGENT_VERDICT_SESSION_ORDER}) AS session_verdict
    FROM agent_verdicts
    WHERE incident_id IN (SELECT incident_id FROM closes)
    GROUP BY incident_id, session_id
  ),
  verdicts AS (
    -- Последняя сессия, начатая не позже закрытия.
    SELECT s.session_incident AS incident_id, argMax(s.session_verdict, (s.session_created, s.session)) AS verdict
    FROM sessions AS s INNER JOIN closes AS c ON c.incident_id = s.session_incident
    WHERE s.session_created <= c.closed_at
    GROUP BY s.session_incident
  )
SELECT d.rule_id AS rule_id, any(d.rule_title) AS rule_title, c.blind AS blind,
       count() AS labeled,
       countIf(c.disposition = 'false_positive' OR c.ops_cause = 'false_positive') AS fp,
       countIf(c.disposition != '' AND transform(v.verdict, [${VERDICTS}], [${DISPOSITIONS}], '') != '') AS compared,
       countIf(c.disposition != '' AND transform(v.verdict, [${VERDICTS}], [${DISPOSITIONS}], '') = c.disposition) AS agreed,
       countIf(c.disposition != '' AND v.verdict = 'undetermined') AS undetermined,
       countIf(c.disposition != '' AND v.verdict = '') AS no_verdict
FROM closes AS c
INNER JOIN done AS d ON d.incident_id = c.incident_id
LEFT JOIN verdicts AS v ON v.incident_id = c.incident_id
GROUP BY rule_id, blind
ORDER BY rule_id, blind`;

export function agreementParams(window: AgreementWindow, nowMs = Date.now()): { from: string; to: string } {
  return { from: chTs(nowMs - AGREEMENT_WINDOWS[window].days * 86_400_000), to: chTs(nowMs + 1) };
}

export async function agreementMetrics(window: AgreementWindow, nowMs = Date.now()) {
  const params = agreementParams(window, nowMs);
  const rows = await chQuery<AgreementSqlRow>(AGREEMENT_SQL, params, { max_execution_time: null });
  return { window, ...params, ...assembleAgreement(rows) };
}

/** Страница — аналитику и администратору (наблюдателю — «Доступ запрещён»). */
export async function requireAgreementAccess(): Promise<Session> {
  const session = await requirePageSession();
  if (ROLE_RANK[session.role] < ROLE_RANK.analyst) throw new ForbiddenError("Метрики согласия доступны аналитику и администратору");
  return session;
}

/** API: сессия консоли от аналитика и выше или bearer ARGUS_API_TOKEN. Сессия
 *  разбора и issuer — нет: агенту незачем знать, как часто с ним согласны люди. */
export function agreementApiForbidden(s: Session): Response | null {
  if (s.kind === "api-token") return null;
  if (s.kind === "console" && ROLE_RANK[s.role] >= ROLE_RANK.analyst) return null;
  return Response.json({ error: "forbidden", detail: "метрики согласия доступны аналитику и администратору" }, { status: 403 });
}
