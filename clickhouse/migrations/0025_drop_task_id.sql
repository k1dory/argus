-- Внешний id задачи трекера уходит из схемы: сессии разбора выпускаются по
-- incident_id (POST /api/triage/sessions), вердикт пишется в ARGUS
-- (agent_verdicts, 0024), и консоли больше нечего сопоставлять с задачей.
--
-- webhook_deliveries: колонка и индекс 0018 не входят в ключ сортировки —
-- удаляются.
ALTER TABLE argus.webhook_deliveries DROP INDEX IF EXISTS idx_task_id;
ALTER TABLE argus.webhook_deliveries DROP COLUMN IF EXISTS task_id;

-- triage_verdict_claims (0021) и triage_verdicts (0020) держат task_id в
-- ORDER BY — колонку из них удалить нельзя. Отметки переезжают в
-- triage_verdict_claims_v2 с ключом (incident_id, epoch); старая таблица
-- остаётся как есть, консоль её не читает. Журнал снятий отметок
-- (triage_verdicts, state = 'reopened') продолжает вестись — с пустым task_id,
-- поколение (epoch) считается по incident_id.
--
-- Победитель по-прежнему определяется дедупликацией вставки: консоль пишет
-- claim с insert_deduplication_token = 'triage-claim:<incident_id>:<epoch>',
-- повторная вставка с тем же токеном отбрасывается сервером под блокировкой
-- таблицы; первая строка по (incident_id, epoch) неизменяема. async_insert для
-- этой таблицы не включать: claim должен быть синхронным.
CREATE TABLE IF NOT EXISTS argus.triage_verdict_claims_v2
(
    incident_id String,
    epoch       Int64,
    session_id  String,
    actor       String,
    claimed_at  DateTime64(3, 'UTC') DEFAULT now64(3)
)
ENGINE = MergeTree
ORDER BY (incident_id, epoch)
SETTINGS non_replicated_deduplication_window = 1000000;

-- Перенос действующих отметок: claim текущего поколения своей задачи
-- становится claim инцидента в поколении «число снятий по инциденту».
-- Владелец — самая ранняя из таких отметок. Повтор миграции ничего не дублирует.
INSERT INTO argus.triage_verdict_claims_v2 (incident_id, epoch, session_id, actor, claimed_at)
SELECT c.incident_id AS incident_id, toInt64(any(r.e)) AS epoch,
       argMin(c.session_id, (c.claimed_at, c.session_id)) AS session_id,
       argMin(c.actor, (c.claimed_at, c.session_id)) AS actor,
       min(c.claimed_at) AS claimed_at
FROM argus.triage_verdict_claims AS c
LEFT JOIN
(
    SELECT task_id, toInt64(count()) AS e FROM argus.triage_verdicts WHERE state = 'reopened' GROUP BY task_id
) AS t ON c.task_id = t.task_id
LEFT JOIN
(
    SELECT incident_id, toInt64(count()) AS e FROM argus.triage_verdicts WHERE state = 'reopened' GROUP BY incident_id
) AS r ON c.incident_id = r.incident_id
WHERE c.epoch = t.e AND c.incident_id != ''
GROUP BY c.incident_id
HAVING (c.incident_id, toInt64(any(r.e))) NOT IN (SELECT incident_id, epoch FROM argus.triage_verdict_claims_v2)
SETTINGS join_use_nulls = 0;
