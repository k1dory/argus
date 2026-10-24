-- Перенос действующих отметок published из журнала 0020 в triage_verdict_claims
-- (замечание ревью 0021). Читатели теперь смотрят только
-- claims, поэтому без переноса задача с отметкой published снова выдавалась бы
-- другой сессии.
--
-- Поколение (epoch) — число строк reopened по задаче; владелец — первая
-- сессия, отметившая задачу после последнего reopened, как выбирал прежний
-- читатель (updated_at, затем session_id). claimed_at = исходный updated_at.
-- Владелец выбирается сначала среди отметок строго позже последнего reopened
-- (published(A,T) → reopened(T) → published(B,T+1с) даёт B); отметка с
-- updated_at, равным последнему reopened, — запасной вариант и считается действующей:
-- ошибка в эту сторону лишь требует от человека лишнего «Разрешить повторный
-- разбор», а не даёт второй 201. Задачи, у которых claim этого поколения уже
-- есть, пропускаются — миграция безопасна при повторе.
--
-- Порядок переключения: остановить запись старой консоли и шлюза (старый код
-- пишет published в triage_verdicts), применить 0021 и 0022, затем раскатить
-- консоль с новым кодом. Что старый код записал после 0022, не переносится.
INSERT INTO argus.triage_verdict_claims (task_id, epoch, incident_id, session_id, actor, claimed_at)
SELECT v.task_id AS task_id, toInt64(any(r.epoch)) AS epoch,
       argMin(v.incident_id, (v.updated_at = r.last_reopen, v.updated_at, v.session_id)) AS incident_id,
       argMin(v.session_id, (v.updated_at = r.last_reopen, v.updated_at, v.session_id)) AS session_id,
       argMin(v.actor, (v.updated_at = r.last_reopen, v.updated_at, v.session_id)) AS actor,
       argMin(v.updated_at, (v.updated_at = r.last_reopen, v.updated_at, v.session_id)) AS claimed_at
FROM argus.triage_verdicts AS v
LEFT JOIN
(
    SELECT task_id, count() AS epoch, max(updated_at) AS last_reopen
    FROM argus.triage_verdicts WHERE state = 'reopened' GROUP BY task_id
) AS r ON v.task_id = r.task_id
WHERE v.state = 'published' AND v.updated_at >= r.last_reopen
GROUP BY v.task_id
HAVING (v.task_id, toInt64(any(r.epoch))) NOT IN (SELECT task_id, epoch FROM argus.triage_verdict_claims)
SETTINGS join_use_nulls = 0;
