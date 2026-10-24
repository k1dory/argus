-- Атомарная отметка вердикта задачи (блокер ревью журнала 0020).
-- Журнал 0020 с выбором победителя «по updated_at, затем session_id» не атомарен:
-- вставка с более ранним временем может стать видимой позже, и победитель
-- меняется после того, как первой сессии уже ответили 201.
--
-- Здесь победитель определяется дедупликацией вставки: консоль пишет claim с
-- insert_deduplication_token = 'triage-claim:<task_id>:<epoch>', повторная
-- вставка с тем же токеном отбрасывается сервером при добавлении куска, под
-- блокировкой таблицы. Первая строка по (task_id, epoch) неизменяема.
-- epoch — мс последнего reopened в triage_verdicts (0 — снятий не было): после
-- снятия отметки человеком токен другой, и задачу можно отметить заново.
-- Окно дедупликации — число последних вставок таблицы (токен вытесняется только
-- после стольких новых claim); на задачу их единицы, 1 000 000 — запас на годы.
-- async_insert для этой таблицы не включать: claim должен быть синхронным.
CREATE TABLE IF NOT EXISTS argus.triage_verdict_claims
(
    task_id     String,
    epoch       Int64,
    incident_id String,
    session_id  String,
    actor       String,
    claimed_at  DateTime64(3, 'UTC') DEFAULT now64(3)
)
ENGINE = MergeTree
ORDER BY (task_id, epoch)
SETTINGS non_replicated_deduplication_window = 1000000;
