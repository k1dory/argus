-- Вердикты агента разбора, записанные в ARGUS через POST /api/triage/verdicts
-- (bearer — токен triage-session). Раньше консоль хранила только отметку
-- «вердикт принят», а текст уходил во внешний трекер; теперь документ
-- argus-triage/v3 (verdict_json) и собранный консолью Markdown лежат здесь, а
-- Markdown дублируется комментарием incident_comments от автора agent:<имя>.
-- Одна сессия — один вердикт: session_id и есть идентификатор записи.
-- confidence — уверенность числом: high 0.9, medium 0.6, low 0.3.
-- Отдельно от incident_verdicts: та таблица — вердикты движка.
-- TTL нет: вердикт — часть досье инцидента.
CREATE TABLE IF NOT EXISTS argus.agent_verdicts
(
    incident_id  String,
    session_id   String,
    agent        LowCardinality(String),
    created_at   DateTime64(3, 'UTC'),
    verdict      LowCardinality(String),
    confidence   Float32,
    human_needed UInt8,
    verdict_json String CODEC(ZSTD(3)),
    markdown     String CODEC(ZSTD(3))
)
ENGINE = MergeTree
ORDER BY (incident_id, created_at);
