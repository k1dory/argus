-- Ответ человека при завершении инцидента — типизированная метка рядом со
-- свободной причиной (reason) в том же неизменяемом событии: по тексту не обучить
-- и не посчитать долю ложных срабатываний правила.
--   disposition      — malicious | benign_authorized | false_positive (инциденты ИБ);
--   escalate         — нужна ли была эскалация;
--   severity_correct — верен ли уровень правила;
--   ops_cause / ops_action — причина и действие для эксплуатационных правил (теги ops.*);
--   blind            — инцидент из слепой выборки: до закрытия консоль не показывала
--                      вердикт агента и анализ модели, ответ человека независим от них;
--   labeled_by_human — метку поставил человек. Автозакрытия (kind auto_close) пишут
--                      статус closed так же, как человек; выгрузка меток берёт только эти.
-- Старые события получают пустые значения: восстановить ответ задним числом нельзя.
ALTER TABLE argus.incident_state_events
    ADD COLUMN IF NOT EXISTS disposition LowCardinality(String) DEFAULT '',
    ADD COLUMN IF NOT EXISTS escalate Nullable(Bool),
    ADD COLUMN IF NOT EXISTS severity_correct Nullable(Bool),
    ADD COLUMN IF NOT EXISTS ops_cause LowCardinality(String) DEFAULT '',
    ADD COLUMN IF NOT EXISTS ops_action LowCardinality(String) DEFAULT '',
    ADD COLUMN IF NOT EXISTS blind Bool DEFAULT false,
    ADD COLUMN IF NOT EXISTS labeled_by_human Bool DEFAULT false;
