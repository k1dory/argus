-- Окна дедупликации вставок для таблиц, куда консоль пишет идемпотентно по
-- insert_deduplication_token: вердикт агента (ключ agent-verdict:<инцидент>:<сессия>)
-- и его комментарий (детерминированный comment_id по сессии). Без окна ClickHouse
-- игнорирует токен на нереплицируемых MergeTree, и параллельные повторы одной
-- сессии разбора снимались бы только чтением (LIMIT 1 BY), а не на записи.
-- Миграция идемпотентна: MODIFY SETTING повторяется без ошибки.
ALTER TABLE argus.agent_verdicts MODIFY SETTING non_replicated_deduplication_window = 1000000;
ALTER TABLE argus.incident_comments MODIFY SETTING non_replicated_deduplication_window = 1000000;
