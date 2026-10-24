-- ID задачи трекера в отметке доставки вебхука. Внешний агент разбора находит
-- инцидент по id задачи, а не по тексту: заголовок и описание может подменить
-- атакующий.
-- Пусто у целей без задач (HTTP — там ref = код ответа). Старые строки не
-- заполняются: по ref нельзя отличить id задачи от кода ответа HTTP-цели.
ALTER TABLE argus.webhook_deliveries ADD COLUMN IF NOT EXISTS task_id String DEFAULT '' AFTER ref;
ALTER TABLE argus.webhook_deliveries ADD INDEX IF NOT EXISTS idx_task_id task_id TYPE bloom_filter GRANULARITY 1;
