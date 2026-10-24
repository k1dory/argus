-- Журнал реагирования: индексы для карточки инцидента и поиска по адресу;
-- console_settings — миллисекунды в версии, чтобы два переключения в одну
-- секунду не давали ничью в argMax (таблица новая, данных в ней нет).
ALTER TABLE argus.response_log ADD INDEX IF NOT EXISTS idx_incident incident_id TYPE bloom_filter GRANULARITY 4;
ALTER TABLE argus.response_log ADD INDEX IF NOT EXISTS idx_ip ip TYPE bloom_filter GRANULARITY 4;

DROP TABLE IF EXISTS argus.console_settings;
CREATE TABLE argus.console_settings
(
    key        String,
    value      String,
    updated_at DateTime64(3) DEFAULT now64(3),
    updated_by String
)
ENGINE = ReplacingMergeTree(updated_at)
ORDER BY key;
