-- Обратная связь оператора и служебные таблицы движка.

-- Исключения из правил: «ложное срабатывание» из консоли становится
-- исключением, которое движок применяет к событиям (field = value).
CREATE TABLE IF NOT EXISTS argus.rule_exceptions
(
    rule_id     String,
    field       LowCardinality(String),   -- actor.name, src.ip, node, object ...
    value       String,
    reason      String,
    incident_id String,
    created_by  String,
    created_at  DateTime DEFAULT now(),
    active      UInt8 DEFAULT 1
)
ENGINE = ReplacingMergeTree(created_at)
ORDER BY (rule_id, field, value);

-- Журнал действий оператора в консоли: кто, что, когда.
CREATE TABLE IF NOT EXISTS argus.console_audit
(
    ts       DateTime DEFAULT now(),
    user     String,
    action   LowCardinality(String),   -- incident.status, rule.mute, wazuh.group.add ...
    target   String,
    detail   String
)
ENGINE = MergeTree
ORDER BY ts
TTL ts + INTERVAL 365 DAY;

-- Инциденты: обогащение и похожие закрытые инциденты (для аналитика).
ALTER TABLE argus.incidents ADD COLUMN IF NOT EXISTS enrichment Array(String) DEFAULT [];
ALTER TABLE argus.incidents ADD COLUMN IF NOT EXISTS similar Array(String) DEFAULT [];

-- Дедупликация повторно отправленных батчей шиппера: insert_deduplication_token
-- по содержимому батча + окно дедупликации на нереплицируемой таблице.
ALTER TABLE argus.wazuh_alerts MODIFY SETTING non_replicated_deduplication_window = 1000;
ALTER TABLE argus.events MODIFY SETTING non_replicated_deduplication_window = 1000;

-- Пользователи консоли (роли) живут в auth.json; лицензионный учёт — по
-- collector_health (пиковый EPS) и TTL таблиц.
