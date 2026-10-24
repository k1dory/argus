-- Заглушённые правила консоли (борьба с шумом алертов): последняя запись
-- по rule_id побеждает (ReplacingMergeTree по updated_at), запросы консоли
-- исключают правила с muted = 1.
CREATE TABLE IF NOT EXISTS argus.console_rule_mutes
(
    rule_id    UInt32,
    muted      UInt8,
    updated_at DateTime DEFAULT now()
)
ENGINE = ReplacingMergeTree(updated_at)
ORDER BY rule_id;
