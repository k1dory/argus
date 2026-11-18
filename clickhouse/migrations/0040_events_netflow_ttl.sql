-- NetFlow — ~93 % строк argus.events (на argus1 ~35–40 млн в сутки), а правила по
-- нему смотрят в окна до часа. 180 дней flow-записей — основной объём таблицы;
-- держим их 30 дней, остальные классы — по-прежнему 180.
-- MODIFY TTL идемпотентен; materialize_ttl_after_modify (по умолчанию 1) запускает
-- фоновую мутацию, которая перепишет старые части: миграцию она не держит,
-- ход — в system.mutations.
ALTER TABLE argus.events
    MODIFY TTL
        toDateTime(ts) + INTERVAL 30 DAY DELETE WHERE source_class = 'netflow',
        toDateTime(ts) + INTERVAL 180 DAY DELETE;
