-- Последнее событие каждого источника — агрегатной проекцией events: страница
-- «Источники» и GET /api/sources находят замолчавшие источники, включая тех, кто
-- пишет в events мимо коллектора (телеметрия движка argus.system) и потому не имеет
-- heartbeat в collector_health_log. Запрос `SELECT source, any(source_class),
-- max(received_at) FROM events GROUP BY source` читает проекцию (по строке на
-- источник в каждом парте — на стенде с 4 млн событий 1,5 тыс. строк вместо
-- 4 млн), а не сырые события. Проекция пересобирается при слияниях и мутациях
-- (ALTER TABLE … DELETE её поддерживает). MATERIALIZE — мутация по существующим
-- партам: читает три колонки, на 100+ млн строк — минуты, идёт в фоне; пока она не
-- закончилась, консоль строит список по heartbeat (force_optimize_projection).
-- Идемпотентно.
ALTER TABLE argus.events ADD PROJECTION IF NOT EXISTS p_source_last
(
    SELECT source, any(source_class), max(received_at)
    GROUP BY source
);
ALTER TABLE argus.events MATERIALIZE PROJECTION p_source_last;
