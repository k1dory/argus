-- 0023: числовое измерение в единой схеме события.
-- value — число (заполненность диска, температура, длина очереди), unit — его
-- подпись (percent, bytes, celsius). Правила ops сравнивают value теми же
-- операторами ('>= 90'), что и поля безопасности, поэтому мониторинг
-- инфраструктуры пишется тем же YAML, что и детекты.
-- Идемпотентно: IF NOT EXISTS, повторный прогон ничего не ломает.
-- mv_alerts_to_events (0005) подставляет колонки по именам (TO argus.events),
-- новые колонки берут DEFAULT — представление менять не нужно.
ALTER TABLE argus.events ADD COLUMN IF NOT EXISTS value Float64 DEFAULT 0 AFTER packets;
ALTER TABLE argus.events ADD COLUMN IF NOT EXISTS unit LowCardinality(String) DEFAULT '' AFTER value;
