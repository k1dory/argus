-- Движок читает хвост событий страницами по received_at (курсор), а таблица упорядочена
-- по ts: без индекса каждая страница сканировала всю месячную партицию (на стенде —
-- 9,5 млн строк и 4,7 с на страницу из 50 тыс.; первый опрос после рестарта не
-- заканчивался). received_at растёт вместе с порядком вставки, поэтому minmax-индекс
-- отсекает почти все гранулы. MATERIALIZE — мутация по существующим партам (на 10 млн
-- строк — секунды), новые парты индексируются при вставке. Идемпотентно.
ALTER TABLE argus.events ADD INDEX IF NOT EXISTS idx_received_at received_at TYPE minmax GRANULARITY 4;
ALTER TABLE argus.events MATERIALIZE INDEX idx_received_at;
