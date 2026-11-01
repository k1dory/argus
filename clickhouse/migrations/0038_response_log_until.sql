-- Срок исключения адреса из автоблокировки (engine/cmd/engine/respond_key.go):
-- строка step=exclude с пустым incident_id — оператор исключил адрес до until;
-- until не позже ts — отзыв исключения. После рестарта движок восстанавливает
-- исключения по последней строке exclude адреса за 30 дней. У остальных строк —
-- значение по умолчанию.
ALTER TABLE argus.response_log ADD COLUMN IF NOT EXISTS until DateTime DEFAULT toDateTime(0);
