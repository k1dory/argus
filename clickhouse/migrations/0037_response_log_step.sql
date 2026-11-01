-- Шаг автомата автоблокировки в response_log (engine/cmd/engine/respond.go):
-- reserve — запись вперёд перед вызовом исполнителей; blocked | noop | simulated |
-- failed | exhausted | capped | refused | ids — итог попытки. После рестарта движок
-- восстанавливает решение по ключу incident_id|ip по последней строке с шагом и
-- место в потолке блокировок — по её времени. Старые строки — с пустым шагом.
ALTER TABLE argus.response_log ADD COLUMN IF NOT EXISTS step LowCardinality(String) DEFAULT '';
