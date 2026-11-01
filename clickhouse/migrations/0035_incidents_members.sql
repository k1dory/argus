-- Адреса инцидента, склеенного по подсети (правила с collapse, сканы снаружи):
-- JSON-массив {ip, first, last, events, rules} строкой и сколько адресов не
-- поместилось в список. Движок восстанавливает их после рестарта вместе с
-- group_key, консоль показывает в карточке со статусом блокировки по адресу.
-- В incidents_current не выводятся — читаются из incidents.
ALTER TABLE argus.incidents ADD COLUMN IF NOT EXISTS members String DEFAULT '';
ALTER TABLE argus.incidents ADD COLUMN IF NOT EXISTS members_dropped UInt32 DEFAULT 0;
-- Признак склеенного инцидента: по нему, а не по виду group_key (его значение у
-- обычного правила с group_by приходит из данных события), движок выбирает путь.
ALTER TABLE argus.incidents ADD COLUMN IF NOT EXISTS collapsed UInt8 DEFAULT 0;
