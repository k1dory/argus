-- Ключ явного group_by правила (node, object …) в инциденте: реестр движка
-- различает по нему инциденты одного правила, субъекта и узла (второй диск
-- того же NAS — свой инцидент и своё уведомление) и восстанавливает его после
-- рестарта. В incidents_current не выводится — движок читает его из incidents.
ALTER TABLE argus.incidents ADD COLUMN IF NOT EXISTS group_key String DEFAULT '';
