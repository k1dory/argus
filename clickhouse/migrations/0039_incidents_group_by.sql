-- group_by правила, по которому посчитан group_key инцидента (engine/internal/incidents):
-- group_by_previous отличает по нему инцидент, заведённый до смены group_by, от
-- заведённого или уже перенесённого после — и после рестарта движка. Пусто — строка
-- до этой миграции: считается заведённой по прежнему group_by.
ALTER TABLE argus.incidents ADD COLUMN IF NOT EXISTS group_by String DEFAULT '';
