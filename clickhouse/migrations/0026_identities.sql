-- Паспорт субъекта: персоны и их алиасы во времени. Паспорт — представление
-- над журналом argus.events, а не отдельная база: события остаются как есть,
-- а эти две таблицы говорят, какой actor_name / src_ip / node в какой период
-- принадлежал какому человеку или сервису. Алиас действует на событие, если
-- valid_from <= ts AND (valid_to IS NULL OR ts < valid_to).
-- Источники алиасов: identities.yml движка (source = yaml), API консоли
-- (source = api) и события identity.alias любого экспортера
-- (source = event:<source события>). Снимок пиров VPN раз в пять минут — это
-- повтор того же события: ReplacingMergeTree схлопывает версии по updated_at.
-- Чтение «последней версии» — argMax(..., updated_at) с deleted = 0; удаление
-- — запись той же строки с deleted = 1 (ключ ORDER BY не меняется).
-- Значения нормализованы на записи: email/login/host — нижний регистр, ip —
-- каноническая форма адреса. person_id — slug вида i.petrov или uuid.
-- TTL нет: история принадлежности адресов — часть журнала.
CREATE TABLE IF NOT EXISTS argus.identities
(
    person_id  String,                                     -- стабильный id: slug (i.petrov) или uuid; задаёт источник
    display    String,
    kind       LowCardinality(String) DEFAULT 'person',    -- person | service
    team       String,
    note       String,
    updated_at DateTime64(3, 'UTC'),
    deleted    UInt8 DEFAULT 0
)
ENGINE = ReplacingMergeTree(updated_at)
ORDER BY person_id;

CREATE TABLE IF NOT EXISTS argus.identity_aliases
(
    person_id   String,
    alias_kind  LowCardinality(String),                    -- email | login | uid | ip | host | sid | peer
    alias_value String,                                    -- нормализовано: нижний регистр для email/login/host
    valid_from  DateTime64(3, 'UTC'),
    valid_to    Nullable(DateTime64(3, 'UTC')),            -- NULL = действует
    source      LowCardinality(String),                    -- yaml | api | event:<source события>
    confidence  Float32 DEFAULT 1,
    note        String,
    updated_at  DateTime64(3, 'UTC'),
    deleted     UInt8 DEFAULT 0
)
ENGINE = ReplacingMergeTree(updated_at)
ORDER BY (alias_kind, alias_value, valid_from, person_id);

-- Паспорт читает журнал по субъекту и адресу источника за окно до 30 дней.
-- Индексы действуют для новых партов; старые достраиваются вручную (тяжёлая
-- операция, по желанию): ALTER TABLE argus.events MATERIALIZE INDEX idx_actor;
ALTER TABLE argus.events ADD INDEX IF NOT EXISTS idx_actor actor_name TYPE bloom_filter GRANULARITY 4;
ALTER TABLE argus.events ADD INDEX IF NOT EXISTS idx_src_ip src_ip TYPE bloom_filter GRANULARITY 4;
