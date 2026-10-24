-- Единая схема события для всех источников (NGFW, EDR, k8s, CI/CD, NetFlow,
-- syslog, Wazuh): субъект (actor), объект (object), действие (action), узел
-- (node), сеанс (session). Правило пишется один раз поверх любого вендора.
CREATE TABLE IF NOT EXISTS argus.events
(
    ts           DateTime64(3, 'UTC'),
    received_at  DateTime DEFAULT now(),
    source       LowCardinality(String),   -- ngfw.checkpoint, edr.kaspersky, k8s.audit ...
    source_class LowCardinality(String),   -- ngfw | edr | wazuh | cicd | k8s | netflow | syslog
    vendor       LowCardinality(String),
    product      LowCardinality(String),
    action       LowCardinality(String),   -- session.allow, process.create, rbac.change, flow ...
    outcome      LowCardinality(String),   -- allow | deny | success | failure | unknown
    severity     UInt8,                    -- 0..10
    actor_name   String,
    actor_kind   LowCardinality(String),   -- user | service | system | unknown
    object       String,
    node         String,
    session_id   String,
    src_ip       String,
    src_port     UInt16,
    dst_ip       String,
    dst_port     UInt16,
    proto        LowCardinality(String),
    bytes        UInt64,
    packets      UInt64,
    pii          UInt8,                    -- событие содержит ПДн (источник или детектор)
    attrs        Map(LowCardinality(String), String),
    raw          String CODEC(ZSTD(3))
)
ENGINE = MergeTree
PARTITION BY toYYYYMM(ts)
ORDER BY (ts, source_class, source)
TTL toDateTime(ts) + INTERVAL 180 DAY;

-- Алерты Wazuh — тоже события общей схемы: движок корреляции видит их
-- рядом с NGFW и k8s без второго пути чтения.
CREATE MATERIALIZED VIEW IF NOT EXISTS argus.mv_alerts_to_events
TO argus.events
AS SELECT
    timestamp                                   AS ts,
    'wazuh.agents'                              AS source,
    'wazuh'                                     AS source_class,
    'Wazuh'                                     AS vendor,
    decoder_name                                AS product,
    concat('rule.', toString(rule_id))          AS action,
    'unknown'                                   AS outcome,
    least(rule_level, 10)                       AS severity,
    ''                                          AS actor_name,
    'unknown'                                   AS actor_kind,
    rule_description                            AS object,
    agent_name                                  AS node,
    ''                                          AS session_id,
    srcip                                       AS src_ip,
    toUInt16(0)                                 AS src_port,
    agent_ip                                    AS dst_ip,
    toUInt16(0)                                 AS dst_port,
    ''                                          AS proto,
    toUInt64(0)                                 AS bytes,
    toUInt64(0)                                 AS packets,
    toUInt8(0)                                  AS pii,
    map('rule_groups', arrayStringConcat(rule_groups, ','),
        'mitre', arrayStringConcat(mitre_ids, ','),
        'location', location)                   AS attrs,
    raw                                         AS raw
FROM argus.wazuh_alerts;

-- Инциденты: последняя версия строки побеждает (смена статуса = новая строка).
CREATE TABLE IF NOT EXISTS argus.incidents
(
    incident_id  String,                   -- INC-8841
    updated_at   DateTime,
    created_at   DateTime,
    rule_id      String,
    rule_title   String,
    level        LowCardinality(String),   -- low | medium | high | critical
    tags         Array(String),
    status       LowCardinality(String),   -- new | escalated | in_progress | waiting_owner | observing | closed | false_positive
    owner        String,
    note         String,
    actor_name   String,
    node         String,
    sources      Array(String),
    event_count  UInt32,
    first_ts     DateTime64(3, 'UTC'),
    last_ts      DateTime64(3, 'UTC'),
    pii          UInt8,
    chain        Array(String)             -- «ts  source  node  action  detail»
)
ENGINE = ReplacingMergeTree(updated_at)
ORDER BY incident_id;

-- Вердикт LLM-аналитика: строгая схема ответа, порог уверенности.
CREATE TABLE IF NOT EXISTS argus.incident_verdicts
(
    incident_id  String,
    evaluated_at DateTime,
    profile      LowCardinality(String),   -- on-prem-strict | cloud-fast | mock
    model        String,
    summary_ru   String,
    evidence     Array(String),
    first_action String,
    confidence   Float32,
    shown        UInt8,                    -- 0 — ниже порога, дежурному не показан
    tokens       UInt32,
    latency_ms   UInt32,
    error        String
)
ENGINE = ReplacingMergeTree(evaluated_at)
ORDER BY incident_id;

-- Живость коллекторов: heartbeat раз в минуту даже без событий.
CREATE TABLE IF NOT EXISTS argus.collector_health
(
    source     String,
    listener   LowCardinality(String),
    seen_at    DateTime,
    events_1m  UInt32
)
ENGINE = ReplacingMergeTree(seen_at)
ORDER BY source;
