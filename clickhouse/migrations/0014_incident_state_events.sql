-- Человеческий workflow не хранится версиями incidents с секундным
-- updated_at: переходы append-only и получают монотонный revision от
-- единственного движка. Установка с несколькими engine требует отдельного
-- транзакционного координатора до включения второй реплики.
CREATE TABLE IF NOT EXISTS argus.incident_state_events
(
    event_id    UUID,
    incident_id String,
    revision    UInt64,
    changed_at  DateTime64(3, 'UTC'),
    actor       String,
    kind        LowCardinality(String),
    status      LowCardinality(String),
    owner       String
)
ENGINE = MergeTree
ORDER BY (incident_id, revision, event_id);

CREATE VIEW IF NOT EXISTS argus.incidents_current AS
WITH base AS
(
    SELECT incident_id,
           argMax(updated_at, (updated_at, event_count, last_ts)) AS det_updated_at,
           argMax(created_at, (updated_at, event_count, last_ts)) AS det_created_at,
           argMax(rule_id, (updated_at, event_count, last_ts)) AS det_rule_id,
           argMax(rule_title, (updated_at, event_count, last_ts)) AS det_rule_title,
           argMax(level, (updated_at, event_count, last_ts)) AS det_level,
           argMax(tags, (updated_at, event_count, last_ts)) AS det_tags,
           argMax(status, (updated_at, event_count, last_ts)) AS base_status,
           argMax(owner, (updated_at, event_count, last_ts)) AS base_owner,
           argMax(note, (updated_at, event_count, last_ts)) AS det_note,
           argMax(actor_name, (updated_at, event_count, last_ts)) AS det_actor_name,
           argMax(node, (updated_at, event_count, last_ts)) AS det_node,
           argMax(sources, (updated_at, event_count, last_ts)) AS det_sources,
           argMax(event_count, (updated_at, event_count, last_ts)) AS det_event_count,
           argMax(first_ts, (updated_at, event_count, last_ts)) AS det_first_ts,
           argMax(last_ts, (updated_at, event_count, last_ts)) AS det_last_ts,
           argMax(pii, (updated_at, event_count, last_ts)) AS det_pii,
           argMax(chain, (updated_at, event_count, last_ts)) AS det_chain,
           argMax(enrichment, (updated_at, event_count, last_ts)) AS det_enrichment,
           argMax(similar, (updated_at, event_count, last_ts)) AS det_similar
    FROM argus.incidents GROUP BY incident_id
), changes AS
(
    SELECT incident_id, max(revision) AS event_revision,
           argMax(changed_at, revision) AS event_changed_at,
           argMax(status, revision) AS event_status,
           argMax(owner, revision) AS event_owner
    FROM argus.incident_state_events GROUP BY incident_id
)
SELECT base.incident_id,
       greatest(toDateTime64(base.det_updated_at, 3, 'UTC'), changes.event_changed_at) AS updated_at,
       base.det_created_at AS created_at, base.det_rule_id AS rule_id,
       base.det_rule_title AS rule_title, base.det_level AS level, base.det_tags AS tags,
       if(base.base_status IN ('closed', 'false_positive'), base.base_status,
          if(changes.event_revision = 0, base.base_status, changes.event_status)) AS status,
       if(base.base_status IN ('closed', 'false_positive') OR changes.event_revision = 0,
          base.base_owner, changes.event_owner) AS owner,
       base.det_note AS note, base.det_actor_name AS actor_name, base.det_node AS node,
       base.det_sources AS sources, base.det_event_count AS event_count,
       base.det_first_ts AS first_ts, base.det_last_ts AS last_ts,
       base.det_pii AS pii, base.det_chain AS chain,
       base.det_enrichment AS enrichment, base.det_similar AS similar
FROM base LEFT JOIN changes USING incident_id;
