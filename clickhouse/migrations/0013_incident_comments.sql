-- Комментарии расследования не являются версиями инцидента: они сохраняются
-- независимо от ReplacingMergeTree и не меняют статус/ответственного.
CREATE TABLE IF NOT EXISTS argus.incident_comments
(
    comment_id  UUID,
    incident_id String,
    created_at  DateTime64(3, 'UTC'),
    author      String,
    body        String
)
ENGINE = MergeTree
ORDER BY (incident_id, created_at, comment_id);
