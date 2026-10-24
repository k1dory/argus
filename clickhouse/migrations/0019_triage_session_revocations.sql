-- Отозванные сессии разбора (токены triage-session): консоль сверяет jti с
-- этим списком, поэтому отзыв переживает рестарт web. Токен живёт не больше
-- 60 минут — запись нужна столько же, TTL с запасом в час.
CREATE TABLE IF NOT EXISTS argus.triage_session_revocations
(
    session_id  String,
    incident_id String,
    revoked_at  DateTime DEFAULT now(),
    expires_at  DateTime
)
ENGINE = ReplacingMergeTree(revoked_at)
ORDER BY session_id
TTL expires_at + INTERVAL 1 HOUR;
