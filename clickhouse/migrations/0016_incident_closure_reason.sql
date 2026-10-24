-- Причина завершения хранится в том же неизменяемом событии, что автор и время.
-- Старые события получают пустую причину: её нельзя восстановить задним числом.
ALTER TABLE argus.incident_state_events ADD COLUMN IF NOT EXISTS reason String DEFAULT '';
