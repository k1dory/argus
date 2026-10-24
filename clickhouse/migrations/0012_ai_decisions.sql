-- Separate the explanatory model's self-assessment from typed decision probabilities.
ALTER TABLE argus.incident_verdicts ADD COLUMN IF NOT EXISTS missing String DEFAULT '';
ALTER TABLE argus.incident_verdicts ADD COLUMN IF NOT EXISTS actions Array(String) DEFAULT [];
ALTER TABLE argus.incident_verdicts ADD COLUMN IF NOT EXISTS decision_json String DEFAULT '';
ALTER TABLE argus.incident_verdicts ADD COLUMN IF NOT EXISTS confidence_kind LowCardinality(String) DEFAULT 'self_reported';
