-- Метка закрытия по плану разметки (вики argus-laya-данные-и-разметка): только новые
-- колонки, прежние (0033) не меняются. severity_level — какой уровень правильный
-- (1–4: low, medium, high, critical); severity_correct из 0033 движок теперь вычисляет
-- из него и уровня правила. attack_tactic / attack_technique — shortname тактики и ID
-- техники ATT&CK Enterprise или «other», attack_version — версия справочника
-- (engine/internal/attack/enterprise.json). DevOps: ops_act_now — действовать сейчас,
-- ops_urgency — срочность 1–4; ops_cause (0033) получает словарь плана, ops_action
-- становится необязательным. Nullable — «нет ответа» отличим от ответа.
ALTER TABLE argus.incident_state_events
    ADD COLUMN IF NOT EXISTS severity_level Nullable(UInt8),
    ADD COLUMN IF NOT EXISTS attack_tactic LowCardinality(String) DEFAULT '',
    ADD COLUMN IF NOT EXISTS attack_technique LowCardinality(String) DEFAULT '',
    ADD COLUMN IF NOT EXISTS attack_version LowCardinality(String) DEFAULT '',
    ADD COLUMN IF NOT EXISTS ops_act_now Nullable(Bool),
    ADD COLUMN IF NOT EXISTS ops_urgency Nullable(UInt8);
