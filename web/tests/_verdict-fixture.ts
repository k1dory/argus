// Валидный вердикт argus-triage/v3 для инцидента INC-7 из тестов сессий разбора.
export const VERDICT_OK = {
  schema: "argus-triage/v3",
  incident_id: "INC-7",
  level: "high",
  rule_id: "a41c-cicd-007",
  verdict: "true_positive",
  confidence: "high",
  human_needed: true,
  human_reason: "утечка секрета требует ротации и проверки использования",
  summary: "Сборка CI вывела значение REGISTRY_TOKEN в журнал, секрет считается скомпрометированным.",
  subject: { kind: "service_account", display: "project_7_bot" },
  evidence: [
    {
      ts: "2026-10-12 04:01:38", source: "gitlab.ci", fact: "строка журнала сборки содержит значение секрета",
      provenance: "event_other_source", attacker_control: "low", direction: "attack", refs: ["card", "ev-1"],
    },
  ],
  gaps: ["нет подтверждения использования секрета извне"],
  related: [{ incident_id: "INC-5", relation: "same_subject", note: "тот же бот неделей раньше" }],
  recommendation: {
    console_status: "escalated", status_reason: "секрет в журнале сборки, нужна ротация",
    actions: [{ action: "revoke_secret", target: "subject" }], exception: null,
  },
  injection_suspected: false,
  injection_reason: null,
  injection_fields: [],
  damaged_values: [],
  engine_verdict: { used: false, disagreement: "" },
  pii_seen: false,
  behavior_assessment: "attack",
};

/** Копия с заменой полей верхнего уровня. */
export const verdictWith = (patch: Record<string, unknown>): Record<string, unknown> => ({ ...structuredClone(VERDICT_OK), ...patch });
