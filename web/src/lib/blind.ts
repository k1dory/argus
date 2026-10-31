import "server-only";
import crypto from "node:crypto";

/** Доля инцидентов, разбираемых вслепую. Та же константа и та же функция — в
 *  движке (engine/cmd/engine/labels.go, blindIncident): он и записывает признак
 *  blind при закрытии, консоль лишь скрывает подсказки. */
export const BLIND_PERCENT = 25;

/** Слепая выборка: первые два байта SHA-256 от incident_id по модулю 100 меньше
 *  BLIND_PERCENT. Детерминирована и не зависит от правила, уровня и времени. */
export function isBlindIncident(id: string): boolean {
  return crypto.createHash("sha256").update(id).digest().readUInt16BE(0) % 100 < BLIND_PERCENT;
}

/** Скрыть вердикт агента и анализ модели: слепой инцидент, пока он не завершён. */
export function hideVerdicts(inc: { incident_id: string; status: string }): boolean {
  return inc.status !== "closed" && inc.status !== "false_positive" && isBlindIncident(inc.incident_id);
}
