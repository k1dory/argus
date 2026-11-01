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

/** Копии вердикта агента вне самого вердикта: triage/verdicts кладёт его Markdown
 *  в комментарий от agent:<имя>, а категорию и уверенность — в аудит triage.verdict*.
 *  Пока hideVerdicts, их отдавать нельзя ни в JSON, ни в Markdown, ни в props страницы. */
export function blindComments<T extends { author: string }>(comments: T[]): T[] {
  return comments.filter((c) => !c.author.startsWith("agent:"));
}

export function blindActions<T extends { action?: unknown }>(actions: T[]): T[] {
  return actions.filter((a) => !String(a.action ?? "").startsWith("triage.verdict"));
}

/** Общий журнал (/settings): записи triage.verdict* по слепым незавершённым инцидентам
 *  убираются. Статус спрашивается только у слепых целей — их четверть, а в хвосте
 *  журнала единицы. Статус не прочитался — запись скрывается (безопасная сторона). */
export async function blindAuditTail<T extends { action: string; target: string }>(
  rows: T[], statusOf: (id: string) => Promise<{ incident_id: string; status: string } | null>,
): Promise<T[]> {
  const ids = [...new Set(rows.filter((r) => r.action.startsWith("triage.verdict") && isBlindIncident(r.target)).map((r) => r.target))];
  if (!ids.length) return rows;
  const hidden = new Set<string>();
  await Promise.all(ids.map(async (id) => {
    const inc = await statusOf(id).catch(() => null);
    if (!inc || hideVerdicts(inc)) hidden.add(id);
  }));
  return rows.filter((r) => !(r.action.startsWith("triage.verdict") && hidden.has(r.target)));
}
