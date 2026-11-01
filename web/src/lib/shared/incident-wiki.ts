import { INCIDENT_STATUSES, type IncidentStatus } from "./incidents";
import { closureLabelText, type ClosureLabelView } from "./closure-label";

export type WikiIncident = {
  incident_id: string; rule_title: string; rule_id: string; level: string;
  status: IncidentStatus; owner: string; created_at: string; note: string;
};
export type WikiVerdict = {
  summary_ru: string; shown: number; error: string; model: string; profile: string;
  evaluated_at: string; evidence: string[]; actions?: string[]; first_action: string;
  missing?: string; shown_reason?: string;
} | null;
export type WikiChange = {
  changed_at: string; actor: string; kind: string; status: IncidentStatus;
  owner: string; reason: string; revision: number;
  // Метка ответа (миграции 0033, 0036); старые события и автоматика — без неё.
} & ClosureLabelView;
export type WikiComment = { created_at: string; author: string; body: string };

export function closingEvent<T extends WikiChange>(status: IncidentStatus, changes: T[]): T | null {
  if (status !== "closed" && status !== "false_positive") return null;
  return changes.reduce<T | null>((latest, change) => {
    if (change.status !== status || (change.kind !== "status" && change.kind !== "auto_close")) return latest;
    return !latest || change.revision > latest.revision ? change : latest;
  }, null);
}

/** Значение из данных внутри Markdown: спецсимволы экранируются, переводы строк схлопываются. */
export function literal(value: string): string {
  return value.replace(/[\\`*_{}\[\]()#+.!|>~-]/g, "\\$&").replace(/\r?\n/g, " ");
}

/** Единый Markdown для карточки и скачиваемого файла; записи людей не переписываются моделью. */
export function incidentMarkdown(incident: WikiIncident, verdict: WikiVerdict, changes: WikiChange[], comments: WikiComment[], unavailable: { verdict?: boolean; history?: boolean; comments?: boolean; blind?: boolean } = {}): string {
  const closure = closingEvent(incident.status, changes);
  const lines = [
    `# ${literal(incident.incident_id)} — ${literal(incident.rule_title)}`,
    "",
    `- Статус: ${INCIDENT_STATUSES[incident.status]}`,
    `- Уровень: ${literal(incident.level)}`,
    `- Правило: ${literal(incident.rule_id)}`,
    `- Создан: ${literal(incident.created_at)} UTC`,
    `- Ответственный: ${literal(incident.owner || "не назначен")}`,
    "",
    "## Завершение",
    "",
  ];
  if (incident.status === "closed" || incident.status === "false_positive") {
    if (unavailable.history) lines.push("История завершения временно недоступна.");
    else
    lines.push(
      `- Кем: ${closure ? literal(closure.kind === "auto_close" ? "ARGUS (автоматически)" : closure.actor) : "не зафиксировано в истории"}`,
      `- Когда: ${closure ? literal(closure.changed_at) + " UTC" : "не зафиксировано в истории"}`,
      ...(closure && closureLabelText(closure) ? [`- Ответ: ${literal(closureLabelText(closure))}`] : []),
      `- Причина: ${closure?.reason ? literal(closure.reason) : "не зафиксирована"}`,
    );
  } else {
    lines.push("Инцидент ещё не завершён.");
  }
  lines.push("", "## Анализ модели", "");
  if (unavailable.blind) lines.push("Скрыт до завершения: инцидент разбирается вслепую.");
  else if (unavailable.verdict) lines.push("Анализ модели временно недоступен. Обновите карточку позже.");
  else if (!verdict) lines.push("Анализ ещё не готов.");
  else if (verdict.error) lines.push(`Анализ не выполнен: ${literal(verdict.error)}`);
  else if (verdict.shown !== 1) lines.push(`Анализ скрыт после проверки качества: ${literal(verdict.shown_reason || "нужна проверка аналитика")}`);
  else {
    lines.push(`Модель: ${literal(verdict.model || "не указана")} · профиль ${literal(verdict.profile)} · ${literal(verdict.evaluated_at)} UTC`, "", verdict.summary_ru, "");
    if (verdict.evidence.length) {
      lines.push("### Подтверждения", "", ...verdict.evidence.map((item) => `- ${literal(item)}`), "");
    }
    const actions = verdict.actions?.length ? verdict.actions : [verdict.first_action].filter(Boolean);
    if (actions.length) lines.push("### Рекомендации", "", ...actions.map((item, i) => `${i + 1}. ${literal(item)}`), "");
    if (verdict.missing) lines.push("### Недостающие данные", "", literal(verdict.missing), "");
  }
  lines.push("## Ход расследования", "");
  if (unavailable.history) lines.push("История изменений временно недоступна.", "");
  else if (!changes.length) lines.push("Переходов в журнале нет.", "");
  else lines.push(...changes.map((change) => `- ${literal(change.changed_at)} UTC · ${literal(change.actor)} · ${literal(change.kind)} · ${INCIDENT_STATUSES[change.status]}${change.reason ? ` · ${literal(change.reason)}` : ""}`), "");
  if (incident.note) lines.push("## Прежняя заметка / автоматика", "", incident.note, "");
  lines.push("## Записи команды", "");
  if (unavailable.comments) lines.push("Записи команды временно недоступны.", "");
  else if (!comments.length) lines.push("Записей пока нет.", "");
  else for (const comment of comments) {
    lines.push(`### ${literal(comment.author)} · ${literal(comment.created_at)} UTC`, "", comment.body, "");
  }
  return lines.join("\n").trimEnd() + "\n";
}
