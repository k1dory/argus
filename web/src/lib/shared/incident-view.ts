// Представление инцидента для списка и карточки: срочность строки, ATT&CK из
// тегов в любом из принятых форматов, срок реакции человеческим языком,
// главное действие по состоянию. Чистые функции, без React и запросов.
import { reactionDeadline } from "./incident-sla";
import { toDate } from "./time";

const FINAL = new Set(["closed", "false_positive"]);
export const isFinalStatus = (status: string): boolean => FINAL.has(status);

/**
 * Техники ATT&CK из тегов правила. Правила пишут их по-разному: `attack.t1003`,
 * `attack.T1003.001`, просто `T1003` или `t1110` — все дают «T1003». Порядок
 * тегов сохраняется, повторы убираются.
 */
export function incidentTechniques(tags: readonly string[]): string[] {
  const out: string[] = [];
  for (const tag of tags) {
    const m = /^(?:attack\.)?(t\d{4}(?:\.\d{3})?)$/i.exec(tag.trim());
    const id = m?.[1].toUpperCase();
    if (id && !out.includes(id)) out.push(id);
  }
  return out;
}

/** Теги без техник ATT&CK (их показывает своя строка) — чтобы не дублировать. */
export function plainTags(tags: readonly string[]): string[] {
  return tags.filter((t) => !/^(?:attack\.)?t\d{4}(?:\.\d{3})?$/i.test(t.trim()));
}

/** Ссылка на технику в матрице ATT&CK: T1003.001 → /techniques/T1003/001/. */
export const attackHref = (id: string): string => `https://attack.mitre.org/techniques/${id.replace(".", "/")}/`;

/** Длительность «на сколько»: 40 с, 15 мин, 23 ч, 3 дн. */
export function formatSpan(ms: number): string {
  const s = Math.max(0, Math.round(ms / 1000));
  if (s < 60) return `${s} с`;
  if (s < 3600) return `${Math.floor(s / 60)} мин`;
  if (s < 86400) return `${Math.floor(s / 3600)} ч`;
  return `${Math.floor(s / 86400)} дн`;
}

/** Склонение: plural(3, ["инцидент", "инцидента", "инцидентов"]) → «инцидента». */
export function plural(n: number, forms: readonly [string, string, string]): string {
  const a = Math.abs(n) % 100;
  const b = a % 10;
  if (a > 10 && a < 20) return forms[2];
  if (b === 1) return forms[0];
  if (b >= 2 && b <= 4) return forms[1];
  return forms[2];
}

type Row = { created_at: string; level: string; status: string };

/** На сколько просрочена первичная реакция (только «новый»); null — не просрочена. */
export function overdueMs(row: Row, now: Date = new Date()): number | null {
  if (row.status !== "new") return null;
  const deadline = reactionDeadline(row.created_at, row.level);
  if (!deadline) return null;
  const late = now.getTime() - deadline.getTime();
  return late > 0 ? late : null;
}

/**
 * Срочность строки очереди — тот же порядок, что ORDER BY списка
 * (lib/argus-queries PRIORITY_ORDER): overdue — реакция просрочена;
 * urgent — открытый критический или высокий; normal — остальное.
 */
export function incidentUrgency(row: Row, now: Date = new Date()): "overdue" | "urgent" | "normal" {
  if (overdueMs(row, now) !== null) return "overdue";
  if (!isFinalStatus(row.status) && (row.level === "critical" || row.level === "high")) return "urgent";
  return "normal";
}

export type ReactionView = { text: string; tone: "err" | "warn" | "ok" | "muted" };

/**
 * Строка SLA карточки. Взятие в работу и есть первая реакция: время — по
 * первому take в истории. Если инцидент уже в работе, а записи take нет
 * (старые или импортированные данные), это «нет данных», а не «реакции не было».
 */
export function reactionView(
  inc: { created_at: string; level: string; status: string; owner: string },
  takenAt: string | null,
  now: Date = new Date(),
  fmt: (d: Date | string) => string = (d) => String(d),
): ReactionView | null {
  const deadline = reactionDeadline(inc.created_at, inc.level);
  if (!deadline) return null;
  const due = `Реакция до ${fmt(deadline)}`;
  const taken = takenAt ? toDate(takenAt) : null;
  if (taken) {
    const late = taken.getTime() - deadline.getTime();
    const who = inc.owner ? ` у ${inc.owner}` : "";
    const head = isFinalStatus(inc.status) ? `Взят в работу ${fmt(taken)}` : `В работе${who} с ${fmt(taken)}`;
    return late > 0
      ? { text: `${head} — реакция позже срока на ${formatSpan(late)}`, tone: "warn" }
      : { text: `${head} — в срок`, tone: "ok" };
  }
  if (inc.status === "new") {
    const late = now.getTime() - deadline.getTime();
    return late > 0
      ? { text: `${due} — просрочено на ${formatSpan(late)}`, tone: "err" }
      : { text: `${due} — осталось ${formatSpan(-late)}`, tone: "warn" };
  }
  if (isFinalStatus(inc.status)) return { text: "Время взятия в работу не записано", tone: "muted" };
  // В работе, но take не записан: просрочку утверждать нельзя — сказать честно.
  const who = inc.owner ? `В работе у ${inc.owner}` : "В работе";
  return { text: `${who} · время взятия не записано, срок реакции был до ${fmt(deadline)}`, tone: "muted" };
}

/** Главное действие карточки по состоянию и роли. */
export type IncidentNextAction = "take" | "finish" | null;

export function nextAction(inc: { status: string; owner: string }, user: string, canEdit: boolean): IncidentNextAction {
  if (!canEdit || isFinalStatus(inc.status)) return null;
  const mine = inc.owner === user;
  if (!inc.owner || (mine && (inc.status === "new" || inc.status === "waiting_owner"))) return "take";
  if (mine) return "finish";
  return null;
}

/** Человеческие подписи переходов истории (kind из incident_state_events). */
export function changeVerb(kind: string, status: string): string {
  if (kind === "take") return "взял в работу";
  if (kind === "assign") return "назначил";
  if (kind === "auto_close") return "закрыто автоматически";
  if (status === "false_positive") return "закрыл как ложное";
  if (status === "closed") return "закрыл";
  if (status === "escalated") return "эскалировал";
  if (status === "observing") return "перевёл в наблюдение";
  if (status === "in_progress") return "вернул в работу";
  return "изменил статус";
}

/** Момент для людей, UTC: «сегодня, 13:09», «вчера, 13:09», «26 ноя, 13:09» (другой год — с годом). */
export function formatWhen(value: string | Date | null | undefined, now: Date = new Date()): string {
  const d = toDate(value);
  if (!d) return "—";
  const hm = `${String(d.getUTCHours()).padStart(2, "0")}:${String(d.getUTCMinutes()).padStart(2, "0")}`;
  const day = Math.floor(d.getTime() / 86_400_000);
  const today = Math.floor(now.getTime() / 86_400_000);
  if (day === today) return `сегодня, ${hm}`;
  if (day === today - 1) return `вчера, ${hm}`;
  const months = ["янв", "фев", "мар", "апр", "мая", "июн", "июл", "авг", "сен", "окт", "ноя", "дек"];
  const year = d.getUTCFullYear() === now.getUTCFullYear() ? "" : ` ${d.getUTCFullYear()}`;
  return `${d.getUTCDate()} ${months[d.getUTCMonth()]}${year}, ${hm}`;
}
