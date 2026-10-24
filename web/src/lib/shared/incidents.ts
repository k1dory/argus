export const INCIDENT_STATUSES = {
  new: "новый",
  escalated: "эскалация",
  in_progress: "в работе",
  waiting_owner: "ждёт владельца",
  observing: "наблюдение",
  closed: "закрыт",
  false_positive: "ложное",
} as const;
export type IncidentStatus = keyof typeof INCIDENT_STATUSES;
/** Проверка статуса из формы/URL. Не `in`: он пропускает toString/constructor
 *  из прототипа, и «статус» уехал бы в SQL-параметр. */
export function isIncidentStatus(x: unknown): x is IncidentStatus {
  return typeof x === "string" && Object.hasOwn(INCIDENT_STATUSES, x);
}

/** Поля, по которым можно завести исключение из правила. Источник правды —
 *  движок: whitelist в eval.go и GET /rules/exception_fields; список здесь
 *  обязан с ним совпадать, иначе исключение молча не применится. */
export const EXCEPTION_FIELDS = ["actor.name", "src.ip", "node", "object", "dst.ip"] as const;

export type Role = "viewer" | "analyst" | "admin";
export const ROLE_RANK: Record<Role, number> = { viewer: 0, analyst: 1, admin: 2 };
export const ROLE_LABELS: Record<Role, string> = { viewer: "наблюдатель", analyst: "аналитик", admin: "администратор" };
export function isRole(x: unknown): x is Role {
  return x === "viewer" || x === "analyst" || x === "admin";
}

/** Состояние вердикта аналитика — вместо тернарных пирамид в JSX. */
export type VerdictLike = { error?: string; shown?: number } | null | undefined;
export type VerdictState = "missing" | "error" | "hidden" | "shown";
export function verdictState(v: VerdictLike): VerdictState {
  if (!v) return "missing";
  if (v.error) return "error";
  return v.shown === 1 ? "shown" : "hidden";
}

/** Редакции по пиковому EPS — таблица вместо вложенных тернарников. */
export const EDITIONS: { max: number; label: string }[] = [
  { max: 5000, label: "Пилот (до 5 000 EPS)" },
  { max: 25000, label: "Базовая (до 25 000 EPS)" },
  { max: 120000, label: "Закрытый контур (до 120 000 EPS)" },
  { max: Infinity, label: "Своя сборка" },
];
export const editionFor = (eps: number): string => EDITIONS.find((e) => eps <= e.max)!.label;
