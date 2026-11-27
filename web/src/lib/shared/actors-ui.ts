// Подписи и правила интерфейса раздела «Субъекты» (список, «Кому принадлежит»,
// форма привязки): человеческие названия машинных значений, сортировка по риску,
// безопасное начало действия привязки. Без "use client" — читается и сервером, и формой.
import { CONFIRMED_NOTE_PREFIX, HOLD_NOTE_PREFIX, holdPolicy, isHeld, isIp, isPhone, type Alias, type AliasKind } from "./actors";

/* ===== Привязка алиаса: с какой даты ===== */

/** Сегодня по UTC в формате поля даты (YYYY-MM-DD): начало действия привязки по умолчанию. */
export function todayUtc(now: number = Date.now()): string {
  return new Date(now).toISOString().slice(0, 10);
}

/** Флажок формы «на всю историю»: без него пустая дата — ошибка, а не начало журнала. */
export const ALL_HISTORY_FIELD = "all_history";

export type BindFrom = { ok: true; from: string | null } | { ok: false; error: string };

/**
 * Начало действия привязки из формы. Пустая дата действует на всю историю
 * журнала (все прошлые события и инциденты с этим значением отойдут персоне),
 * поэтому принимается только с явным флажком; флажок главнее даты.
 */
export function bindFromInput(from: unknown, allHistory: unknown): BindFrom {
  if (allHistory === "1" || allHistory === "on" || allHistory === true) return { ok: true, from: null };
  const v = typeof from === "string" ? from.trim() : "";
  if (!v) return { ok: false, error: "Укажите, с какой даты действует привязка, или отметьте «на всю историю»" };
  return { ok: true, from: v };
}

/** Общие учётки: привязка такого значения к одному человеку почти всегда ошибка. */
const SHARED_ACCOUNTS = new Set(["root", "admin", "administrator", "administrators", "guest", "user", "test", "nobody", "system", "service", "hostgroup", "postgres", "www-data", "ubuntu", "debian", "centos", "ec2-user", "pi"]);

export const isSharedAccount = (value: string): boolean => SHARED_ACCOUNTS.has(value.trim().toLowerCase().replace(/^.*\\/, ""));

/** Предупреждение над кнопкой «Привязать»: адрес и хост бывают общими, root/admin — у всех. */
export function bindRisk(kind: AliasKind, value: string): string | null {
  if (isSharedAccount(value)) return `«${value.trim()}» — общая системная учётка: ей пользуются многие, и все её действия будут записаны на одного человека. Обычно её не привязывают.`;
  if (kind === "ip") return "IP-адрес часто общий (NAT, VPN, DHCP) и со временем переходит к другим. Ограничьте привязку датой начала.";
  if (kind === "host") return "Хостом могут пользоваться несколько человек: все события на нём будут записаны на одного.";
  return null;
}

/* ===== Откуда алиас и пометки ===== */

const SOURCE_LABELS: Record<string, string> = {
  yaml: "файл identities.yml",
  api: "вручную в консоли",
  console: "вручную в консоли",
};

/** Источник записи алиаса: yaml, api, event:<экспортёр>. */
export function aliasSourceLabel(source: string): string {
  const s = source.trim();
  if (SOURCE_LABELS[s]) return SOURCE_LABELS[s];
  if (s.startsWith("event:")) {
    const who = s.slice("event:".length);
    const names: Record<string, string> = { netbird: "NetBird", vpn: "VPN", idp: "входа в IdP", authentik: "Authentik" };
    return `событие ${names[who] ?? who}`;
  }
  return s || "—";
}

/** Пометка алиаса без служебных префиксов: удержание и подтверждение — по-человечески. */
export function aliasNoteLabel(a: Pick<Alias, "confidence" | "note">): string {
  if (isHeld(a)) {
    const p = holdPolicy(a);
    return p ? `политика «${p}»` : "";
  }
  if (a.note.startsWith(CONFIRMED_NOTE_PREFIX)) return `подтверждён вручную, политика «${a.note.slice(CONFIRMED_NOTE_PREFIX.length)}»`;
  if (a.note.startsWith(HOLD_NOTE_PREFIX)) return `политика «${a.note.slice(HOLD_NOTE_PREFIX.length)}»`;
  return a.note;
}

/* ===== «Где встречалось» ===== */

/** Строка «где встречалось» одной фразой: «Вход по SSH на bastion», «sudo на argus1». */
export function sightingTitle(r: { source: string; action: string; where: string; fails?: number; events?: number }): string {
  const a = r.action.toLowerCase();
  const s = r.source.toLowerCase();
  const on = r.where ? ` на ${r.where}` : "";
  const failed = (r.fails ?? 0) > 0 && (r.fails ?? 0) >= (r.events ?? Infinity);
  if (/logout|logoff|session\.close|disconnect/.test(a)) return `Выход${on}`;
  if (a.includes("sudo")) return `sudo${on}`;
  if (/(^|[._-])su($|[._-])/.test(a)) return `su${on}`;
  if (s.includes("vpn") || s.includes("netbird") || a.startsWith("vpn")) return `${failed ? "Неудачное подключение" : "Подключение"} к VPN${on}`;
  if (a.includes("ssh") || (a.startsWith("auth") && (s.includes("ssh") || s.includes("linux")))) return `${failed ? "Неудачный вход" : "Вход"} по SSH${on}`;
  if (a.startsWith("auth") || a.includes("login")) return `${failed ? "Неудачный вход" : "Вход"}${on || ` в ${r.source}`}`;
  if (a.startsWith("identity.")) return `Идентичность: ${r.action.slice("identity.".length)}`;
  return `${r.action}${on}`;
}

/* ===== Список: вкладки и порядок ===== */

export const PERSON_TABS = ["all", "incidents", "active", "service"] as const;
export type PersonTab = (typeof PERSON_TABS)[number];
export const PERSON_TAB_LABELS: Record<PersonTab, string> = { all: "Все", incidents: "С инцидентами", active: "Активные", service: "Служебные" };
export const parsePersonTab = (v: unknown): PersonTab => (PERSON_TABS as readonly string[]).includes(String(v ?? "")) ? (v as PersonTab) : "all";

type Ranked = { person_id: string; display: string; kind: string; events: number; incidents: number; last_ts: string | null };

export function matchesPersonTab(p: Ranked, tab: PersonTab): boolean {
  if (tab === "incidents") return p.incidents > 0;
  if (tab === "active") return p.events > 0;
  if (tab === "service") return p.kind === "service";
  return true;
}

/** Сначала риск: больше инцидентов, затем свежая активность, без активности — в конце, затем по имени. */
export function byRisk(a: Ranked, b: Ranked): number {
  if (a.incidents !== b.incidents) return b.incidents - a.incidents;
  if (a.last_ts !== b.last_ts) {
    if (!a.last_ts) return 1;
    if (!b.last_ts) return -1;
    return a.last_ts < b.last_ts ? 1 : -1;
  }
  return (a.display || a.person_id).localeCompare(b.display || b.person_id, "ru") || a.person_id.localeCompare(b.person_id);
}

/* ===== «Кому принадлежит»: подсказки ===== */

/** Вид алиаса по значению для формы привязки: IP, телефон, почта, иначе логин (поле видно — проверить). */
export function guessAliasKind(raw: string): AliasKind {
  if (isIp(raw)) return "ip";
  if (isPhone(raw)) return "phone";
  return raw.includes("@") ? "email" : "login";
}

/** Примеры поиска на пустом экране: что можно ввести. */
export const LOOKUP_EXAMPLES: { label: string; value: string }[] = [
  { label: "IP", value: "192.168.0.88" },
  { label: "почта", value: "user@example.com" },
  { label: "логин", value: "root" },
  { label: "телефон", value: "+79001234567" },
];
