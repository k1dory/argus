// Лента активности субъекта: те же агрегаты, что у трассировки, но плоским
// списком «что произошло» — понятный заголовок, кто/откуда/что, время, отметка
// отказов и инцидентов. Сеть в ленту не идёт: это фон, а не поступки.
import type { ActorIncident, Alias, Section } from "./actors";
import { aliasMatches, tsMs } from "./actors";
import { LOGOUT_RE, spanLabel, spanEventsHref, type ActorTrace, type OwnerScope, type TraceAction, type TraceSpan } from "./actor-trace";

export const FEED_FILTERS = ["flagged", "all", "login", "host", "app", "change"] as const;
export type FeedFilter = (typeof FEED_FILTERS)[number];
export const FEED_FILTER_LABELS: Record<FeedFilter, string> = {
  flagged: "Отмеченные", all: "Все", login: "Входы", host: "Команды", app: "Приложения", change: "Изменения",
};
export const parseFeedFilter = (v: string | undefined | null): FeedFilter =>
  (FEED_FILTERS as readonly string[]).includes(v ?? "") ? (v as FeedFilter) : "all";

export type FeedKind = Exclude<Section, "network"> | "incident";

export type FeedItem = {
  key: string;
  kind: FeedKind;
  /** Последнее событие действия — по нему сортировка и время справа. */
  at: number;
  first: number;
  title: string;
  /** Полный заголовок, если в title цель сокращена (длинный URL). */
  titleFull?: string;
  /** Текстовая сводка строки: кто (если не основной алиас), откуда, детали, ×N. */
  meta: string[];
  /** Алиас, под которым действовали, — только если это не основной алиас субъекта. */
  actor?: string;
  /** Откуда: «с 10.8.0.5» / «после входа с 10.8.0.5». */
  from?: string;
  /** Команды/объекты действия (sudo, сеанс) — отдельной строкой. */
  details: string[];
  /** Исходное действие источника (pve.api.write) — для подсказки. */
  action?: string;
  count: number;
  fails: number;
  flagged: boolean;
  /** Пометка справа от заголовка: «отклонено», «2 из 3 отклонены», «инцидент». */
  badge?: string;
  href: string | null;
  incident?: ActorIncident;
};

/** Строк ленты: дальше — трассировка и журнал. */
export const FEED_MAX = 80;

const has = (a: string, ...parts: string[]) => parts.some((p) => a.includes(p));

/** Действия «прочего», которые на деле — изменения (запись через API, push). */
const CHANGE_ACTION_RE = /write|push|create|update|delete/i;

/** Раздел строки ленты: «прочее» с глаголом изменения — изменение. */
export function feedKind(section: Exclude<Section, "network">, action: string): Exclude<FeedKind, "incident"> {
  return section === "other" && CHANGE_ACTION_RE.test(action) ? "change" : section;
}

/** Длинный URL → «хост/…/последний-сегмент»; остальное без изменений. */
export function shortTarget(t: string, max = 60): string {
  if (t.length <= max || !/^https?:\/\//i.test(t)) return t;
  try {
    const u = new URL(t);
    const last = u.pathname.split("/").filter(Boolean).pop();
    return last ? `${u.host}/…/${last.length > 40 ? `${last.slice(0, 40)}…` : last}` : u.host;
  } catch {
    return `${t.slice(0, max)}…`;
  }
}

/** Человеческий заголовок по разделу, действию и цели — без знания вендоров. */
export function feedTitle(span: Pick<TraceSpan, "section" | "target" | "target_kind" | "dst_port" | "folded">, act: Pick<TraceAction, "action" | "count" | "fails">, short = false): string {
  const a = act.action.toLowerCase();
  const full = spanLabel(span);
  const t = short ? shortTarget(full) : full;
  const allFailed = act.fails > 0 && act.fails >= act.count;
  switch (span.section) {
    case "login": {
      if (LOGOUT_RE.test(a)) return `Выход${span.target_kind === "node" ? ` с ${t}` : ` из ${t}`}`;
      const how = has(a, "ssh") ? "по SSH " : "";
      const where = span.target_kind === "node" ? `на ${t}` : `в ${t}`;
      return `${allFailed ? "Неудачный вход" : "Вход"} ${how}${where}`.replace(/\s+/g, " ");
    }
    case "host":
      if (has(a, "sudo")) return `sudo на ${t}`;
      if (/(^|[._-])su($|[._-])/.test(a)) return `su на ${t}`;
      if (has(a, "session")) return `Сеанс на ${t}`;
      return `${act.action} на ${t}`;
    case "app":
      return `${allFailed ? "Отказ в доступе к" : "Доступ к"} ${t}`;
    case "change":
      if (a.startsWith("identity.")) return `Идентичность: ${act.action.slice("identity.".length) || act.action}`;
      if (has(a, "push")) return `Push в ${t}`;
      return `Изменение: ${t}`;
    default:
      if (CHANGE_ACTION_RE.test(a)) return has(a, "push") ? `Push в ${t}` : `Изменение: ${t}`;
      return `${act.action} · ${t}`;
  }
}

/** Пометка об отказах: «отклонено» / «все 3 отклонены» / «2 из 3 отклонены». */
export function failBadge(fails: number, count: number): string | undefined {
  if (fails <= 0) return undefined;
  if (fails >= count) return count > 1 ? `все ${count} отклонены` : "отклонено";
  return `${fails} из ${count} ${fails === 1 ? "отклонён" : "отклонены"}`;
}

/** primary — основной алиас субъекта: его имя в строках не повторяется. Сравнение —
 *  по правилу вида алиаса (aliasMatches): uid/sid/peer — с учётом регистра. */
export type BuildFeedOptions = { incidents?: ActorIncident[]; owner?: OwnerScope; primary?: Pick<Alias, "kind" | "value"> };

/** Действия трассы → строки ленты (свежие первыми) + инциденты. */
export function buildFeed(trace: ActorTrace, opts: BuildFeedOptions = {}): FeedItem[] {
  const out: FeedItem[] = [];
  const primary = opts.primary;
  for (const s of trace.sessions) {
    for (const o of s.origins) {
      for (const span of o.spans) {
        if (span.section === "network" || span.folded) continue;
        for (const act of span.actions) {
          const kind = feedKind(span.section as Exclude<Section, "network">, act.action);
          const badge = failBadge(act.fails, act.count);
          const actor = act.actors[0] && !(primary && aliasMatches(primary, act.actors[0])) ? act.actors[0] : undefined;
          const from = o.origin ? (span.attached ? `после входа с ${o.origin}` : `с ${o.origin}`) : undefined;
          const meta: string[] = [];
          if (actor) meta.push(actor);
          if (from) meta.push(from);
          if (act.details.length) meta.push(act.details.slice(0, 3).join(" · ") + (act.details.length > 3 ? " …" : ""));
          // При пометке число событий уже в ней: «2 из 3 отклонены».
          if (!badge && act.count > 1) meta.push(`×${act.count}`);
          const title = feedTitle(span, act, true);
          const titleFull = feedTitle(span, act);
          out.push({
            key: `${s.id}|${o.origin}|${span.section}|${span.target_kind}|${span.target}|${span.attached ? 1 : 0}|${act.source}|${act.action}`,
            kind, at: act.last, first: act.first,
            title, ...(titleFull !== title ? { titleFull } : {}),
            meta, actor, from, details: act.details, action: act.action,
            count: act.count, fails: act.fails,
            flagged: act.fails > 0,
            badge,
            href: spanEventsHref(o.origin, span, trace.bucketSec, act, opts.owner),
          });
        }
      }
    }
  }
  for (const inc of opts.incidents ?? []) {
    const at = tsMs(inc.created_at);
    if (at === null) continue;
    out.push({
      key: `inc|${inc.id}`, kind: "incident", at, first: at,
      title: inc.rule_title || inc.rule_id, meta: [inc.id], details: [],
      count: 1, fails: 0, flagged: true, badge: "инцидент", href: `/incidents/${encodeURIComponent(inc.id)}`, incident: inc,
    });
  }
  return out.sort((a, b) => b.at - a.at || a.key.localeCompare(b.key));
}

export function filterFeed(items: FeedItem[], f: FeedFilter): FeedItem[] {
  if (f === "all") return items;
  if (f === "flagged") return items.filter((i) => i.flagged);
  return items.filter((i) => i.kind === f);
}

const DAY = 86_400_000;
const hhmm = (ms: number) => new Date(ms).toISOString().slice(11, 16);

/** Время справа: сегодня — «N мин назад», иначе ЧЧ:ММ (UTC). */
export function feedTime(at: number, now: number): string {
  const diff = now - at;
  if (Math.floor(at / DAY) === Math.floor(now / DAY) && diff >= 0) {
    if (diff < 60_000) return "только что";
    if (diff < 3_600_000) return `${Math.floor(diff / 60_000)} мин назад`;
    return `${Math.floor(diff / 3_600_000)} ч назад`;
  }
  return hhmm(at);
}

/** Время строки: повторы в пределах суток — интервалом «06:08–06:12». */
export function feedTimeRange(it: Pick<FeedItem, "first" | "at" | "count">, now: number): string {
  const one = feedTime(it.at, now);
  if (it.count <= 1 || !/^\d\d:\d\d$/.test(one) || Math.floor(it.first / DAY) !== Math.floor(it.at / DAY)) return one;
  const a = hhmm(it.first);
  return a === one ? one : `${a}–${one}`;
}
