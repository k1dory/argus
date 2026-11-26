// Лента активности субъекта: те же агрегаты, что у трассировки, но плоским
// списком «что произошло» — понятный заголовок, кто/откуда/что, время, отметка
// отказов и инцидентов. Сеть в ленту не идёт: это фон, а не поступки.
import type { ActorIncident, Section } from "./actors";
import { tsMs } from "./actors";
import { LOGOUT_RE, spanLabel, spanEventsHref, type ActorTrace, type OwnerScope, type TraceAction, type TraceSpan } from "./actor-trace";

export const FEED_FILTERS = ["flagged", "all", "login", "host", "app", "change"] as const;
export type FeedFilter = (typeof FEED_FILTERS)[number];
export const FEED_FILTER_LABELS: Record<FeedFilter, string> = {
  flagged: "Отмеченные", all: "Все", login: "Входы", host: "Узлы", app: "Приложения", change: "Изменения",
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
  /** Части второй строки: кто, откуда, детали. */
  meta: string[];
  count: number;
  fails: number;
  flagged: boolean;
  /** Пометка справа от заголовка: «отказ», «инцидент», уровень. */
  badge?: string;
  href: string | null;
  incident?: ActorIncident;
};

/** Строк ленты: дальше — трассировка и журнал. */
export const FEED_MAX = 80;

const has = (a: string, ...parts: string[]) => parts.some((p) => a.includes(p));

/** Человеческий заголовок по разделу, действию и цели — без знания вендоров. */
export function feedTitle(span: Pick<TraceSpan, "section" | "target" | "target_kind" | "dst_port" | "folded">, act: Pick<TraceAction, "action" | "count" | "fails">): string {
  const a = act.action.toLowerCase();
  const t = spanLabel(span);
  const allFailed = act.fails > 0 && act.fails >= act.count;
  switch (span.section) {
    case "login": {
      if (LOGOUT_RE.test(a)) return `Выход${span.target_kind === "node" ? ` с ${t}` : ` из ${t}`}`;
      const how = has(a, "ssh") ? "по SSH " : "";
      const where = span.target_kind === "node" ? `на ${t}` : span.target_kind === "source" ? `в ${t}` : `в ${t}`;
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
      return `${act.action} · ${t}`;
    default:
      return `${act.action} · ${t}`;
  }
}

export type BuildFeedOptions = { incidents?: ActorIncident[]; owner?: OwnerScope };

/** Действия трассы → строки ленты (свежие первыми) + инциденты. */
export function buildFeed(trace: ActorTrace, opts: BuildFeedOptions = {}): FeedItem[] {
  const out: FeedItem[] = [];
  for (const s of trace.sessions) {
    for (const o of s.origins) {
      for (const span of o.spans) {
        if (span.section === "network" || span.folded) continue;
        const kind = span.section as FeedKind;
        for (const act of span.actions) {
          const meta: string[] = [];
          if (act.actors[0]) meta.push(act.actors[0]);
          if (o.origin) meta.push(span.attached ? `после входа с ${o.origin}` : `с ${o.origin}`);
          if (act.details.length) meta.push(act.details.slice(0, 3).join(" · ") + (act.details.length > 3 ? " …" : ""));
          if (act.count > 1) meta.push(`×${act.count}`);
          if (act.fails > 0) meta.push(`отказов ${act.fails}`);
          out.push({
            key: `${s.id}|${o.origin}|${span.section}|${span.target_kind}|${span.target}|${span.attached ? 1 : 0}|${act.source}|${act.action}`,
            kind, at: act.last, first: act.first,
            title: feedTitle(span, act), meta,
            count: act.count, fails: act.fails,
            flagged: act.fails > 0,
            badge: act.fails > 0 ? (act.fails >= act.count ? "отказ" : "были отказы") : undefined,
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
      title: inc.rule_title || inc.rule_id, meta: [inc.id, inc.status, inc.rule_id].filter(Boolean),
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

/** Заголовок дня в UTC: «Сегодня», «Вчера», иначе дата. */
export function dayLabel(at: number, now: number): string {
  const d = Math.floor(at / DAY);
  const today = Math.floor(now / DAY);
  if (d === today) return "Сегодня";
  if (d === today - 1) return "Вчера";
  return new Date(d * DAY).toISOString().slice(0, 10);
}

/** Время справа: сегодня — «N мин назад», иначе ЧЧ:ММ (UTC). */
export function feedTime(at: number, now: number): string {
  const diff = now - at;
  if (Math.floor(at / DAY) === Math.floor(now / DAY) && diff >= 0) {
    if (diff < 60_000) return "только что";
    if (diff < 3_600_000) return `${Math.floor(diff / 60_000)} мин назад`;
    return `${Math.floor(diff / 3_600_000)} ч назад`;
  }
  return new Date(at).toISOString().slice(11, 16);
}

/** Строки по дням (порядок сохраняется). */
export function groupByDay(items: FeedItem[], now: number): { day: string; items: FeedItem[] }[] {
  const out: { day: string; items: FeedItem[] }[] = [];
  for (const it of items) {
    const day = dayLabel(it.at, now);
    const last = out[out.length - 1];
    if (last && last.day === day) last.items.push(it);
    else out.push({ day, items: [it] });
  }
  return out;
}
