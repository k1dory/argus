// Лента активности субъекта: дни, строки с иконкой, заголовком, «кто · откуда ·
// что» и временем справа; отказы и инциденты подсвечены. Фильтры — ссылками.
import Link from "next/link";
import { Activity, AppWindow, Flag, LogIn, PencilLine, ShieldAlert, Siren, SquareTerminal, type LucideIcon } from "lucide-react";
import { Panel } from "@/components/console/panel";
import { cn } from "@/lib/utils";
import { FEED_FILTER_LABELS, FEED_FILTERS, FEED_MAX, feedTime, filterFeed, groupByDay, type FeedFilter, type FeedItem, type FeedKind } from "@/lib/shared/actor-feed";
import { fmtNum, formatTs } from "@/lib/shared/time";

const ICON: Record<FeedKind, LucideIcon> = {
  login: LogIn, host: SquareTerminal, app: AppWindow, change: PencilLine, other: Activity, incident: Siren,
};

function Row({ it, now }: { it: FeedItem; now: number }) {
  const Icon = it.flagged && it.kind === "login" ? ShieldAlert : ICON[it.kind];
  const body = (
    <>
      <Icon className={cn("size-5 shrink-0", it.flagged ? "text-[var(--status-err)]" : "text-muted-foreground")} strokeWidth={1.5} />
      <div className="min-w-0 flex-1">
        <div className="flex min-w-0 items-baseline gap-2">
          <span className="truncate text-sm font-medium">{it.title}</span>
          {it.badge && <span className="shrink-0 text-xs font-medium text-[var(--status-err)]">{it.badge}</span>}
        </div>
        {it.meta.length > 0 && (
          <div className="mt-0.5 flex min-w-0 gap-x-4 overflow-hidden text-xs text-muted-foreground">
            {it.meta.map((m, i) => <span key={i} className={cn("truncate", i === 0 && "text-foreground/80")}>{m}</span>)}
          </div>
        )}
      </div>
      <span className="shrink-0 text-xs tabular-nums text-muted-foreground" title={`${formatTs(it.first)} → ${formatTs(it.at)} UTC`}>{feedTime(it.at, now)}</span>
    </>
  );
  const cls = cn(
    "flex items-center gap-4 rounded-md px-4 py-3 transition-colors",
    it.flagged ? "bg-[var(--status-err)]/10 hover:bg-[var(--status-err)]/15" : "hover:bg-[var(--muted)]/40",
  );
  return it.href
    ? <Link href={it.href} className={cls} title="Открыть события в журнале">{body}</Link>
    : <div className={cls} title="Ссылку в журнал построить нельзя: длинное значение или вне интервала владения алиасом">{body}</div>;
}

function Tabs({ current, counts, hrefFor }: { current: FeedFilter; counts: Record<FeedFilter, number>; hrefFor: (f: FeedFilter) => string }) {
  const seg = FEED_FILTERS.filter((f) => f !== "flagged");
  const pill = (f: FeedFilter) => cn(
    "rounded-md px-3 py-1.5 text-sm transition-colors",
    current === f ? "bg-background font-medium text-foreground shadow-sm" : "text-muted-foreground hover:text-foreground",
  );
  return (
    <div className="flex flex-wrap items-center gap-2" role="group" aria-label="Фильтр ленты">
      <Link href={hrefFor("flagged")} aria-pressed={current === "flagged"} className={cn(
        "flex items-center gap-2 rounded-md border px-3 py-1.5 text-sm transition-colors",
        current === "flagged" ? "border-[var(--status-err)] text-[var(--status-err)]" : "border-border text-muted-foreground hover:text-foreground",
      )}>
        <Flag className="size-4" strokeWidth={1.5} />{FEED_FILTER_LABELS.flagged}
        {counts.flagged > 0 && <span className="font-mono text-xs text-[var(--status-err)]">{fmtNum(counts.flagged)}</span>}
      </Link>
      <div className="flex rounded-lg bg-[var(--muted)]/60 p-1">
        {seg.map((f) => (
          <Link key={f} href={hrefFor(f)} aria-pressed={current === f} className={pill(f)}>
            {FEED_FILTER_LABELS[f]}
            {f !== "all" && counts[f] > 0 && <span className="ml-1.5 font-mono text-[11px] text-muted-foreground">{fmtNum(counts[f])}</span>}
          </Link>
        ))}
      </div>
    </div>
  );
}

export function ActorFeed({ items, filter, now, hrefFor }: { items: FeedItem[]; filter: FeedFilter; now: number; hrefFor: (f: FeedFilter) => string }) {
  const counts = Object.fromEntries(FEED_FILTERS.map((f) => [f, filterFeed(items, f).length])) as Record<FeedFilter, number>;
  const shown = filterFeed(items, filter);
  const days = groupByDay(shown.slice(0, FEED_MAX), now);
  return (
    <Panel label="Активность" meta="входы, команды, приложения и изменения субъекта · время UTC" bodyClassName="space-y-4">
      <div id="activity" className="scroll-mt-20"><Tabs current={filter} counts={counts} hrefFor={hrefFor} /></div>
      {shown.length === 0 ? (
        <p className="py-6 text-center text-sm text-muted-foreground">
          {filter === "flagged" ? "Отказов и инцидентов в периоде нет." : "Действий этого вида в периоде нет."}
        </p>
      ) : (
        <div className="rounded-lg border border-border p-2">
          {days.map((d) => (
            <section key={d.day}>
              <div className="px-4 pb-1 pt-3 text-xs text-muted-foreground">{d.day}</div>
              <div className="divide-y divide-border/50">
                {d.items.map((it) => <Row key={it.key} it={it} now={now} />)}
              </div>
            </section>
          ))}
          {shown.length > FEED_MAX && (
            <p className="px-4 py-3 text-xs text-muted-foreground">Показаны последние {fmtNum(FEED_MAX)} из {fmtNum(shown.length)} — остальное в трассировке ниже и в журнале.</p>
          )}
        </div>
      )}
    </Panel>
  );
}
