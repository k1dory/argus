// Лента событий по образцу референса: строка — иконка, заголовок, бейдж,
// вторая строка частями («кто · где · что» без точек — отступами), время
// справа; отмеченное — фоном и полосой слева; строки сгруппированы по дням.
// Серверный компонент без состояния; годится для паспорта, инцидентов,
// журнала реагирования, «Требует внимания» на обзоре.
//
//   <FeedList>
//     {groupFeedByDay(items, (i) => i.ts).map((g) => (
//       <FeedDay key={g.key} heading={g.heading}>
//         {g.items.map((i) => <FeedRow key={i.id} icon={LogIn} title="Вход" meta={[i.user, i.ip]} time={<Ago ts={i.ts} />} href={…} />)}
//       </FeedDay>
//     ))}
//   </FeedList>
import Link from "next/link";
import type { LucideIcon } from "lucide-react";
import { cn } from "@/lib/utils";
import { TONE_COLOR, type Tone } from "./tone";

/** Рамка ленты. label — подпись списка для скринридера. */
export function FeedList({ children, label, className }: { children: React.ReactNode; label?: string; className?: string }) {
  return (
    <div role={label ? "region" : undefined} aria-label={label} className={cn("rounded-[10px] border border-border p-1.5", className)}>
      {children}
    </div>
  );
}

/** Группа дня: заголовок («Сегодня», «вт, 25 ноября») и строки. */
export function FeedDay({ heading, children, sticky = false }: { heading: React.ReactNode; children: React.ReactNode; sticky?: boolean }) {
  return (
    <section>
      <h3 className={cn("px-3 pb-1 pt-2 text-[12px] font-medium tracking-normal text-[var(--text-tertiary)]", sticky && "sticky top-0 z-10 bg-[var(--card)]")}>{heading}</h3>
      <ul className="divide-y divide-border/70">{children}</ul>
    </section>
  );
}

export type FeedBadge = { label: string; tone?: Tone };

/**
 * Строка ленты.
 * - flagged — «отмечено» (отказ, инцидент): фон и полоса тона (по умолчанию err), иконка тоном;
 * - tone — тон иконки и подсветки при flagged;
 * - meta — части второй строки; первая (обычно «кто») — чуть ярче;
 * - time — время справа (строка или <Ago/>); timeTitle — подсказка к нему;
 * - href — ссылка на всю строку; linkTitle — куда ведёт.
 */
export function FeedRow({
  icon: Icon,
  title,
  badge,
  meta = [],
  time,
  timeTitle,
  flagged = false,
  tone,
  href,
  linkTitle,
  className,
}: {
  icon?: LucideIcon;
  title: React.ReactNode;
  badge?: FeedBadge | React.ReactNode;
  meta?: React.ReactNode[];
  time?: React.ReactNode;
  timeTitle?: string;
  flagged?: boolean;
  tone?: Tone;
  href?: string;
  linkTitle?: string;
  className?: string;
}) {
  const t: Tone = tone ?? (flagged ? "err" : "muted");
  const color = TONE_COLOR[t];
  const badgeNode = isFeedBadge(badge)
    ? <span className="shrink-0 text-[12px] font-medium" style={{ color: TONE_COLOR[badge.tone ?? "err"] }}>{badge.label}</span>
    : badge;
  const parts = meta.filter((m) => m !== null && m !== undefined && m !== false && m !== "");
  const body = (
    <>
      {Icon && <Icon className="size-[18px] shrink-0" style={{ color: flagged || tone ? color : undefined }} strokeWidth={1.5} aria-hidden />}
      <div className="min-w-0 flex-1">
        <div className="flex min-w-0 items-baseline gap-2">
          <span className="min-w-0 truncate text-sm font-medium text-foreground">{title}</span>
          {badgeNode}
        </div>
        {parts.length > 0 && (
          <div className="mt-0.5 flex min-w-0 flex-wrap gap-x-4 text-[12px] leading-5 text-muted-foreground">
            {parts.map((m, i) => <span key={i} className={cn("min-w-0 max-w-full truncate", i === 0 && "text-[var(--fg-2)]")}>{m}</span>)}
          </div>
        )}
      </div>
      {time !== undefined && <span className="shrink-0 self-center text-[12px] tabular-nums text-muted-foreground" title={timeTitle}>{time}</span>}
    </>
  );
  const cls = cn(
    "flex items-center gap-3.5 rounded-md px-3 py-2.5 transition-colors",
    flagged && "bg-[color-mix(in_oklab,var(--feed-tone)_9%,transparent)] shadow-[inset_2px_0_0_var(--feed-tone)]",
    href && (flagged ? "hover:bg-[color-mix(in_oklab,var(--feed-tone)_14%,transparent)]" : "hover:bg-[var(--surface-elevated)]"),
    className,
  );
  const style = flagged ? ({ "--feed-tone": color } as React.CSSProperties) : undefined;
  return (
    <li data-flagged={flagged || undefined}>
      {href
        ? <Link href={href} className={cn(cls, "focus-visible:outline-offset-[-2px]")} style={style} title={linkTitle}>{body}</Link>
        : <div className={cls} style={style}>{body}</div>}
    </li>
  );
}

function isFeedBadge(x: unknown): x is FeedBadge {
  return typeof x === "object" && x !== null && "label" in x && typeof (x as FeedBadge).label === "string" && !("$$typeof" in x);
}
