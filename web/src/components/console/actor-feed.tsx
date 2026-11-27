// Лента активности субъекта на общих FeedList/FeedDay/FeedRow: дни, строки
// «что · откуда · ×N», команды третьей строкой моно; отказы и инциденты
// подсвечены. Фильтры — общим FilterTabs (ссылки, без JS).
import { Activity, AppWindow, LogIn, PencilLine, ShieldAlert, Siren, SquareTerminal, type LucideIcon } from "lucide-react";
import { FeedDay, FeedList, FeedRow } from "@/components/console/feed";
import { FilterTabs, type FilterTab } from "@/components/console/filter-tabs";
import { LevelBadge, StatusBadge } from "@/components/console/incident-badges";
import { Empty, Panel } from "@/components/console/panel";
import { TONE_OUTLINE_CLASS } from "@/components/console/tone";
import { cn } from "@/lib/utils";
import { FEED_FILTER_LABELS, FEED_FILTERS, FEED_MAX, feedTimeRange, filterFeed, type FeedFilter, type FeedItem, type FeedKind } from "@/lib/shared/actor-feed";
import { groupFeedByDay } from "@/lib/shared/feed";
import { isIncidentStatus } from "@/lib/shared/incidents";
import { fmtNum, formatTs } from "@/lib/shared/time";

const ICON: Record<FeedKind, LucideIcon> = {
  login: LogIn, host: SquareTerminal, app: AppWindow, change: PencilLine, other: Activity, incident: Siren,
};

/** Пометка об отказах — чип с рамкой, а не голый красный текст. */
function FailChip({ label }: { label: string }) {
  return <span className={cn("shrink-0 rounded-[5px] border px-1.5 py-px text-[11px] font-medium leading-4", TONE_OUTLINE_CLASS.err)}>{label}</span>;
}

/** Разрыв строки в meta FeedRow: детали встают отдельной (третьей) строкой. */
const LINE_BREAK = <span aria-hidden className="block h-0 w-screen" />;

function Row({ it, now }: { it: FeedItem; now: number }) {
  const time = feedTimeRange(it, now);
  const timeTitle = it.count > 1 && it.first !== it.at ? `${formatTs(it.first)} → ${formatTs(it.at)}` : formatTs(it.at);
  if (it.incident) {
    const inc = it.incident;
    return (
      <FeedRow
        icon={Siren}
        title={it.title}
        badge={<span className="flex shrink-0 items-center gap-1.5"><LevelBadge level={inc.level} />{isIncidentStatus(inc.status) ? <StatusBadge status={inc.status} /> : null}</span>}
        meta={[<span key="id" className="font-mono">{inc.id}</span>, !isIncidentStatus(inc.status) && inc.status ? inc.status : null]}
        time={time}
        timeTitle={timeTitle}
        flagged
        href={it.href ?? undefined}
        linkTitle={`Открыть инцидент · правило ${inc.rule_id}`}
      />
    );
  }
  const icon = it.flagged && it.kind === "login" ? ShieldAlert : ICON[it.kind];
  const details = it.details.slice(0, 3).join(" · ") + (it.details.length > 3 ? " …" : "");
  const meta: React.ReactNode[] = [
    it.from ? <span key="from" className="font-mono" title={it.from}>{it.from}</span> : <span key="from" title="Источник не передал IP">адрес неизвестен</span>,
    it.actor ? <span key="actor">как <span className="font-mono">{it.actor}</span></span> : null,
    !it.badge && it.count > 1 ? <span key="n" className="font-mono">×{fmtNum(it.count)}</span> : null,
  ];
  if (details) {
    meta.push(LINE_BREAK);
    meta.push(<span key="d" className="font-mono text-xs text-foreground/90" title={it.details.join("\n")}>{details}</span>);
  }
  return (
    <FeedRow
      icon={icon}
      title={it.titleFull ? <span title={it.titleFull}>{it.title}</span> : it.title}
      badge={it.badge ? <FailChip label={it.badge} /> : undefined}
      meta={meta}
      time={time}
      timeTitle={timeTitle}
      flagged={it.flagged}
      href={it.href ?? undefined}
      linkTitle={it.href
        ? `Открыть события в журнале${it.action ? ` · ${it.action}` : ""}`
        : "Ссылку в журнал построить нельзя: длинное значение или вне интервала владения алиасом"}
    />
  );
}

export function ActorFeed({ items, filter, now, hrefFor }: { items: FeedItem[]; filter: FeedFilter; now: number; hrefFor: (f: FeedFilter) => string }) {
  const counts = Object.fromEntries(FEED_FILTERS.map((f) => [f, filterFeed(items, f).length])) as Record<FeedFilter, number>;
  const shown = filterFeed(items, filter);
  const days = groupFeedByDay(shown.slice(0, FEED_MAX), (i) => i.at, new Date(now));
  const tab = (f: FeedFilter): FilterTab => ({ key: f, label: FEED_FILTER_LABELS[f], href: hrefFor(f), count: f === "all" ? undefined : counts[f] });
  return (
    <Panel label="Активность" meta="входы, команды, приложения и изменения · время UTC" bodyClassName="p-0">
      <div id="activity" className="scroll-mt-20 border-b border-border px-4 py-3">
        <FilterTabs
          label="Фильтр ленты"
          current={filter}
          flag={tab("flagged")}
          items={FEED_FILTERS.filter((f) => f !== "flagged").map(tab)}
        />
      </div>
      {shown.length === 0 ? (
        <Empty className="px-4 py-8 text-center">
          {filter === "flagged" ? "Отказов и инцидентов в периоде нет." : "Действий этого вида в периоде нет."}
        </Empty>
      ) : (
        <FeedList label="Лента активности" className="rounded-none border-0 p-1.5">
          {days.map((d) => (
            <FeedDay key={d.key} heading={d.heading} sticky>
              {d.items.map((it) => <Row key={it.key} it={it} now={now} />)}
            </FeedDay>
          ))}
          {shown.length > FEED_MAX && (
            <p className="px-3 py-3 text-xs text-muted-foreground">Показаны последние {fmtNum(FEED_MAX)} из {fmtNum(shown.length)} — остальное в сеансах ниже и в журнале.</p>
          )}
        </FeedList>
      )}
    </Panel>
  );
}
