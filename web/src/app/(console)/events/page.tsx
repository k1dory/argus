import type { Metadata } from "next";
import Link from "next/link";
import { X } from "lucide-react";
import { DownloadButton } from "@/components/console/download-button";
import { JournalFilterBar } from "@/components/console/journal/filter-bar";
import { JournalHistogram } from "@/components/console/journal/histogram";
import { EventFeed } from "@/components/console/journal/event-feed";
import { Empty, Panel } from "@/components/console/panel";
import { Pager } from "@/components/console/pager";
import { RangePicker } from "@/components/console/range-picker";
import { StorageUnavailable } from "@/components/console/storage-error";
import { requirePageSession } from "@/lib/auth";
import { safeQuery } from "@/lib/clickhouse";
import { JOURNAL_MAX_PAGE, journalSearch } from "@/lib/journal";
import { activeChips, fillBars, journalHref, journalQuery, parseJournalParams, windowBounds } from "@/lib/shared/journal";
import { RANGES } from "@/lib/shared/ranges";
import { fmtMs, fmtNum, isLongRange } from "@/lib/shared/time";

export const dynamic = "force-dynamic";
export const metadata: Metadata = { title: "Журнал событий" };

export default async function JournalPage({ searchParams }: PageProps<"/events">) {
  await requirePageSession();
  const f = parseJournalParams(await searchParams);
  const r = await safeQuery(() => journalSearch(f));
  const longRange = isLongRange(f.range, f.from);
  const period = f.from ? "за выбранный интервал" : `за ${RANGES[f.range].label}`;
  const chips = activeChips(f);
  const filtered = chips.length > 0 || f.q.trim() !== "";
  const exportQs = new URLSearchParams({ index: "events", q: journalQuery(f), range: f.range });
  if (f.from) exportQs.set("from", f.from);
  if (f.to) exportQs.set("to", f.to);
  const exportName = `argus-journal-${new Date().toISOString().slice(0, 10)}`;

  return (
    <>
      <div className="flex flex-wrap items-end justify-between gap-4">
        <h1 className="max-w-[60rem] text-[26px] leading-[1.15] sm:text-[32px]">
          Журнал событий.{" "}
          <span className="text-muted-foreground">
            {r.ok && !r.data.error
              ? `${fmtNum(r.data.total)} ${plural(r.data.total, "событие", "события", "событий")} ${period}${filtered ? " по фильтрам" : ` из ${fmtNum(r.data.options.sources.length)} ${plural(r.data.options.sources.length, "источника", "источников", "источников")}`}.`
              : "Все источники в одной ленте."}
          </span>
        </h1>
        <RangePicker value={f.range} />
      </div>

      <Panel label="Фильтры" meta="время в UTC · поля: source node severity rule actor object src dst action outcome attr.*">
        <JournalFilterBar filters={f} sources={r.ok ? r.data.options.sources : []} hosts={r.ok ? r.data.options.hosts : []} />
        {chips.length > 0 && (
          <ul className="mt-3 flex flex-wrap items-center gap-2" aria-label="Активные фильтры">
            {chips.map((c) => (
              <li key={c.key}>
                <Link href={c.href} className="inline-flex h-7 items-center gap-1.5 rounded-[6px] border border-[var(--border-strong)] bg-background pr-1.5 pl-2 text-[12px] text-muted-foreground transition-colors hover:border-[#3a3f4a] hover:text-foreground" aria-label={`Убрать фильтр: ${c.label} ${c.value}`}>
                  {c.label} <span className="font-mono text-foreground">{c.value}</span>
                  <X strokeWidth={1.5} className="size-3.5" aria-hidden />
                </Link>
              </li>
            ))}
            <li>
              <Link href={journalHref({ q: "", range: f.range })} className="text-[12px] text-[var(--ring)] hover:underline">сбросить всё</Link>
            </li>
          </ul>
        )}
        {r.ok && r.data.error && <p role="alert" className="mt-3 text-[13px] text-err">{r.data.error}</p>}
      </Panel>

      {!r.ok ? (
        <StorageUnavailable reason={r.error} />
      ) : (
        <>
          <section className="frame" aria-label="Гистограмма событий по времени">
            <div className="frame__inner px-4 pt-4 pb-3">
              {r.data.series.length === 0 ? (
                <Empty className="py-10 text-center">Нет событий {period}.</Empty>
              ) : (
                <JournalHistogram
                  bars={fillBars(r.data.series, r.data.bucketMinutes, windowBounds(f).startMs, windowBounds(f).endMs)}
                  bucketMinutes={r.data.bucketMinutes}
                  longRange={longRange}
                  hrefFor={(b) => journalHref(f, { from: b.from, to: b.to })}
                />
              )}
            </div>
          </section>

          <Panel
            label={`Лента · страница ${fmtNum(r.data.page)} из ${fmtNum(pagesOf(r.data.total, r.data.pageSize))}`}
            meta={
              <span className="flex items-center gap-1">
                <span className="mr-2">{fmtMs(r.data.ms)}</span>
                <DownloadButton href={`/api/search?${exportQs.toString()}&format=csv`} filename={`${exportName}.csv`} size="sm" variant="ghost">CSV</DownloadButton>
                <DownloadButton href={`/api/search?${exportQs.toString()}&format=export`} filename={`${exportName}.json`} size="sm" variant="ghost">JSON</DownloadButton>
              </span>
            }
            bodyClassName="p-0"
          >
            <EventFeed
              key={`${journalHref(f, { page: f.page })}|${r.data.cursor}`}
              initial={r.data.rows}
              incidents={r.data.incidents}
              filters={f}
              cursor={r.data.cursor}
              liveAllowed={!f.from && r.data.page === 1}
              showDate={f.range !== "1h" || Boolean(f.from)}
            />
            <div className="px-4 pb-4">
              <Pager page={r.data.page} pages={pagesOf(r.data.total, r.data.pageSize)} total={r.data.total} pageSize={r.data.pageSize} capped={r.data.total > r.data.pageSize * JOURNAL_MAX_PAGE} href={(p) => journalHref(f, { page: p })} />
            </div>
          </Panel>
        </>
      )}
    </>
  );
}

function pagesOf(total: number, size: number): number {
  return Math.min(JOURNAL_MAX_PAGE, Math.max(1, Math.ceil(total / size)));
}

function plural(n: number, one: string, few: string, many: string): string {
  const m10 = n % 10, m100 = n % 100;
  if (m10 === 1 && m100 !== 11) return one;
  if (m10 >= 2 && m10 <= 4 && (m100 < 12 || m100 > 14)) return few;
  return many;
}
