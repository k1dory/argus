import type { Metadata } from "next";
import Link from "next/link";
import { TriangleAlert, X } from "lucide-react";
import { DownloadButton } from "@/components/console/download-button";
import { FilterTabs } from "@/components/console/filter-tabs";
import { JournalFilterBar } from "@/components/console/journal/filter-bar";
import { TimeHistogram } from "@/components/console/time-histogram";
import { EventFeed } from "@/components/console/journal/event-feed";
import { Empty, PageHeader, Panel } from "@/components/console/panel";
import { Button } from "@/components/ui/button";
import { Pager } from "@/components/console/pager";
import { RangePicker } from "@/components/console/range-picker";
import { StorageUnavailable } from "@/components/console/storage-error";
import { requirePageSession } from "@/lib/auth";
import { engineState, safeQuery } from "@/lib/clickhouse";
import { JOURNAL_MAX_PAGE, journalSearch } from "@/lib/journal";
import { activeChips, fillBars, journalHref, journalQuery, parseJournalParams, windowBounds } from "@/lib/shared/journal";
import { RANGES } from "@/lib/shared/ranges";
import { SEVERITY, SEVERITY_MAX } from "@/lib/shared/severity";
import { fmtNum } from "@/lib/shared/time";

export const dynamic = "force-dynamic";
export const metadata: Metadata = { title: "Журнал событий" };

export default async function JournalPage({ searchParams }: PageProps<"/events">) {
  await requirePageSession();
  const f = parseJournalParams(await searchParams);
  const [r, engine] = await Promise.all([safeQuery(() => journalSearch(f)), engineState()]);
  const period = f.from ? "за выбранный интервал" : `за ${RANGES[f.range].label}`;
  const chips = activeChips(f);
  const filtered = chips.length > 0 || f.q.trim() !== "";
  const exportQs = new URLSearchParams({ index: "events", q: journalQuery(f), range: f.range });
  if (f.from) exportQs.set("from", f.from);
  if (f.to) exportQs.set("to", f.to);
  const exportName = `argus-journal-${new Date().toISOString().slice(0, 10)}`;

  const sums = r.ok ? r.data.series.reduce((a, b) => ({ critical: a.critical + Number(b.critical), high: a.high + Number(b.high) }), { critical: 0, high: 0 }) : { critical: 0, high: 0 };
  const important = sums.critical + sums.high;
  const importantOnly = (f.sev ?? 0) >= SEVERITY.events.high;
  const capLimit = r.ok ? r.data.pageSize * JOURNAL_MAX_PAGE : 0;
  const capped = r.ok && r.data.total > capLimit;
  const sourcesN = r.ok ? r.data.options.sources.length : 0;

  return (
    <>
      <PageHeader
        title="Журнал"
        subtitle={
          r.ok && !r.data.error
            ? `${fmtNum(r.data.total)} ${plural(r.data.total, "событие", "события", "событий")} ${period}${filtered ? " по фильтрам" : ` · ${fmtNum(sourcesN)} ${plural(sourcesN, "источник", "источника", "источников")}`}`
            : "Все источники в одной ленте"
        }
        actions={<RangePicker value={f.range} />}
      />

      <Panel label="Фильтры" meta="время — UTC">
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
              <Button asChild variant="ghost" size="sm">
                <Link href={journalHref({ q: "", range: f.range })}>сбросить всё</Link>
              </Button>
            </li>
          </ul>
        )}
        {r.ok && r.data.error && <p role="alert" className="mt-3 text-[13px] text-err">{r.data.error}</p>}
      </Panel>

      {!r.ok ? (
        <StorageUnavailable reason={r.error} />
      ) : (
        <>
          <section className="frame" aria-label="События по времени">
            <div className="frame__inner px-4 pt-4 pb-3">
              {r.data.series.length === 0 ? (
                <Empty className="py-10 text-center">Нет событий {period}{chips.length ? ` по фильтрам: ${chips.map((c) => `${c.label} ${c.value}`).join(", ")}` : ""}.</Empty>
              ) : (
                <TimeHistogram
                  bars={fillBars(r.data.series, r.data.bucketMinutes, windowBounds(f).startMs, windowBounds(f).endMs)}
                  bucketMinutes={r.data.bucketMinutes}
                  scale={SEVERITY.events}
                  scaleMax={SEVERITY_MAX.events}
                  hrefFor={(b) => journalHref(f, { from: b.from, to: b.to })}
                />
              )}
            </div>
          </section>

          <Panel
            label="Лента"
            actions={
              <>
                <DownloadButton href={`/api/search?${exportQs.toString()}&format=csv`} filename={`${exportName}.csv`} size="sm" variant="ghost">CSV</DownloadButton>
                <DownloadButton href={`/api/search?${exportQs.toString()}&format=export`} filename={`${exportName}.json`} size="sm" variant="ghost">JSON</DownloadButton>
              </>
            }
            bodyClassName="p-0"
          >
            <div className="flex flex-wrap items-center gap-x-4 gap-y-2 border-b border-[var(--border)] px-4 py-3">
              <FilterTabs
                label="Фильтр ленты"
                current={importantOnly ? "important" : "all"}
                flag={{ key: "important", label: "Только важное", count: important, icon: TriangleAlert, href: journalHref(f, { sev: SEVERITY.events.high, sevMax: undefined }) }}
                items={[{ key: "all", label: "Все", href: journalHref(f, { sev: undefined, sevMax: undefined }) }]}
              />
              <span className="text-[12px] text-[var(--text-tertiary)]">важное — серьёзность от {SEVERITY.events.high} из {SEVERITY_MAX.events}</span>
              {capped && (
                <p role="status" className="basis-full text-[13px] text-[var(--status-warn)] sm:ml-auto sm:basis-auto">
                  Показаны первые {fmtNum(capLimit)} из {fmtNum(r.data.total)} — сузьте интервал или фильтры
                </p>
              )}
            </div>
            {!engine.ok && (
              <p role="status" className="flex items-center gap-2 border-b border-[var(--border)] bg-[color-mix(in_oklab,var(--status-warn)_8%,transparent)] px-4 py-2 text-[13px] text-[var(--status-warn)]">
                <TriangleAlert strokeWidth={1.5} className="size-4 shrink-0" aria-hidden />
                Движок корреляции недоступен — связь событий с инцидентами не показывается
              </p>
            )}
            <EventFeed
              key={`${journalHref(f, { page: f.page })}|${r.data.cursor}`}
              initial={r.data.rows}
              incidents={r.data.incidents}
              filters={f}
              cursor={r.data.cursor}
              liveAllowed={!f.from && r.data.page === 1}
              engineUp={engine.ok}
            />
            <div className="px-4 pb-4">
              <Pager page={r.data.page} pages={pagesOf(r.data.total, r.data.pageSize)} total={r.data.total} pageSize={r.data.pageSize} capped={capped} href={(p) => journalHref(f, { page: p })} />
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
