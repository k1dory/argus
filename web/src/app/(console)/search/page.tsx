import type { Metadata } from "next";
import Link from "next/link";
import { Suspense, type ReactNode } from "react";
import { Search as SearchIcon } from "lucide-react";
import { AlertsSeriesChart } from "@/components/console/charts";
import { DownloadButton } from "@/components/console/download-button";
import { Empty, PageHeader, Panel } from "@/components/console/panel";
import { Pager } from "@/components/console/pager";
import { RangePicker } from "@/components/console/range-picker";
import { SearchHit } from "@/components/console/search-hit";
import { ChartSkeleton, PanelSkeleton } from "@/components/console/skeletons";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { requirePageSession } from "@/lib/auth";
import {
  availableIndexes, clampPage, FACET_SAMPLE, FACETS_SETTINGS, INDEXES, lowerBoundTotal, MAX_QUERY_LEN, PAGE_SIZE, pageCount, parseIndex, partErrorMessage, planSearch,
  searchErrorMessage, searchFacets, searchPage, searchSeries, seriesTotal, SERIES_SETTINGS, type Facet, type IndexKey, type SearchPlan,
} from "@/lib/search";
import type { SeriesPoint } from "@/lib/queries";
import { parseRange } from "@/lib/shared/ranges";
import { appendTerm } from "@/lib/shared/search-query";
import { fmtMs, fmtNum, isLongRange } from "@/lib/shared/time";

export const dynamic = "force-dynamic";
export const metadata: Metadata = { title: "Поиск" };

const INDEX_LABEL: Record<IndexKey, string> = { alerts: "алерты Wazuh", events: "события всех источников" };

const HINT = {
  alerts: 'root 203.0.113.5 · agent:web-01 level>=10 · -group:syscheck · desc:"brute force" · srcip:10.0.* · mitre:T1110',
  events: 'kubectl · source:k8s.audit actor:oidc:i.petrov · severity>=7 · attr.rule_groups:sshd · src:10.20.* -outcome:allow',
};

const DT_RE = /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}(:\d{2})?$/;

export default async function SearchPage({ searchParams }: PageProps<"/search">) {
  await requirePageSession();
  const sp = await searchParams;
  const g = (k: string) => (typeof sp[k] === "string" ? (sp[k] as string) : undefined);
  const dt = (v: string | undefined) => (v && DT_RE.test(v) ? v : undefined);
  const input = {
    index: parseIndex(g("index")),
    q: (g("q") ?? "").slice(0, MAX_QUERY_LEN),
    range: parseRange(g("range")),
    from: dt(g("from")),
    to: dt(g("to")),
    page: clampPage(g("page")),
    showMuted: g("muted") === "1",
  };
  const def = INDEXES[input.index];

  const query = (patch: Record<string, string | undefined>) => {
    const p = new URLSearchParams();
    const merged: Record<string, string | undefined> = { index: input.index, q: input.q, range: input.range, from: input.from, to: input.to, muted: input.showMuted ? "1" : undefined, ...patch };
    for (const [k, v] of Object.entries(merged)) if (v) p.set(k, v);
    return p;
  };
  const href = (patch: Record<string, string | undefined>) => `/search?${query(patch).toString()}`;
  const exportHref = (format: string) => `/api/search?${query({ page: undefined, format }).toString()}`;
  const exportName = `argus-${input.index}-${new Date().toISOString().slice(0, 10)}`;
  const longRange = isLongRange(input.range, input.from);

  // Страница результатов — сразу; гистограмма (с итогом) и поля догружаются
  // своими блоками: для частого слова за длинный интервал это полный скан, и
  // раньше вся страница ждала самый медленный из трёх запросов (или его таймаут).
  const { plan, empty } = planSearch(input);
  const seriesP = plan ? settle(searchSeries(plan)) : null;
  const facetsP = plan ? settle(searchFacets(plan)) : null;
  const timed = plan ? await timedRows(plan) : null;
  const r = timed?.r ?? null;
  const rowsMs = timed?.ms ?? 0;
  if (r && !r.ok) console.error("search:", r.error instanceof Error ? r.error.message : r.error);
  // Ошибка разбора запроса или страницы результатов — в панель запроса, как раньше.
  const formError = !plan ? empty.error : r && !r.ok ? searchErrorMessage(r.error) : null;

  return (
    <>
      <PageHeader title="Поиск">
        <RangePicker value={input.range} />
      </PageHeader>

      <Panel label="Запрос" meta={`${INDEX_LABEL[input.index]} · поля: ${Object.keys(def.fields).join(" ")}`}>
        <form method="get" action="/search" className="space-y-3">
          <input type="hidden" name="index" value={input.index} />
          <input type="hidden" name="range" value={input.range} />
          {input.showMuted && <input type="hidden" name="muted" value="1" />}
          <div className="flex flex-wrap gap-2">
            <Label htmlFor="search-q" className="sr-only">Строка запроса</Label>
            <Input id="search-q" name="q" defaultValue={input.q} maxLength={MAX_QUERY_LEN} placeholder={HINT[input.index]} spellCheck={false} autoFocus className="h-10 min-w-0 flex-1 px-3 font-mono sm:min-w-[24rem]" />
            <Button type="submit" className="min-h-10"><SearchIcon strokeWidth={1.5} />Искать</Button>
          </div>
          <div className="flex flex-wrap items-center gap-3 font-mono text-xs text-muted-foreground">
            <span>индекс:</span>
            {availableIndexes().map((k) => (
              <Button key={k} asChild variant="secondary" size="sm" aria-pressed={k === input.index}>
                <Link href={href({ index: k, page: undefined })}>{INDEX_LABEL[k]}</Link>
              </Button>
            ))}
            <span className="ml-2" title="Время вводится и трактуется в UTC, как в ClickHouse">точный интервал, UTC:</span>
            <Label htmlFor="search-from" className="sr-only">Начало интервала (UTC)</Label>
            <input id="search-from" type="datetime-local" name="from" defaultValue={input.from} aria-label="Начало интервала, UTC" className="h-8 border border-border bg-[var(--surface-deep)] px-2 font-mono text-xs" />
            <span aria-hidden>—</span>
            <Label htmlFor="search-to" className="sr-only">Конец интервала (UTC)</Label>
            <input id="search-to" type="datetime-local" name="to" defaultValue={input.to} aria-label="Конец интервала, UTC" className="h-8 border border-border bg-[var(--surface-deep)] px-2 font-mono text-xs" />
            {(input.from || input.to) && <Link href={href({ from: undefined, to: undefined, page: undefined })} className="underline">сбросить интервал</Link>}
            {input.index === "alerts" && (
              <Link href={href({ muted: input.showMuted ? undefined : "1", page: undefined })} className="underline">
                {input.showMuted ? "скрыть заглушённые правила" : "показать заглушённые правила"}
              </Link>
            )}
          </div>
          {formError && <p role="alert" className="text-sm text-destructive">{formError}</p>}
        </form>
      </Panel>

      {plan && r?.ok && seriesP && facetsP ? (
        <SearchResults
          plan={plan}
          rows={r.data.rows}
          hasMore={r.data.hasMore}
          rowsMs={rowsMs}
          seriesP={seriesP}
          facetsP={facetsP}
          def={def}
          index={input.index}
          q={input.q}
          longRange={longRange}
          href={href}
          exportHref={exportHref}
          exportName={exportName}
        />
      ) : null}
    </>
  );
}

type Settled<T> = { ok: true; data: T } | { ok: false; error: unknown };
/** Страница результатов со временем ответа (для подписи «страница — N мс»). */
async function timedRows(plan: SearchPlan): Promise<{ r: Settled<{ rows: Record<string, unknown>[]; hasMore: boolean }>; ms: number }> {
  const started = Date.now();
  const r = await settle(searchPage(plan));
  return { r, ms: Date.now() - started };
}
/** Обещание без отказа: ошибка части страницы не роняет рендер. */
function settle<T>(p: Promise<T>): Promise<Settled<T>> {
  return p.then((data) => ({ ok: true as const, data }), (error: unknown) => ({ ok: false as const, error }));
}

function SearchResults({
  plan,
  rows,
  hasMore,
  rowsMs,
  seriesP,
  facetsP,
  def,
  index,
  q,
  longRange,
  href,
  exportHref,
  exportName,
}: {
  plan: SearchPlan;
  rows: Record<string, unknown>[];
  /** Следующая страница подтверждена лишней прочитанной строкой. */
  hasMore: boolean;
  rowsMs: number;
  seriesP: Promise<Settled<SeriesPoint[]>>;
  facetsP: Promise<Settled<{ facets: Facet[]; sample: number }>>;
  def: (typeof INDEXES)[IndexKey];
  index: IndexKey;
  q: string;
  longRange: boolean;
  href: (patch: Record<string, string | undefined>) => string;
  exportHref: (format: string) => string;
  exportName: string;
}) {
  const pager = (total: number, exact: boolean) => (
    <Pager
      page={plan.page}
      pages={pageCount(total, exact, hasMore)}
      total={exact ? total : undefined}
      pageSize={PAGE_SIZE}
      href={(p) => href({ page: p > 1 ? String(p) : undefined })}
    />
  );
  const approxPager = pager(lowerBoundTotal(plan, rows.length), false);
  return (
    <>
      <Suspense fallback={<ChartSkeleton label="Распределение · считаем…" />}>
        <SeriesBlock seriesP={seriesP} longRange={longRange} rowsMs={rowsMs} />
      </Suspense>

      <div className="grid gap-6 lg:grid-cols-[16rem_1fr]">
        <Suspense fallback={<PanelSkeleton label="Поля" lines={8} />}>
          <FacetsBlock facetsP={facetsP} q={q} href={href} />
        </Suspense>

        <Panel
          label={`Результаты · стр. ${fmtNum(plan.page)}`}
          meta={
            <span className="flex gap-2">
              <DownloadButton href={exportHref("csv")} filename={`${exportName}.csv`} size="sm" variant="ghost">CSV</DownloadButton>
              <DownloadButton href={exportHref("export")} filename={`${exportName}.json`} size="sm" variant="ghost">JSON</DownloadButton>
            </span>
          }
        >
          <div className="c-well overflow-x-auto p-2">
            <table className="w-full text-sm">
              <thead>
                <tr className="border-b border-border/60">
                  <th scope="col" className="w-6"><span className="sr-only">подробности</span></th>
                  {def.columns.map((c) => <th scope="col" key={c.key} className="c-label px-2 py-1 text-left">{c.key === "time" ? "Время (UTC)" : c.label}</th>)}
                </tr>
              </thead>
              <tbody>
                {rows.length === 0 && (
                  <tr><td colSpan={def.columns.length + 1} className="py-8 text-center font-mono text-muted-foreground">Ничего не найдено — измените запрос или интервал</td></tr>
                )}
                {rows.map((row, i) => <SearchHit key={`${String(row.time ?? "")}|${i}`} row={row} columns={def.columns} index={index} />)}
              </tbody>
            </table>
          </div>
          <Suspense fallback={approxPager}>
            <ExactPager seriesP={seriesP} fallback={approxPager} pager={pager} />
          </Suspense>
        </Panel>
      </div>
    </>
  );
}

async function SeriesBlock({ seriesP, longRange, rowsMs }: { seriesP: Promise<Settled<SeriesPoint[]>>; longRange: boolean; rowsMs: number }) {
  const r = await seriesP;
  if (!r.ok) {
    return (
      <Panel label="Распределение" meta={`страница — ${fmtMs(rowsMs)} · время UTC`}>
        <p role="status" className="text-sm text-muted-foreground">Распределение и итог не посчитаны: {partErrorMessage(r.error, SERIES_SETTINGS.max_execution_time)}. Результаты ниже — полные для своей страницы.</p>
      </Panel>
    );
  }
  return (
    <Panel label={`Распределение · ${fmtNum(seriesTotal(r.data))} записей`} meta={`страница — ${fmtMs(rowsMs)} · время UTC`}>
      {r.data.length === 0 ? <Empty>Нет данных за выбранный интервал.</Empty> : <AlertsSeriesChart data={r.data} longRange={longRange} />}
    </Panel>
  );
}

async function FacetsBlock({ facetsP, q, href }: { facetsP: Promise<Settled<{ facets: Facet[]; sample: number }>>; q: string; href: (patch: Record<string, string | undefined>) => string }) {
  const r = await facetsP;
  if (!r.ok) {
    return (
      <Panel label="Поля" bodyClassName="space-y-2">
        <p role="status" className="text-sm text-muted-foreground">Не посчитаны: {partErrorMessage(r.error, FACETS_SETTINGS.max_execution_time)}.</p>
      </Panel>
    );
  }
  const sampled = r.data.sample >= FACET_SAMPLE;
  return (
    <Panel
      label="Поля"
      meta={sampled ? `по последним ${fmtNum(FACET_SAMPLE)} совпадениям · клик — добавить в запрос` : "клик — добавить в запрос"}
      bodyClassName="space-y-4"
    >
      {r.data.facets.map((f) => (
        <div key={f.field}>
          <div className="c-label mb-1">{f.label} <span className="text-muted-foreground">{f.field}</span></div>
          <ul className="space-y-0.5 font-mono text-xs">
            {f.values.length === 0 && <li className="text-muted-foreground">—</li>}
            {f.values.map((v) => (
              <li key={v.value} className="flex justify-between gap-2">
                <Link href={href({ q: appendTerm(q, f.field, v.value, { literal: true }), page: undefined })} className="truncate hover:underline" title={v.value}>{v.value}</Link>
                <span className="text-muted-foreground tabular-nums">{fmtNum(v.count)}</span>
              </li>
            ))}
          </ul>
        </div>
      ))}
    </Panel>
  );
}

async function ExactPager({
  seriesP,
  fallback,
  pager,
}: {
  seriesP: Promise<Settled<SeriesPoint[]>>;
  fallback: ReactNode;
  pager: (total: number, exact: boolean) => ReactNode;
}) {
  const r = await seriesP;
  return r.ok ? pager(seriesTotal(r.data), true) : fallback;
}
