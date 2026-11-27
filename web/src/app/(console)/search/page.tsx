import type { Metadata } from "next";
import Link from "next/link";
import { Suspense, type ReactNode } from "react";
import { DownloadButton } from "@/components/console/download-button";
import { FilterTabs } from "@/components/console/filter-tabs";
import { SearchForm } from "@/components/console/search-form";
import { TimeHistogram } from "@/components/console/time-histogram";
import { Empty, PageHeader, Panel } from "@/components/console/panel";
import { Pager } from "@/components/console/pager";
import { RangePicker } from "@/components/console/range-picker";
import { SearchHit } from "@/components/console/search-hit";
import { ChartSkeleton, PanelSkeleton } from "@/components/console/skeletons";
import { Button } from "@/components/ui/button";
import { requirePageSession } from "@/lib/auth";
import {
  availableIndexes, clampPage, FACET_SAMPLE, FACETS_SETTINGS, INDEXES, lowerBoundTotal, MAX_QUERY_LEN, PAGE_SIZE, pageCount, parseIndex, partErrorMessage, planSearch,
  searchErrorMessage, searchFacets, searchPage, searchSeries, seriesTotal, SERIES_SETTINGS, type Facet, type IndexKey, type SearchPlan,
} from "@/lib/search";
import type { SeriesPoint } from "@/lib/queries";
import { appendTerm } from "@/lib/shared/search-query";
import { fmtNum, formatTs } from "@/lib/shared/time";
import { parseTimeFilter, rangeLabel } from "@/lib/shared/filters";
import { parseSearchLevel } from "@/lib/shared/page-filters";
import { fillBars, windowBounds } from "@/lib/shared/journal";
import { SEVERITY, SEVERITY_MAX } from "@/lib/shared/severity";
import type { RangeKey } from "@/lib/shared/ranges";

export const dynamic = "force-dynamic";
export const metadata: Metadata = { title: "Поиск" };

const INDEX_LABEL: Record<IndexKey, string> = { alerts: "Алерты Wazuh", events: "События" };

/** Один пример, а не перечень: полный синтаксис — в шпаргалке «?». */
const HINT = {
  alerts: "agent:web-01 level>=10 -group:syscheck",
  events: "sshd actor:i.petrov -outcome:allow",
};

/** Меньше записей — график свёрнут до строки: человек пришёл за строками, а не за тремя столбиками. */
const SERIES_COLLAPSE_BELOW = 50;

export default async function SearchPage({ searchParams }: PageProps<"/search">) {
  await requirePageSession();
  const sp = await searchParams;
  const g = (k: string) => (typeof sp[k] === "string" ? (sp[k] as string) : undefined);
  const index = parseIndex(g("index"));
  // Точный интервал (невалидные даты отброшены, границы по порядку) и порог уровня индекса.
  const time = parseTimeFilter(sp, { defaultRange: "24h" });
  const level = parseSearchLevel(sp, index);
  const input = {
    index,
    q: (g("q") ?? "").slice(0, MAX_QUERY_LEN),
    range: time.range ?? "24h",
    from: time.from,
    to: time.to,
    page: clampPage(g("page")),
    showMuted: g("muted") === "1",
    levelMin: level.min,
    levelMax: level.max,
  };
  const levelText = rangeLabel(level.min !== undefined ? String(level.min) : undefined, level.max !== undefined ? String(level.max) : undefined);
  const def = INDEXES[input.index];

  const query = (patch: Record<string, string | undefined>) => {
    const p = new URLSearchParams();
    const merged: Record<string, string | undefined> = { index: input.index, q: input.q, range: input.range, from: input.from, to: input.to, muted: input.showMuted ? "1" : undefined,
      level_min: level.min !== undefined ? String(level.min) : undefined, level_max: level.max !== undefined ? String(level.max) : undefined, ...patch };
    for (const [k, v] of Object.entries(merged)) if (v) p.set(k, v);
    return p;
  };
  const href = (patch: Record<string, string | undefined>) => `/search?${query(patch).toString()}`;
  const exportHref = (format: string) => `/api/search?${query({ page: undefined, format }).toString()}`;
  const exportName = `argus-${input.index}-${new Date().toISOString().slice(0, 10)}`;

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

      <Panel label="Запрос" meta="время — UTC">
        {availableIndexes().length > 1 && (
          <FilterTabs
            className="mb-3"
            label="Где искать"
            current={input.index}
            items={availableIndexes().map((k) => ({ key: k, label: INDEX_LABEL[k], href: href({ index: k, page: undefined, level_min: undefined, level_max: undefined }) }))}
          />
        )}
        <SearchForm
          key={query({}).toString()}
          index={input.index}
          q={input.q}
          range={input.range}
          from={input.from}
          to={input.to}
          levelMin={level.min}
          levelMax={level.max}
          showMuted={input.showMuted}
          levelTop={SEVERITY_MAX[input.index]}
          levelLabel={input.index === "alerts" ? "Уровень правила" : "Серьёзность"}
          maxLength={MAX_QUERY_LEN}
          placeholder={HINT[input.index]}
        />
        {((input.from || input.to) || levelText || input.index === "alerts") && (
          <div className="mt-3 flex flex-wrap items-center gap-2">
            {(input.from || input.to) && <Button asChild variant="ghost" size="sm"><Link href={href({ from: undefined, to: undefined, page: undefined })}>сбросить интервал</Link></Button>}
            {levelText && <Button asChild variant="ghost" size="sm"><Link href={href({ level_min: undefined, level_max: undefined, page: undefined })}>сбросить уровень {levelText}</Link></Button>}
            {input.index === "alerts" && (
              <Button asChild variant="ghost" size="sm">
                <Link href={href({ muted: input.showMuted ? undefined : "1", page: undefined })}>{input.showMuted ? "скрыть заглушённые правила" : "показать заглушённые правила"}</Link>
              </Button>
            )}
          </div>
        )}
        {formError && <p role="alert" className="mt-3 text-sm text-destructive">{formError}</p>}
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
          window={{ range: input.range, from: input.from, to: input.to }}
          href={href}
          exportHref={exportHref}
          exportName={exportName}
          emptyHint={[input.from || input.to ? "интервал" : null, levelText ? `уровень ${levelText}` : null].filter(Boolean).join(", ")}
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
  window,
  href,
  exportHref,
  exportName,
  emptyHint,
}: {
  emptyHint: string;
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
  window: { range: RangeKey; from?: string; to?: string };
  href: (patch: Record<string, string | undefined>) => string;
  exportHref: (format: string) => string;
  exportName: string;
}) {
  const pager = (total: number, exact: boolean) => (
    <Pager
      page={plan.page}
      pages={pageCount(total, exact, hasMore, plan.page)}
      total={exact ? total : undefined}
      pageSize={PAGE_SIZE}
      href={(p) => href({ page: p > 1 ? String(p) : undefined })}
    />
  );
  const approxPager = pager(lowerBoundTotal(plan, rows.length), false);
  // Колонки, пустые у всех строк страницы, не показываем: «src/dst» с прочерками только съедают ширину.
  const columns = rows.length === 0 ? def.columns : def.columns.filter((c) => c.key === "time" || rows.some((r) => { const v = r[c.key]; return v !== "" && v !== null && v !== undefined && v !== 0 && v !== "0"; }));
  return (
    <>
      <Suspense fallback={<ChartSkeleton label="По времени · считаем…" />}>
        <SeriesBlock seriesP={seriesP} index={index} bucketMinutes={plan.bucketMinutes} window={window} href={href} />
      </Suspense>

      <div className="grid gap-6 lg:grid-cols-[16rem_1fr]">
        <Suspense fallback={<PanelSkeleton label="Поля" lines={8} />}>
          <FacetsBlock facetsP={facetsP} q={q} href={href} />
        </Suspense>

        <Panel
          label={plan.page > 1 ? `Результаты · стр. ${fmtNum(plan.page)}` : "Результаты"}
          meta={rowsMs > 1000 ? `ответ ${fmtNum(rowsMs / 1000, 1)} с` : undefined}
          actions={
            <>
              <DownloadButton href={exportHref("csv")} filename={`${exportName}.csv`} size="sm" variant="ghost">CSV</DownloadButton>
              <DownloadButton href={exportHref("export")} filename={`${exportName}.json`} size="sm" variant="ghost">JSON</DownloadButton>
            </>
          }
        >
          <div className="c-well overflow-x-auto p-2" tabIndex={0} aria-label="Таблица результатов, прокручивается по горизонтали">
            <table className="w-full text-sm">
              <thead>
                <tr className="border-b border-border/60">
                  <th scope="col" className="w-6"><span className="sr-only">Раскрыть</span></th>
                  {columns.map((c) => <th scope="col" key={c.key} className="c-label px-2 py-1 text-left whitespace-nowrap">{c.key === "time" ? "Время, UTC" : c.label}</th>)}
                </tr>
              </thead>
              <tbody>
                {rows.length === 0 && (
                  <tr><td colSpan={columns.length + 1} className="py-8 text-center text-[13px] text-muted-foreground">Ничего не найдено{emptyHint ? ` (активны: ${emptyHint})` : ""} — измените запрос или интервал</td></tr>
                )}
                {rows.map((row, i) => <SearchHit key={`${String(row.time ?? "")}|${i}`} rowKey={`${plan.page}-${i}`} row={row} columns={columns} index={index} />)}
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

async function SeriesBlock({
  seriesP,
  index,
  bucketMinutes,
  window,
  href,
}: {
  seriesP: Promise<Settled<SeriesPoint[]>>;
  index: IndexKey;
  bucketMinutes: number;
  window: { range: RangeKey; from?: string; to?: string };
  href: (patch: Record<string, string | undefined>) => string;
}) {
  const r = await seriesP;
  if (!r.ok) {
    return (
      <Panel label="По времени">
        <p role="status" className="text-sm text-muted-foreground">График и итог не посчитаны: {partErrorMessage(r.error, SERIES_SETTINGS.max_execution_time)}. Результаты ниже — полные для своей страницы.</p>
      </Panel>
    );
  }
  const total = seriesTotal(r.data);
  const noun = index === "alerts" ? ["алерт", "алерта", "алертов"] : ["запись", "записи", "записей"];
  const found = `Найдено ${fmtNum(total)} ${plural(total, noun[0], noun[1], noun[2])}`;
  if (r.data.length === 0) {
    return (
      <Panel label={found}>
        <Empty>Ничего не найдено за выбранный интервал.</Empty>
      </Panel>
    );
  }
  const { startMs, endMs } = windowBounds(window);
  const bars = fillBars(r.data, bucketMinutes, startMs, endMs);
  const [a, b] = [formatTs(r.data[0].bucket, "short"), formatTs(r.data[r.data.length - 1].bucket, "short")];
  const span = a === b ? a : `${a} – ${b}`;
  const chart = (
    <TimeHistogram
      bars={bars}
      bucketMinutes={bucketMinutes}
      scale={SEVERITY[index]}
      scaleMax={SEVERITY_MAX[index]}
      height={96}
      noun={index === "alerts" ? "алертов" : "записей"}
      ariaLabel={index === "alerts" ? "Алерты по времени" : "Записи по времени"}
      hrefFor={(b) => href({ from: b.from, to: b.to, range: undefined, page: undefined })}
    />
  );
  return (
    <Panel label={found} meta={span}>
      {total < SERIES_COLLAPSE_BELOW ? (
        <details className="group/s">
          <summary className="cursor-pointer list-none text-[13px] text-[var(--ring)] hover:underline [&::-webkit-details-marker]:hidden">
            <span className="group-open/s:hidden">Показать распределение по времени</span>
            <span className="hidden group-open/s:inline">Скрыть распределение</span>
          </summary>
          <div className="mt-3">{chart}</div>
        </details>
      ) : (
        chart
      )}
    </Panel>
  );
}

function plural(n: number, one: string, few: string, many: string): string {
  const m10 = n % 10, m100 = n % 100;
  if (m10 === 1 && m100 !== 11) return one;
  if (m10 >= 2 && m10 <= 4 && (m100 < 12 || m100 > 14)) return few;
  return many;
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
      bodyClassName="space-y-4"
    >
      <p className="text-[12px] leading-snug text-[var(--text-tertiary)]">
        Нажмите на значение, чтобы уточнить запрос{sampled ? `. По последним ${fmtNum(FACET_SAMPLE)} совпадениям` : ""}.
      </p>
      {r.data.facets.filter((f) => f.values.length > 0).map((f) => (
        <div key={f.field}>
          <div className="c-label mb-1" title={`поле запроса: ${f.field}`}>{f.label.charAt(0).toUpperCase() + f.label.slice(1)}</div>
          <ul className="space-y-0.5 font-mono text-xs">
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
