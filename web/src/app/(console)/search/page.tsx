import type { Metadata } from "next";
import Link from "next/link";
import { Search as SearchIcon } from "lucide-react";
import { AlertsSeriesChart } from "@/components/console/charts";
import { DownloadButton } from "@/components/console/download-button";
import { Empty, PageHeader, Panel } from "@/components/console/panel";
import { Pager } from "@/components/console/pager";
import { RangePicker } from "@/components/console/range-picker";
import { SearchHit } from "@/components/console/search-hit";
import { StorageUnavailable } from "@/components/console/storage-error";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { requirePageSession } from "@/lib/auth";
import { safeQuery } from "@/lib/clickhouse";
import { availableIndexes, clampPage, INDEXES, MAX_QUERY_LEN, parseIndex, search, type IndexKey } from "@/lib/search";
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

  const r = await safeQuery(() => search(input));

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
          {r.ok && r.data.error && <p role="alert" className="text-sm text-destructive">{r.data.error}</p>}
        </form>
      </Panel>

      {!r.ok ? (
        <StorageUnavailable reason={r.error} />
      ) : (
        <SearchResults res={r.data} def={def} index={input.index} q={input.q} longRange={longRange} href={href} exportHref={exportHref} exportName={exportName} />
      )}
    </>
  );
}

function SearchResults({
  res,
  def,
  index,
  q,
  longRange,
  href,
  exportHref,
  exportName,
}: {
  res: Awaited<ReturnType<typeof search>>;
  def: (typeof INDEXES)[IndexKey];
  index: IndexKey;
  q: string;
  longRange: boolean;
  href: (patch: Record<string, string | undefined>) => string;
  exportHref: (format: string) => string;
  exportName: string;
}) {
  const pages = Math.max(1, Math.ceil(res.total / res.pageSize));
  return (
    <>
      <Panel label={`Распределение · ${fmtNum(res.total)} записей`} meta={`${fmtMs(res.ms)} · время UTC`}>
        {res.series.length === 0 ? (
          <Empty>Нет данных за выбранный интервал.</Empty>
        ) : (
          <AlertsSeriesChart data={res.series} longRange={longRange} />
        )}
      </Panel>

      <div className="grid gap-6 lg:grid-cols-[16rem_1fr]">
        <Panel label="Поля" meta="клик — добавить в запрос" bodyClassName="space-y-4">
          {res.facets.map((f) => (
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

        <Panel
          label={`Результаты · стр. ${fmtNum(res.page)} из ${fmtNum(pages)}`}
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
                {res.rows.length === 0 && (
                  <tr><td colSpan={def.columns.length + 1} className="py-8 text-center font-mono text-muted-foreground">Ничего не найдено — измените запрос или интервал</td></tr>
                )}
                {res.rows.map((row, i) => <SearchHit key={`${String(row.time ?? "")}|${i}`} row={row} columns={def.columns} index={index} />)}
              </tbody>
            </table>
          </div>
          <Pager page={res.page} pages={pages} total={res.total} pageSize={res.pageSize} href={(p) => href({ page: p > 1 ? String(p) : undefined })} />
        </Panel>
      </div>
    </>
  );
}
