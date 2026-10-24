"use client";

// Рендер панелей конструктора: timeseries / bar / stat / table на Recharts
// (shadcn charts). Данные приходят с сервера уже выполненными.
import { Area, AreaChart, Bar, BarChart, CartesianGrid, LabelList, XAxis, YAxis } from "recharts";
import { ChartContainer, ChartLegend, ChartLegendContent, ChartTooltip, ChartTooltipContent, type ChartConfig } from "@/components/ui/chart";
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from "@/components/ui/table";
import type { Panel as PanelSpec, PanelData } from "@/lib/dashboards";
import { panelSpanMedium } from "@/lib/shared/dashboard-spec";
import { seriesSlug } from "@/lib/shared/chart-css";
import { fmtMs, fmtNum, formatAxisTs, formatTs } from "@/lib/shared/time";
import { Empty, Panel } from "@/components/console/panel";

const PALETTE = ["var(--chart-3)", "var(--chart-2)", "var(--chart-1)", "var(--chart-4)", "var(--chart-5)", "#a6a6a6", "#5c5c5c"];
const tick = { fill: "var(--muted-foreground)", fontSize: 11, fontFamily: "var(--font-plex-mono)" };
const MAX_SERIES = 12;

function numeric(rows: Record<string, unknown>[], columns: string[]): string[] {
  return columns.filter((c) => rows.some((r) => typeof r[c] === "number" || (typeof r[c] === "string" && r[c] !== "" && !Number.isNaN(Number(r[c])))));
}

/**
 * Первая колонка — время; остальные числовые — серии; либо series-колонка → pivot.
 * Ключи серий в данных и в CSS — безопасные слаги s0…sN; исходные имена
 * (значения из ClickHouse) живут только в label конфига.
 */
export function pivotTimeseries(p: PanelSpec, d: PanelData): { data: Record<string, number | string>[]; series: { key: string; label: string }[] } {
  if (d.rows.length === 0) return { data: [], series: [] };
  const timeCol = d.columns[0];
  if (p.series && d.columns.includes(p.series)) {
    const valueCol = numeric(d.rows, d.columns.filter((c) => c !== timeCol && c !== p.series))[0];
    const slugOf = new Map<string, string>();
    const byTime = new Map<string, Record<string, number | string>>();
    for (const r of d.rows) {
      const t = String(r[timeCol]);
      const name = String(r[p.series]);
      let key = slugOf.get(name);
      if (!key) {
        if (slugOf.size >= MAX_SERIES) continue;
        key = seriesSlug(slugOf.size);
        slugOf.set(name, key);
      }
      const row = byTime.get(t) ?? { time: t };
      row[key] = Number(r[valueCol] ?? 0);
      byTime.set(t, row);
    }
    return { data: [...byTime.values()], series: [...slugOf.entries()].map(([label, key]) => ({ key, label })) };
  }
  const cols = numeric(d.rows, d.columns.slice(1)).slice(0, MAX_SERIES);
  const series = cols.map((label, i) => ({ key: seriesSlug(i), label }));
  return {
    data: d.rows.map((r) => ({ time: String(r[timeCol]), ...Object.fromEntries(series.map((s) => [s.key, Number(r[s.label] ?? 0)])) })),
    series,
  };
}

export function TimeSeriesPanel({ panel, data, longRange }: { panel: PanelSpec; data: PanelData; longRange: boolean }) {
  const { data: rows, series } = pivotTimeseries(panel, data);
  const config = Object.fromEntries(series.map((s, i) => [s.key, { label: s.label, color: PALETTE[i % PALETTE.length] }])) satisfies ChartConfig;
  if (rows.length === 0) return <Empty className="text-xs">нет данных за период</Empty>;
  return (
    <ChartContainer config={config} className="h-full w-full" role="img" aria-label={panel.title || "временной ряд"}>
      <AreaChart data={rows} margin={{ left: 0, right: 8, top: 8 }}>
        <CartesianGrid vertical={false} stroke="var(--border)" />
        <XAxis dataKey="time" tickLine={false} axisLine={false} tick={tick} tickFormatter={(v: string) => formatAxisTs(v, longRange)} minTickGap={40} />
        <YAxis tickLine={false} axisLine={false} tick={tick} width={44} allowDecimals={false} tickFormatter={(v: number) => fmtNum(v)} />
        <ChartTooltip content={<ChartTooltipContent labelFormatter={(v) => formatTs(String(v), "full")} />} />
        {series.length > 1 && <ChartLegend content={<ChartLegendContent />} />}
        {series.map((s) => (
          <Area key={s.key} dataKey={s.key} name={s.label} type="step" stackId="s" stroke={`var(--color-${s.key})`} fill={`var(--color-${s.key})`} fillOpacity={0.25} strokeWidth={1.5} />
        ))}
      </AreaChart>
    </ChartContainer>
  );
}

export function BarPanel({ panel, data }: { panel: PanelSpec; data: PanelData }) {
  if (data.rows.length === 0) return <Empty className="text-xs">нет данных за период</Empty>;
  const cat = data.columns[0];
  const val = numeric(data.rows, data.columns.slice(1))[0] ?? data.columns[1];
  const rows = data.rows.slice(0, 20).map((r) => ({ name: String(r[cat]), value: Number(r[val] ?? 0) }));
  const config = { value: { label: val, color: "var(--chart-3)" } } satisfies ChartConfig;
  return (
    <ChartContainer config={config} className="h-full w-full" role="img" aria-label={panel.title || "столбцы"}>
      <BarChart data={rows} layout="vertical" margin={{ left: 8, right: 44 }}>
        <XAxis type="number" hide />
        <YAxis type="category" dataKey="name" tickLine={false} axisLine={false} tick={tick} width={170} tickFormatter={(v: string) => (v.length > 24 ? v.slice(0, 23) + "…" : v)} />
        <ChartTooltip content={<ChartTooltipContent />} />
        <Bar dataKey="value" fill="var(--color-value)" barSize={12} radius={0}>
          <LabelList dataKey="value" position="right" formatter={(v: unknown) => fmtNum(Number(v))} style={{ fill: "var(--muted-foreground)", fontSize: 11, fontFamily: "var(--font-plex-mono)" }} />
        </Bar>
      </BarChart>
    </ChartContainer>
  );
}

export function StatPanel({ panel, data }: { panel: PanelSpec; data: PanelData }) {
  if (data.rows.length === 0) return <Empty className="text-xs">нет данных за период</Empty>;
  const row = data.rows[0];
  const cols = data.columns.slice(0, 4);
  return (
    <dl className="grid h-full grid-cols-2 gap-4">
      {cols.map((c) => (
        <div key={c}>
          <dt className="c-label">{c}</dt>
          <dd className="mt-1 font-mono text-3xl font-medium text-foreground">
            {typeof row[c] === "number" ? fmtNum(row[c] as number, Number.isInteger(row[c]) ? 0 : 1) : String(row[c] ?? "—")}
            {panel.unit && <span className="ml-1 text-base text-muted-foreground">{panel.unit}</span>}
          </dd>
        </div>
      ))}
    </dl>
  );
}

const TIME_COL = /^(t|ts|time|timestamp|bucket|date|day|hour|minute|created_at|evaluated_at|first_ts|last_ts)$/i;

export function TablePanel({ data }: { data: PanelData }) {
  if (data.rows.length === 0) return <Empty className="text-xs">нет данных за период</Empty>;
  return (
    <div className="h-full overflow-auto">
      <Table>
        <TableHeader>
          <TableRow>{data.columns.map((c) => <TableHead key={c}>{c}</TableHead>)}</TableRow>
        </TableHeader>
        <TableBody>
          {data.rows.slice(0, 200).map((r, i) => (
            <TableRow key={i}>
              {data.columns.map((c) => {
                const v = r[c];
                const text = typeof v === "number" ? fmtNum(v, Number.isInteger(v) ? 0 : 2) : TIME_COL.test(c) && typeof v === "string" ? formatTs(v) : String(v ?? "");
                return <TableCell key={c} className={typeof v === "number" ? "text-right text-xs tabular-nums" : "text-xs"}>{text}</TableCell>;
              })}
            </TableRow>
          ))}
        </TableBody>
      </Table>
    </div>
  );
}

/** Ошибка панели: короткая причина всем, полный ответ ClickHouse — только редактору (в <details>). */
function PanelError({ data }: { data: PanelData }) {
  return (
    <div className="space-y-2 font-mono text-xs">
      <p className="text-destructive" role="alert">{data.error}</p>
      {data.errorDetail && (
        <details>
          <summary className="cursor-pointer text-muted-foreground hover:text-foreground">полный ответ ClickHouse</summary>
          <pre className="mt-2 max-h-48 overflow-auto whitespace-pre-wrap bg-[var(--surface-deep)] p-2 text-[11px] leading-[1.4] text-muted-foreground">{data.errorDetail}</pre>
        </details>
      )}
    </div>
  );
}

export function PanelBody({ panel, data, longRange }: { panel: PanelSpec; data: PanelData; longRange: boolean }) {
  if (data.error) return <PanelError data={data} />;
  switch (panel.type) {
    case "timeseries":
      return <TimeSeriesPanel panel={panel} data={data} longRange={longRange} />;
    case "bar":
      return <BarPanel panel={panel} data={data} />;
    case "stat":
      return <StatPanel panel={panel} data={data} />;
    default:
      return <TablePanel data={data} />;
  }
}

const TYPE_LABEL: Record<PanelSpec["type"], string> = { timeseries: "ряд", bar: "столбцы", stat: "число", table: "таблица" };

/**
 * Сетка 24 колонки как в Grafana: w — ширина в колонках, h — высота в строках
 * по 40px. Адаптив — в CSS (.dash-panel): < lg все панели во всю ширину,
 * lg…xl узкие панели по половине, ≥ xl как задано.
 */
export function DashboardGrid({ panels, data, longRange }: { panels: PanelSpec[]; data: Record<string, PanelData>; longRange: boolean }) {
  return (
    <div className="dash-grid">
      {panels.map((p) => {
        const d = data[p.id] ?? { columns: [], rows: [], ms: 0 };
        return (
          <Panel
            key={p.id}
            label={p.title || p.id}
            meta={`${TYPE_LABEL[p.type]} · ${fmtMs(d.ms)}${d.cached ? " · кэш" : ""}${d.truncated ? " · обрезано" : ""}`}
            className="dash-panel flex min-w-0 flex-col"
            bodyClassName="min-h-0 flex-1"
            style={{ "--w": p.w, "--wm": panelSpanMedium(p.w), "--dash-h": `${p.h * 40}px` } as React.CSSProperties}
          >
            <PanelBody panel={p} data={d} longRange={longRange} />
          </Panel>
        );
      })}
    </div>
  );
}
