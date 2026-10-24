"use client";

import {
  Bar,
  BarChart,
  CartesianGrid,
  LabelList,
  XAxis,
  YAxis,
} from "recharts";
import {
  ChartContainer,
  ChartLegend,
  ChartLegendContent,
  ChartTooltip,
  ChartTooltipContent,
  type ChartConfig,
} from "@/components/ui/chart";
import type { SeriesPoint, TacticCount, TopRule } from "@/lib/queries";
import { fmtNum, formatAxisTs, formatTs } from "@/lib/shared/time";

// Серии по дизайн-системе лендинга: серое для фона, оранжевый #FF8800 —
// только на критичном. Серьёзность дублируется легендой и таблицей.
const severityConfig = {
  low: { label: "Низкая (1–6)", color: "var(--chart-1)" },
  high: { label: "Высокая (7–11)", color: "var(--chart-2)" },
  critical: { label: "Критичная (12+)", color: "var(--chart-3)" },
} satisfies ChartConfig;

const axisTick = { fill: "var(--muted-foreground)", fontSize: 11, fontFamily: "var(--font-plex-mono)" };

export function AlertsSeriesChart({
  data,
  longRange,
}: {
  data: SeriesPoint[];
  longRange: boolean;
}) {
  return (
    <ChartContainer config={severityConfig} className="h-72 w-full" role="img" aria-label="Алерты по времени и серьёзности">
      <BarChart data={data} margin={{ left: 0, right: 8, top: 8 }}>
        <CartesianGrid vertical={false} stroke="var(--border)" strokeOpacity={0.5} />
        <XAxis
          dataKey="bucket"
          tickLine={false}
          axisLine={false}
          tick={axisTick}
          tickFormatter={(v: string) => formatAxisTs(v, longRange)}
          minTickGap={32}
        />
        <YAxis tickLine={false} axisLine={false} tick={axisTick} width={40} allowDecimals={false} tickFormatter={(v: number) => fmtNum(v)} />
        <ChartTooltip
          content={<ChartTooltipContent labelFormatter={(v) => formatTs(String(v), "full")} />}
        />
        <ChartLegend content={<ChartLegendContent />} />
        {/* 2px обводка цветом поверхности = зазор между сегментами стека */}
        <Bar dataKey="low" stackId="sev" fill="var(--color-low)" stroke="var(--background)" strokeWidth={2} />
        <Bar dataKey="high" stackId="sev" fill="var(--color-high)" stroke="var(--background)" strokeWidth={2} />
        <Bar
          dataKey="critical"
          stackId="sev"
          fill="var(--color-critical)"
          stroke="var(--background)"
          strokeWidth={2}
          radius={0}
        />
      </BarChart>
    </ChartContainer>
  );
}

/* Горизонтальные бары одной последовательной краской: величина, не идентичность.
   Прямые подписи значений на концах — вместо оси. */
function HBars({
  data,
  height,
  ariaLabel,
}: {
  data: { name: string; count: number }[];
  height: number;
  ariaLabel: string;
}) {
  const config = { count: { label: "Алертов", color: "var(--chart-1)" } } satisfies ChartConfig;
  return (
    <ChartContainer config={config} style={{ height }} className="w-full" role="img" aria-label={ariaLabel}>
      <BarChart data={data} layout="vertical" margin={{ left: 8, right: 40 }}>
        <XAxis type="number" hide />
        <YAxis
          type="category"
          dataKey="name"
          tickLine={false}
          axisLine={false}
          tick={axisTick}
          width={190}
          tickFormatter={(v: string) => (v.length > 26 ? v.slice(0, 25) + "…" : v)}
        />
        <ChartTooltip content={<ChartTooltipContent />} />
        <Bar dataKey="count" fill="var(--color-count)" radius={0} barSize={14}>
          <LabelList
            dataKey="count"
            position="right"
            formatter={(v: unknown) => fmtNum(Number(v))}
            style={{ fill: "var(--muted-foreground)", fontSize: 11, fontFamily: "var(--font-plex-mono)" }}
          />
        </Bar>
      </BarChart>
    </ChartContainer>
  );
}

export function TopRulesChart({ rules }: { rules: TopRule[] }) {
  return (
    <HBars
      data={rules.map((r) => ({ name: `${r.ruleId} · ${r.description}`, count: r.count }))}
      height={Math.max(160, rules.length * 34)}
      ariaLabel="Топ правил по числу алертов"
    />
  );
}

export function TacticsChart({ tactics }: { tactics: TacticCount[] }) {
  return (
    <HBars
      data={tactics.map((t) => ({ name: t.tactic, count: t.count }))}
      height={Math.max(160, tactics.length * 34)}
      ariaLabel="Тактики MITRE ATT&CK по числу алертов"
    />
  );
}
