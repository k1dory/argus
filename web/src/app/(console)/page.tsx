import type { Metadata } from "next";
import Link from "next/link";
import { Suspense } from "react";
import { AlertsSeriesChart, TacticsChart, TopRulesChart } from "@/components/console/charts";
import { AutoRefresh } from "@/components/console/auto-refresh";
import { Empty, PageHeader, Panel, StatTile } from "@/components/console/panel";
import { RangePicker } from "@/components/console/range-picker";
import { ChartSkeleton, PanelSkeleton, StatRowSkeleton } from "@/components/console/skeletons";
import { StorageUnavailable } from "@/components/console/storage-error";
import { parseRange, RANGES, safeQuery, type RangeKey } from "@/lib/clickhouse";
import { alertsSeries, overviewStats, topRules, topTactics } from "@/lib/queries";
import { eventsByClass, incidentStats } from "@/lib/argus-queries";
import { fmtNum, isLongRange } from "@/lib/shared/time";
import { requirePageSession } from "@/lib/auth";
import { wazuhEnabled } from "@/lib/integrations";

export const dynamic = "force-dynamic";
export const metadata: Metadata = { title: "Обзор" };

const REFRESH_SEC = 30;

export default async function OverviewPage({ searchParams }: PageProps<"/">) {
  await requirePageSession();
  const range = parseRange((await searchParams).range as string | undefined);
  // Витрины алертов менеджера — только с модулем Wazuh: без него запросов к
  // wazuh_alerts нет, обзор состоит из инцидентов и событий единой схемы.
  const wazuh = wazuhEnabled();

  return (
    <>
      <PageHeader title="Обзор">
        <div className="flex flex-wrap items-center gap-4">
          <AutoRefresh seconds={REFRESH_SEC} />
          <RangePicker value={range} />
        </div>
      </PageHeader>

      {/* Каждый блок грузится сам: шапка и фильтры видны сразу, тяжёлые запросы — со скелетами */}
      <Suspense fallback={<StatRowSkeleton />}>
        <SiemRow range={range} />
      </Suspense>

      {wazuh && (
        <>
          <div className="c-label">Источник Wazuh · алерты менеджера</div>
          <Suspense fallback={<StatRowSkeleton />}>
            <WazuhRow range={range} />
          </Suspense>

          <Suspense fallback={<ChartSkeleton label="Алерты по времени и серьёзности" />}>
            <SeriesPanel range={range} />
          </Suspense>

          <Suspense
            fallback={
              <div className="grid gap-6 lg:grid-cols-2">
                <PanelSkeleton label="Топ правил" lines={6} />
                <PanelSkeleton label="Тактики MITRE ATT&CK" lines={6} />
              </div>
            }
          >
            <TopPanels range={range} />
          </Suspense>
        </>
      )}
    </>
  );
}

async function SiemRow({ range }: { range: RangeKey }) {
  const r = await safeQuery(() => Promise.all([incidentStats(), eventsByClass(RANGES[range].hours)]));
  if (!r.ok) return <StorageUnavailable reason={r.error} />;
  const [inc, classes] = r.data;
  const eventsTotal = classes.reduce((a, c) => a + c.count, 0);
  return (
    <>
      <div className="grid grid-cols-2 gap-6 md:grid-cols-4">
        <StatTile
          label="Открытых инцидентов"
          value={fmtNum(inc.open)}
          led={inc.escalated > 0 ? "var(--status-err)" : inc.open > 0 ? "var(--status-warn)" : "var(--status-ok)"}
          href="/incidents?queue=open"
          hint="Все открытые инциденты, независимо от выбранного периода"
        />
        <StatTile label="Эскалация" value={fmtNum(inc.escalated)} href="/incidents?status=escalated" hint="Все эскалированные инциденты" />
        <StatTile label="Получено за период" value={fmtNum(eventsTotal)} hint="По времени поступления в ARGUS, включая загрузку архивных событий" />
        <StatTile label="Классов источников" value={fmtNum(classes.length)} hint="Среди событий, полученных за выбранный период" />
      </div>
      <p className="text-xs text-muted-foreground">
        Инциденты — текущее состояние за всё время; события — поступления за выбранный период.
      </p>

      <Panel label="Получено по классам источников" meta="по времени приёма · ngfw · edr · k8s · cicd · netflow · syslog · wazuh">
        {classes.length === 0 ? (
          <Empty>
            ClickHouse отвечает, но за выбранный период новые события не поступали. Проверьте <Link href="/sources" className="text-[var(--ring)] hover:underline">источники</Link> или сделайте <span className="font-mono">make replay</span>.
          </Empty>
        ) : (
          <ul className="grid gap-2 sm:grid-cols-2 lg:grid-cols-3">
            {classes.map((c) => (
              <li key={c.source_class} className="flex items-center justify-between border border-border bg-[var(--surface-deep)] px-3 py-2 font-mono text-xs">
                <span>{c.source_class}<span className="text-muted-foreground"> · {fmtNum(c.sources)} ист.</span></span>
                <span>{fmtNum(c.count)}</span>
              </li>
            ))}
          </ul>
        )}
        <p className="mt-3 text-xs text-muted-foreground">
          Подробнее: <Link href="/incidents" className="text-[var(--ring)] hover:underline">инциденты</Link> · <Link href="/sources" className="text-[var(--ring)] hover:underline">источники</Link>
        </p>
      </Panel>
    </>
  );
}

async function WazuhRow({ range }: { range: RangeKey }) {
  const r = await safeQuery(() => overviewStats(range));
  if (!r.ok) return <StorageUnavailable reason={r.error} />;
  const stats = r.data;
  return (
    <div className="grid grid-cols-2 gap-6 md:grid-cols-4">
      <StatTile label="Алертов Wazuh" value={fmtNum(stats.total)} />
      <StatTile
        label="Критичных (уровень 12+)"
        value={fmtNum(stats.critical)}
        led={stats.critical > 0 ? "var(--status-err)" : "var(--status-ok)"}
      />
      <StatTile label="Агентов слали" value={fmtNum(stats.agents)} />
      <StatTile
        label="Соответствие политикам"
        value={stats.compliance === null ? "—" : fmtNum(stats.compliance, 1)}
        unit={stats.compliance === null ? undefined : "%"}
        hint={stats.compliance === null ? "policyd ещё не оценивал" : "доля соблюдённых проверок в последнем раунде policyd"}
        led={
          stats.compliance === null
            ? "var(--status-warn)"
            : stats.compliance >= 95
              ? "var(--status-ok)"
              : "var(--status-err)"
        }
      />
    </div>
  );
}

async function SeriesPanel({ range }: { range: RangeKey }) {
  const r = await safeQuery(() => alertsSeries(range));
  if (!r.ok) return <StorageUnavailable reason={r.error} />;
  return (
    <Panel label="Алерты по времени и серьёзности" meta="время UTC">
      {r.data.length === 0 ? <Empty>Нет данных за период</Empty> : <AlertsSeriesChart data={r.data} longRange={isLongRange(range)} />}
    </Panel>
  );
}

async function TopPanels({ range }: { range: RangeKey }) {
  const r = await safeQuery(() => Promise.all([topRules(range), topTactics(range)]));
  if (!r.ok) return <StorageUnavailable reason={r.error} />;
  const [rules, tactics] = r.data;
  return (
    <div className="grid gap-6 lg:grid-cols-2">
      <Panel label="Топ правил">
        {rules.length > 0 ? <TopRulesChart rules={rules} /> : <Empty>Нет данных за период</Empty>}
      </Panel>
      <Panel label="Тактики MITRE ATT&CK">
        {tactics.length > 0 ? <TacticsChart tactics={tactics} /> : <Empty>Нет данных за период</Empty>}
      </Panel>
    </div>
  );
}
