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
import { eventsByClass, incidentsList, incidentStats, sourcesHealthReport, type ClassCount, type IncidentRow, type SourceHealth } from "@/lib/argus-queries";
import { engineState } from "@/lib/clickhouse";
import { fmtNum, isLongRange } from "@/lib/shared/time";
import { groupFeedByDay } from "@/lib/shared/feed";
import { countOf, INCIDENTS_FORMS, SOURCES_FORMS } from "@/lib/shared/plural";
import { sourceStatusPhrase, splitByStatus } from "@/lib/shared/source-status";
import { incidentLevelLabel } from "@/lib/shared/labels";
import { Ago } from "@/components/console/ago";
import { FeedDay, FeedList, FeedRow } from "@/components/console/feed";
import { LEVEL_TONE, toneFor } from "@/components/console/tone";
import { Button } from "@/components/ui/button";
import {
  ArrowRight, CircleAlert, CircleCheck, Info, OctagonAlert, RadioTower, ServerCrash, ShieldCheck, Siren, TriangleAlert, Unplug, type LucideIcon,
} from "lucide-react";
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
      <Suspense
        fallback={
          <>
            <PanelSkeleton label="Требует внимания" lines={3} />
            <StatRowSkeleton />
          </>
        }
      >
        <SiemOverview range={range} />
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

/** Данные первого экрана: одна выборка на «Требует внимания», плитки, ленту и классы. */
async function SiemOverview({ range }: { range: RangeKey }) {
  const [r, engine] = await Promise.all([
    safeQuery(() =>
      Promise.all([
        incidentStats(),
        eventsByClass(RANGES[range].hours),
        sourcesHealthReport(),
        incidentsList({ queue: "open", level: "critical", pageSize: 10 }),
        incidentsList({ pageSize: 10 }),
      ]),
    ),
    engineState(),
  ]);
  if (!r.ok) return <StorageUnavailable reason={r.error} />;
  const [inc, classes, health, critical, recent] = r.data;
  const now = new Date();
  const sources = health.sources;
  const silent = splitByStatus(sources).silent;
  const silentTotal = silent.length + health.omitted;
  const sourcesTotal = sources.length + health.omitted;
  const eventsTotal = classes.reduce((a, c) => a + c.count, 0);
  const eps = sources.reduce((a, h) => a + h.eps_60s, 0);
  const period = RANGES[range].label;

  return (
    <>
      <Attention
        engineDown={!engine.ok}
        engineCheckedAt={engine.checkedAt}
        silent={silent}
        silentTotal={silentTotal}
        sourcesTotal={sourcesTotal}
        intakeStopped={sources.length > 0 && eps === 0}
        escalated={inc.escalated}
        critical={critical.rows}
        criticalTotal={critical.total}
        now={now}
      />

      <div className="grid grid-cols-2 gap-6 md:grid-cols-4">
        <StatTile
          label="Открыто сейчас"
          value={fmtNum(inc.open)}
          tone={critical.total > 0 || inc.escalated > 0 ? "err" : inc.open > 0 ? "warn" : "ok"}
          href="/incidents?queue=open"
          sub={critical.total > 0 ? `из них критичных: ${fmtNum(critical.total)}` : "за всё время, без учёта периода"}
        />
        <StatTile
          label="Эскалировано сейчас"
          value={fmtNum(inc.escalated)}
          tone={inc.escalated > 0 ? "err" : undefined}
          href="/incidents?status=escalated"
          sub={inc.escalated > 0 ? "ждут решения старшей смены" : "эскалаций нет"}
        />
        <StatTile
          label={`Событий за ${period}`}
          value={fmtNum(eventsTotal)}
          tone={eventsTotal === 0 ? "err" : undefined}
          sub="по времени приёма в ARGUS"
          note={eventsTotal === 0 ? "приём событий стоит" : undefined}
          noteTone="err"
        />
        <StatTile
          label="Молчат источники"
          value={`${fmtNum(silentTotal)} / ${fmtNum(sourcesTotal)}`}
          tone={sourcesTotal === 0 ? "warn" : silentTotal > 0 ? "err" : "ok"}
          href="/sources?status=silent"
          sub={sourcesTotal === 0 ? "источников ещё нет" : silentTotal > 0 ? "дольше своего обычного ритма" : "все шлют события в своём ритме"}
        />
      </div>

      <div className="grid gap-6 lg:grid-cols-[minmax(0,1.6fr)_minmax(0,1fr)]">
        <RecentIncidents rows={recent.rows} total={recent.total} now={now} />
        <ClassesPanel classes={classes} known={sources.map((s) => s.source_class)} period={period} />
      </div>
    </>
  );
}

const LEVEL_ICON: Record<string, LucideIcon> = { critical: OctagonAlert, high: TriangleAlert, medium: CircleAlert, low: Info };
const incidentMeta = (i: IncidentRow): string[] => [i.actor_name, i.node, i.sources.join(", ")].filter(Boolean);

/**
 * «Требует внимания»: по строке на проблему — отказ движка, молчащие
 * источники, остановленный приём, эскалации, открытые критичные инциденты.
 * Нет проблем — одна строка «Всё в порядке».
 */
function Attention({
  engineDown, engineCheckedAt, silent, silentTotal, sourcesTotal, intakeStopped, escalated, critical, criticalTotal, now,
}: {
  engineDown: boolean;
  engineCheckedAt: number;
  silent: SourceHealth[];
  silentTotal: number;
  sourcesTotal: number;
  intakeStopped: boolean;
  escalated: number;
  critical: IncidentRow[];
  criticalTotal: number;
  now: Date;
}) {
  const rows: React.ReactNode[] = [];
  if (engineDown) {
    rows.push(
      <FeedRow key="engine" icon={ServerCrash} flagged title="Движок корреляции не отвечает — новые инциденты не создаются"
        meta={["события продолжают приниматься и сохраняются", <>проверено <Ago ts={engineCheckedAt} now={now} /></>]} href="/rules" linkTitle="Правила корреляции и состояние движка" />,
    );
  }
  if (intakeStopped) {
    rows.push(
      <FeedRow key="intake" icon={Unplug} flagged title="Приём событий стоит: за последнюю минуту не пришло ни одного события"
        meta={[`${countOf(sourcesTotal, SOURCES_FORMS)} за 30 суток`, "проверьте коллектор"]} href="/sources" linkTitle="Источники" />,
    );
  }
  if (silentTotal > 0) {
    const longest = silent[0];
    rows.push(
      <FeedRow key="silent" icon={RadioTower} flagged title={`Молчат ${fmtNum(silentTotal)} из ${countOf(sourcesTotal, SOURCES_FORMS)}`}
        meta={["дольше своего обычного ритма", longest ? `дольше всех — ${longest.source}, ${sourceStatusPhrase(longest).head.toLowerCase()}` : null]}
        href="/sources?status=silent" linkTitle="Молчащие источники" />,
    );
  }
  if (escalated > 0) {
    rows.push(
      <FeedRow key="escalated" icon={Siren} flagged title={`Эскалировано: ${countOf(escalated, INCIDENTS_FORMS)}`}
        meta={["ждут решения старшей смены"]} href="/incidents?status=escalated" linkTitle="Эскалированные инциденты" />,
    );
  }
  const shown = critical.slice(0, 5);
  for (const i of shown) {
    rows.push(
      <FeedRow key={`inc-${i.incident_id}`} icon={OctagonAlert} flagged title={i.rule_title || i.rule_id} badge={{ label: "критический" }}
        meta={incidentMeta(i)} time={<Ago ts={i.created_at} now={now} />} href={`/incidents/${encodeURIComponent(i.incident_id)}`} linkTitle={`Открыть ${i.incident_id}`} />,
    );
  }
  if (criticalTotal > shown.length) {
    rows.push(
      <FeedRow key="more-critical" icon={ArrowRight} tone="err" title={`Ещё ${fmtNum(criticalTotal - shown.length)} открытых критичных`}
        href="/incidents?queue=open&level=critical" linkTitle="Все открытые критичные инциденты" />,
    );
  }
  const problems = rows.length;
  return (
    <Panel label="Требует внимания" tone={problems > 0 ? "err" : undefined} meta={problems > 0 ? countOf(problems, ["пункт", "пункта", "пунктов"]) : undefined}>
      <FeedList label="Что требует внимания">
        <ul className="divide-y divide-border/70">
          {problems > 0 ? rows : <FeedRow icon={CircleCheck} tone="ok" title="Всё в порядке" meta={["службы отвечают, источники шлют события в своём ритме, критичных инцидентов нет"]} />}
        </ul>
      </FeedList>
    </Panel>
  );
}

function RecentIncidents({ rows, total, now }: { rows: IncidentRow[]; total: number; now: Date }) {
  return (
    <Panel
      label="Последние инциденты"
      meta={total > 0 ? `всего ${fmtNum(total)}` : undefined}
      actions={<Button asChild variant="ghost" size="xs"><Link href="/incidents">Все инциденты →</Link></Button>}
    >
      {rows.length === 0 ? (
        <Empty icon={ShieldCheck} title="Инцидентов пока нет" hint="Появятся, когда правила корреляции найдут подозрительную активность." />
      ) : (
        <FeedList label="Последние инциденты">
          {groupFeedByDay(rows, (i) => i.created_at, now).map((g) => (
            <FeedDay key={g.key} heading={g.heading}>
              {g.items.map((i) => {
                const tone = toneFor(LEVEL_TONE, i.level);
                const hot = i.level === "critical" || i.level === "high";
                return (
                  <FeedRow
                    key={i.incident_id}
                    icon={LEVEL_ICON[i.level] ?? CircleAlert}
                    title={i.rule_title || i.rule_id}
                    badge={{ label: incidentLevelLabel(i.level), tone: hot ? tone : "muted" }}
                    meta={incidentMeta(i)}
                    time={<Ago ts={i.created_at} now={now} />}
                    flagged={hot}
                    tone={hot ? tone : undefined}
                    href={`/incidents/${encodeURIComponent(i.incident_id)}`}
                    linkTitle={`Открыть ${i.incident_id}`}
                  />
                );
              })}
            </FeedDay>
          ))}
        </FeedList>
      )}
    </Panel>
  );
}

/** Классы источников за период; классы, известные по источникам, но без событий — отдельной строкой тоном ошибки. */
function ClassesPanel({ classes, known, period }: { classes: ClassCount[]; known: string[]; period: string }) {
  const max = Math.max(1, ...classes.map((c) => c.count));
  const seen = new Set(classes.map((c) => c.source_class));
  const missing = [...new Set(known)].filter((k) => k && !seen.has(k)).sort();
  return (
    <Panel label="Получено по классам" meta={`по времени приёма · ${period}`}>
      {classes.length === 0 ? (
        <Empty
          title="За период событий не поступало"
          action={<Button asChild variant="secondary" size="sm"><Link href="/sources">Проверить источники →</Link></Button>}
        />
      ) : (
        <ul className="flex flex-col gap-1">
          {classes.map((c) => (
            <li key={c.source_class}>
              <Link
                href={`/sources?class=${encodeURIComponent(c.source_class)}`}
                className="block rounded-md px-3 py-2 transition-colors hover:bg-[var(--surface-elevated)] focus-visible:outline-offset-[-2px]"
              >
                <span className="flex items-baseline justify-between gap-3">
                  <span className="min-w-0 truncate text-sm text-foreground">
                    {c.source_class}
                    <span className="ml-2 text-xs text-muted-foreground">{countOf(c.sources, SOURCES_FORMS)}</span>
                  </span>
                  <span className="font-mono text-sm tabular-nums text-foreground">{fmtNum(c.count)}</span>
                </span>
                <span className="mt-1.5 block h-1 bg-[var(--surface-deep)]" aria-hidden>
                  <span className="block h-1 bg-[var(--chart-5)]" style={{ width: `${Math.max(1, Math.round((c.count / max) * 100))}%` }} />
                </span>
              </Link>
            </li>
          ))}
        </ul>
      )}
      {missing.length > 0 && (
        <p className="mt-3 border-t border-border px-3 pt-3 text-xs text-[var(--status-err)]">
          Нет событий за {period}: {missing.join(" · ")}
        </p>
      )}
    </Panel>
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
