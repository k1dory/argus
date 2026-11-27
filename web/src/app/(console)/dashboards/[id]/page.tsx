import type { Metadata } from "next";
import Link from "next/link";
import { notFound } from "next/navigation";
import { Pencil } from "lucide-react";
import { AutoRefresh } from "@/components/console/auto-refresh";
import { DashboardGrid } from "@/components/console/dash-panels";
import { Empty, PageHeader, Panel } from "@/components/console/panel";
import { RangePicker } from "@/components/console/range-picker";
import { StorageUnavailable } from "@/components/console/storage-error";
import { Button } from "@/components/ui/button";
import { requirePageSession, ROLE_RANK } from "@/lib/auth";
import { safeQuery } from "@/lib/clickhouse";
import { getDashboard, refreshSeconds, runPanelQuery, stripPanelDetail, type PanelData } from "@/lib/dashboards";
import { isLongRange } from "@/lib/shared/time";
import { RangeFilters } from "@/components/console/range-filters";
import { BoardErrorBanner } from "@/components/console/dashboard-board";
import { boardTime, commonPanelError, intervalLabel } from "@/lib/shared/dashboard-view";
import { patchHref } from "@/lib/shared/filters";

export const dynamic = "force-dynamic";

const ID_RE = /^[a-z0-9][a-z0-9-]{1,63}$/;

export async function generateMetadata({ params }: PageProps<"/dashboards/[id]">): Promise<Metadata> {
  const { id } = await params;
  if (!ID_RE.test(id)) return { title: "Дашборд" };
  const r = await safeQuery(() => getDashboard(id));
  return { title: `${r.data?.title ?? id} · Дашборды` };
}

export default async function DashboardPage({ params, searchParams }: PageProps<"/dashboards/[id]">) {
  const session = await requirePageSession();
  const canEdit = ROLE_RANK[session.role] >= ROLE_RANK.analyst;
  const { id } = await params;
  if (!ID_RE.test(id)) notFound();
  const sp = await searchParams;
  // Пресет (range или period) — только из белого списка общего парсера; точный интервал
  // (from/to, UTC) главнее пресета: макросы $__timeFilter/$__from/$__to получают его границы параметрами.
  // При точном интервале ни один пресет не подсвечен (boardTime.picker = undefined).
  const bt = boardTime(sp);
  const { time, range } = bt;
  const window = bt.window;
  const specRes = await safeQuery(() => getDashboard(id));
  if (!specRes.ok) {
    return (
      <>
        <PageHeader title={id} />
        <StorageUnavailable reason={specRes.error} />
      </>
    );
  }
  const spec = specRes.data;
  if (!spec) notFound();
  const refreshSec = refreshSeconds(spec);
  // Результат панели живёт в кэше процесса ровно интервал автообновления:
  // несколько вкладок дежурных не гоняют один SQL параллельно.
  const ttlMs = refreshSec > 0 ? refreshSec * 1000 : 0;
  const results = await Promise.all(spec.panels.map((p) => runPanelQuery(p.sql, window, ttlMs)));
  const data: Record<string, PanelData> = {};
  const admin = session.role === "admin";
  spec.panels.forEach((p, i) => (data[p.id] = canEdit ? results[i] : stripPanelDetail(results[i])));
  // Одна причина на всю доску — одна плашка над сеткой, панели свёрнуты.
  const common = commonPanelError(results);
  const interval = intervalLabel(time);

  return (
    <>
      <PageHeader
        title={spec.title}
        subtitle={spec.description}
        actions={
          <>
            {refreshSec > 0 && <AutoRefresh seconds={refreshSec} />}
            {canEdit && (
              <Button asChild variant="secondary" size="sm"><Link href={`/dashboards/${spec.id}/edit?${bt.query}`}><Pencil strokeWidth={1.5} />Редактировать</Link></Button>
            )}
          </>
        }
      />
      <div className="flex flex-wrap items-center gap-3">
        <RangePicker value={bt.picker} />
        {interval ? (
          <Button asChild variant="secondary" size="sm" aria-pressed="true">
            <Link href={patchHref(`/dashboards/${spec.id}`, sp, { from: undefined, to: undefined })} aria-label={`Сбросить интервал ${interval}`}>
              <span className="font-mono tabular-nums">{interval}</span> ✕
            </Link>
          </Button>
        ) : null}
        <details className="group">
          <summary className="cursor-pointer list-none text-[13px] text-muted-foreground hover:text-foreground">
            Свой интервал <span aria-hidden className="inline-block transition-transform group-open:rotate-180">▾</span>
          </summary>
          <div className="mt-3"><RangeFilters time idPrefix="dash" /></div>
        </details>
      </div>
      {common && spec.panels.length > 0 && <BoardErrorBanner error={common.error} detail={admin ? common.detail : undefined} admin={admin} />}
      {spec.panels.length === 0 ? (
        <Panel label="Пусто"><Empty>В дашборде нет панелей{canEdit ? " — добавьте их в редакторе." : "."}</Empty></Panel>
      ) : (
        <DashboardGrid panels={spec.panels} data={data} longRange={isLongRange(range, time.from)} collapsed={Boolean(common)} showType={canEdit} />
      )}
    </>
  );
}
