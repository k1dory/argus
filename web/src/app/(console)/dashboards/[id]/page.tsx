import type { Metadata } from "next";
import Link from "next/link";
import { notFound } from "next/navigation";
import { Pencil, Trash2 } from "lucide-react";
import { ConfirmActionForm } from "@/components/console/action-form";
import { AutoRefresh } from "@/components/console/auto-refresh";
import { DashboardGrid } from "@/components/console/dash-panels";
import { Empty, PageHeader, Panel } from "@/components/console/panel";
import { RangePicker } from "@/components/console/range-picker";
import { StorageUnavailable } from "@/components/console/storage-error";
import { Button } from "@/components/ui/button";
import { requirePageSession, ROLE_RANK } from "@/lib/auth";
import { safeQuery } from "@/lib/clickhouse";
import { deleteDashboardAction } from "@/lib/dashboard-actions";
import { getDashboard, refreshSeconds, runPanelQuery, stripPanelDetail, type PanelData } from "@/lib/dashboards";
import { isLongRange } from "@/lib/shared/time";
import { RangeFilters } from "@/components/console/range-filters";
import { parseTimeFilter } from "@/lib/shared/filters";

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
  const time = parseTimeFilter(sp, { defaultRange: "24h" });
  const range = time.range ?? "24h";
  const window = time.from ? time : range;
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
  spec.panels.forEach((p, i) => (data[p.id] = canEdit ? results[i] : stripPanelDetail(results[i])));

  return (
    <>
      <PageHeader title={spec.title} subtitle={spec.description}>
        <div className="flex flex-wrap items-center gap-3">
          {refreshSec > 0 && <AutoRefresh seconds={refreshSec} />}
          <RangePicker value={range} />
          {canEdit && (
            <>
              <Button asChild variant="secondary" size="sm"><Link href={`/dashboards/${spec.id}/edit?range=${range}`}><Pencil strokeWidth={1.5} />Редактировать</Link></Button>
              <ConfirmActionForm
                action={deleteDashboardAction}
                title="Удалить дашборд"
                description={<>Дашборд «{spec.title}» ({spec.id}) будет скрыт из списка. Версии остаются в console_dashboards, вернуть можно вручную.</>}
                confirmLabel="Да, удалить"
              >
                <input type="hidden" name="id" value={spec.id} />
                <Button type="submit" variant="ghost" size="sm"><Trash2 strokeWidth={1.5} />Удалить</Button>
              </ConfirmActionForm>
            </>
          )}
        </div>
      </PageHeader>
      <RangeFilters time idPrefix="dash" />
      {spec.panels.length === 0 ? (
        <Panel label="Пусто"><Empty>В дашборде нет панелей{canEdit ? " — добавьте их в редакторе." : "."}</Empty></Panel>
      ) : (
        <DashboardGrid panels={spec.panels} data={data} longRange={isLongRange(range, time.from)} />
      )}
    </>
  );
}
