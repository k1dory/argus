import type { Metadata } from "next";
import Link from "next/link";
import { Empty, PageHeader, Panel } from "@/components/console/panel";
import { StorageUnavailable } from "@/components/console/storage-error";
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from "@/components/ui/table";
import { requirePageSession, ROLE_RANK } from "@/lib/auth";
import { safeQuery } from "@/lib/clickhouse";
import { listDashboards } from "@/lib/dashboards";
import { DASHBOARD_ORIGIN_LABELS } from "@/lib/shared/labels";
import { fmtNum, formatAgo, formatTs } from "@/lib/shared/time";
import { CreateDashboardForm } from "@/components/console/dashboard-create";

export const dynamic = "force-dynamic";
export const metadata: Metadata = { title: "Дашборды" };

export default async function DashboardsPage() {
  const session = await requirePageSession();
  const canEdit = ROLE_RANK[session.role] >= ROLE_RANK.analyst;
  const r = await safeQuery(() => listDashboards());
  const now = new Date();
  return (
    <>
      <PageHeader title="Дашборды">
        <span className="c-label">конструктор · панели · SQL · сетка 24</span>
      </PageHeader>
      {!r.ok ? (
        <StorageUnavailable reason={r.error} />
      ) : (
        <Panel label={`Дашборды · ${fmtNum(r.data.length)}`} meta={`${DASHBOARD_ORIGIN_LABELS.provisioned} — JSON из dashboards/`}>
          {canEdit && <div className="mb-5"><CreateDashboardForm /></div>}
          {r.data.length === 0 ? (
            <Empty>Дашбордов пока нет — {canEdit ? "создайте первый выше или положите JSON в каталог dashboards/." : "аналитик может создать их в конструкторе."}</Empty>
          ) : (
            <div className="c-well overflow-x-auto p-2">
              <Table>
                <TableHeader>
                  <TableRow>
                    <TableHead className="c-label">Название</TableHead>
                    <TableHead className="c-label">ID</TableHead>
                    <TableHead className="c-label">Обновлён (UTC)</TableHead>
                    <TableHead className="c-label">Кем</TableHead>
                    <TableHead className="c-label">Источник</TableHead>
                  </TableRow>
                </TableHeader>
                <TableBody>
                  {r.data.map((d) => (
                    <TableRow key={d.id}>
                      <TableCell className="whitespace-normal"><Link href={`/dashboards/${d.id}`} className="text-[var(--ring)] hover:underline">{d.title}</Link></TableCell>
                      <TableCell className="font-mono text-xs text-muted-foreground">{d.id}</TableCell>
                      <TableCell className="font-mono text-xs" title={formatAgo(d.updated_at, now)}>{formatTs(d.updated_at)}</TableCell>
                      <TableCell className="text-xs">{d.updated_by}</TableCell>
                      <TableCell className="text-xs">{d.provisioned ? DASHBOARD_ORIGIN_LABELS.provisioned : DASHBOARD_ORIGIN_LABELS.console}</TableCell>
                    </TableRow>
                  ))}
                </TableBody>
              </Table>
            </div>
          )}
        </Panel>
      )}
    </>
  );
}
