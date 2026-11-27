import type { Metadata } from "next";
import { notFound, redirect } from "next/navigation";
import { Trash2 } from "lucide-react";
import { ConfirmActionForm } from "@/components/console/action-form";
import { Badge } from "@/components/ui/badge";
import { deleteDashboardAction } from "@/lib/dashboard-actions";
import { boardTime } from "@/lib/shared/dashboard-view";
import { DashboardEditor } from "@/components/console/dashboard-editor";
import { PageHeader, Panel } from "@/components/console/panel";
import { RangePicker } from "@/components/console/range-picker";
import { StorageUnavailable } from "@/components/console/storage-error";
import { Button } from "@/components/ui/button";
import { requirePageSession, ROLE_RANK } from "@/lib/auth";
import { safeQuery } from "@/lib/clickhouse";
import { getDashboard } from "@/lib/dashboards";

export const dynamic = "force-dynamic";

const ID_RE = /^[a-z0-9][a-z0-9-]{1,63}$/;

export async function generateMetadata({ params }: PageProps<"/dashboards/[id]/edit">): Promise<Metadata> {
  const { id } = await params;
  if (!ID_RE.test(id)) return { title: "Редактор" };
  const r = await safeQuery(() => getDashboard(id));
  return { title: `Редактор · ${r.data?.title ?? id}` };
}

export default async function DashboardEditPage({ params, searchParams }: PageProps<"/dashboards/[id]/edit">) {
  const session = await requirePageSession();
  const { id } = await params;
  if (!ID_RE.test(id)) notFound();
  // Наблюдателю редактор не показываем — обратно на просмотр, без страницы ошибки.
  if (ROLE_RANK[session.role] < ROLE_RANK.analyst) redirect(`/dashboards/${id}`);
  const bt = boardTime(await searchParams);
  const r = await safeQuery(() => getDashboard(id));
  if (!r.ok) {
    return (
      <>
        <PageHeader title={id} back={{ href: `/dashboards/${id}?${bt.query}`, label: "К дашборду" }} />
        <StorageUnavailable reason={r.error} />
      </>
    );
  }
  const spec = r.data;
  if (!spec) notFound();
  return (
    <>
      <PageHeader
        title={spec.title}
        back={{ href: `/dashboards/${spec.id}?${bt.query}`, label: "К дашборду" }}
        status={<Badge variant="outline">Редактирование</Badge>}
        actions={<RangePicker value={bt.picker} />}
      />
      <DashboardEditor initial={spec} />
      <Panel label="Удаление дашборда" tone="err">
        <div className="flex flex-wrap items-center justify-between gap-3 text-sm">
          <p className="text-muted-foreground">Дашборд «{spec.title}» исчезнет из списка у всех. Его можно восстановить из истории версий — для этого обратитесь к администратору.</p>
          <ConfirmActionForm
            action={deleteDashboardAction}
            title="Удалить дашборд?"
            description={<>Дашборд «{spec.title}» исчезнет из списка. Его можно восстановить из истории версий (обратитесь к администратору).</>}
            confirmLabel="Да, удалить"
          >
            <input type="hidden" name="id" value={spec.id} />
            <Button type="submit" variant="destructive" size="sm"><Trash2 strokeWidth={1.5} />Удалить дашборд</Button>
          </ConfirmActionForm>
        </div>
      </Panel>
    </>
  );
}
