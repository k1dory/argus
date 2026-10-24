import type { Metadata } from "next";
import Link from "next/link";
import { notFound, redirect } from "next/navigation";
import { ArrowLeft } from "lucide-react";
import { DashboardEditor } from "@/components/console/dashboard-editor";
import { PageHeader } from "@/components/console/panel";
import { RangePicker } from "@/components/console/range-picker";
import { StorageUnavailable } from "@/components/console/storage-error";
import { Button } from "@/components/ui/button";
import { requirePageSession, ROLE_RANK } from "@/lib/auth";
import { parseRange, safeQuery } from "@/lib/clickhouse";
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
  const range = parseRange((await searchParams).range as string | undefined);
  const r = await safeQuery(() => getDashboard(id));
  if (!r.ok) {
    return (
      <>
        <PageHeader title={<>Редактор · <span className="text-muted-foreground">{id}</span></>} />
        <StorageUnavailable reason={r.error} />
      </>
    );
  }
  const spec = r.data;
  if (!spec) notFound();
  return (
    <>
      <PageHeader title={<>Редактор · <span className="text-muted-foreground">{spec.title}</span></>}>
        <div className="flex flex-wrap items-center gap-3">
          <RangePicker value={range} />
          <Button asChild variant="ghost" size="sm"><Link href={`/dashboards/${spec.id}?range=${range}`}><ArrowLeft strokeWidth={1.5} />К дашборду</Link></Button>
        </div>
      </PageHeader>
      <DashboardEditor initial={spec} />
    </>
  );
}
