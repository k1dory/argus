import type { Metadata } from "next";
import Link from "next/link";
import { LayoutDashboard } from "lucide-react";
import { Ago } from "@/components/console/ago";
import { Empty, PageHeader, Panel } from "@/components/console/panel";
import { StorageUnavailable } from "@/components/console/storage-error";
import { Badge } from "@/components/ui/badge";
import { requirePageSession, ROLE_RANK } from "@/lib/auth";
import { safeQuery } from "@/lib/clickhouse";
import { listDashboards, type DashboardRow } from "@/lib/dashboards";
import { countOf, PANELS_FORMS } from "@/lib/shared/plural";
import { fmtNum } from "@/lib/shared/time";
import { CreateDashboardButton } from "@/components/console/dashboard-create";

export const dynamic = "force-dynamic";
export const metadata: Metadata = { title: "Дашборды" };

/** Описание и число панелей — из сохранённой спецификации; битый JSON не роняет список. */
function summary(d: DashboardRow): { description: string; panels: number | null } {
  try {
    const s = JSON.parse(d.spec) as { description?: unknown; panels?: unknown };
    return {
      description: typeof s.description === "string" ? s.description : "",
      panels: Array.isArray(s.panels) ? s.panels.length : null,
    };
  } catch {
    return { description: "", panels: null };
  }
}

export default async function DashboardsPage() {
  const session = await requirePageSession();
  const canEdit = ROLE_RANK[session.role] >= ROLE_RANK.analyst;
  const r = await safeQuery(() => listDashboards());
  const now = new Date();
  return (
    <>
      <PageHeader
        title="Дашборды"
        subtitle="Подборки графиков и таблиц по событиям и инцидентам."
        actions={canEdit ? <CreateDashboardButton /> : undefined}
      />
      {!r.ok ? (
        <StorageUnavailable reason={r.error} />
      ) : r.data.length === 0 ? (
        <Panel label="Дашборды">
          <Empty
            icon={LayoutDashboard}
            title="Дашбордов пока нет"
            hint={canEdit ? "Создайте первый кнопкой «Новый дашборд» вверху." : "Аналитик может создать их в конструкторе."}
          />
        </Panel>
      ) : (
        <Panel label="Дашборды" meta={fmtNum(r.data.length)} bodyClassName="p-0">
          <ul className="divide-y divide-border/70">
            {r.data.map((d) => {
              const s = summary(d);
              return (
                <li key={d.id}>
                  <Link
                    href={`/dashboards/${d.id}`}
                    title={d.id}
                    className="flex items-start gap-4 px-5 py-3 transition-colors hover:bg-[var(--surface-elevated)] focus-visible:outline-offset-[-2px]"
                  >
                    <LayoutDashboard className="mt-0.5 size-4 shrink-0 text-muted-foreground" strokeWidth={1.5} aria-hidden />
                    <span className="min-w-0 flex-1">
                      <span className="flex items-center gap-2">
                        <span className="truncate text-sm font-medium text-foreground">{d.title}</span>
                        {d.provisioned ? <Badge variant="outline" className="shrink-0 text-[11px]">Встроенный</Badge> : null}
                      </span>
                      {s.description && <span className="mt-0.5 line-clamp-1 block text-xs text-muted-foreground">{s.description}</span>}
                    </span>
                    <span className="shrink-0 text-right text-xs text-muted-foreground">
                      {s.panels !== null && <span className="block">{countOf(s.panels, PANELS_FORMS)}</span>}
                      <span className="block">
                        {d.provisioned ? "обновлён " : `${d.updated_by} · `}
                        <Ago ts={d.updated_at} now={now} />
                      </span>
                    </span>
                  </Link>
                </li>
              );
            })}
          </ul>
        </Panel>
      )}
    </>
  );
}
