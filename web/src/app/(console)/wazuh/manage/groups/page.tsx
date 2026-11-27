import Link from "next/link";
import { Trash2 } from "lucide-react";
import { Empty, PageHeader, Panel } from "@/components/console/panel";
import { ServiceUnavailable } from "@/components/console/service-unavailable";
import { fmtNum } from "@/lib/shared/time";
import { GroupCreateForm } from "@/components/console/manage-forms";
import { ConfirmActionForm } from "@/components/console/action-form";
import { Button } from "@/components/ui/button";
import {
  Table,
  TableBody,
  TableCell,
  TableHead,
  TableHeader,
  TableRow,
} from "@/components/ui/table";
import { deleteGroupAction } from "@/lib/manage-actions";
import { listGroups, type WzGroup } from "@/lib/wazuh-api";
import { requirePageSession, ROLE_RANK } from "@/lib/auth";

export const dynamic = "force-dynamic";
export const metadata = { title: "Группы агентов" };

export default async function GroupsPage() {
  const session = await requirePageSession();
  const canEdit = ROLE_RANK[session.role] >= ROLE_RANK.analyst;
  const isAdmin = session.role === "admin";
  let groups: WzGroup[] = [];
  let error: string | null = null;
  try {
    groups = await listGroups();
  } catch (err) {
    error = err instanceof Error ? err.message : String(err);
    console.error("manage/groups:", error);
  }

  return (
    <>
      <PageHeader
        title="Группы агентов"
        back={{ href: "/wazuh/manage", label: "Управление Wazuh" }}
        subtitle="Настройки группы применяются ко всем её агентам при следующем подключении."
      />

      {error ? (
        <ServiceUnavailable service="wazuh" what="список групп" reason={error} />
      ) : (
        <Panel label={`Группы · ${fmtNum(groups.length)}`} meta={!canEdit ? "только чтение" : isAdmin ? undefined : "удаление — администратор"}>
          {canEdit && (
            <div className="mb-6">
              <GroupCreateForm />
            </div>
          )}
          {groups.length === 0 ? (
            <Empty title="Групп пока нет" hint={canEdit ? "Создайте первую, например «webservers»." : "Группы создаёт аналитик или администратор."} />
          ) : (
          <div className="c-well overflow-x-auto p-2">
            <Table>
              <TableHeader>
                <TableRow className="border-border/60">
                  <TableHead className="c-label">Группа</TableHead>
                  <TableHead className="c-label text-right">Агентов</TableHead>
                  <TableHead className="c-label">Настройки</TableHead>
                  {isAdmin && <TableHead className="c-label text-right">Действия</TableHead>}
                </TableRow>
              </TableHeader>
              <TableBody>
                {groups.map((g) => (
                  <TableRow key={g.name} className="border-border/40">
                    <TableCell>
                      <Link
                        href={`/wazuh/manage/groups/${encodeURIComponent(g.name)}`}
                        className="font-mono text-sm text-[var(--ring)] hover:underline"
                        title={g.configSum ? `Контрольная сумма настроек: ${g.configSum}` : undefined}
                      >
                        {g.name}
                      </Link>
                    </TableCell>
                    <TableCell className="text-right font-mono text-xs">{fmtNum(g.count ?? 0)}</TableCell>
                    <TableCell className="text-xs text-muted-foreground">
                      {g.configSum ? "заданы" : "не заданы"}
                    </TableCell>
                    {isAdmin && (
                      <TableCell className="text-right">
                        {g.name !== "default" && (
                          <ConfirmActionForm
                            action={deleteGroupAction}
                            title={`Удалить группу «${g.name}»?`}
                            description="Её агенты вернутся в группу default, настройки группы будут удалены."
                            confirmLabel="Удалить"
                            successText={`Группа ${g.name} удалена`}
                            className="inline-block text-left"
                          >
                            <input type="hidden" name="name" value={g.name} />
                            <Button
                              type="submit"
                              variant="ghost"
                              size="icon"
                              title={`Удалить группу ${g.name} (агенты вернутся в default)`}
                            >
                              <Trash2 strokeWidth={1.5} />
                              <span className="sr-only">Удалить группу</span>
                            </Button>
                          </ConfirmActionForm>
                        )}
                      </TableCell>
                    )}
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
