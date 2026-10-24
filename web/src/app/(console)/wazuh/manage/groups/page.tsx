import Link from "next/link";
import { Trash2 } from "lucide-react";
import { Panel } from "@/components/console/panel";
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
  let offline: string | null = null;
  try {
    groups = await listGroups();
  } catch (err) {
    console.error("manage/groups:", err instanceof Error ? err.message : err);
    offline = "Wazuh API недоступен — подробности в логе консоли";
  }

  return (
    <>
      <div className="flex flex-wrap items-center justify-between gap-4">
        <h1 className="text-3xl tracking-tight">Группы агентов</h1>
        <span className="c-label">agent.conf разъезжается штатно, как в Wazuh</span>
      </div>

      {offline ? (
        <Panel label="Wazuh manager API · недоступен">
          <p className="text-sm text-destructive">{offline}</p>
        </Panel>
      ) : (
        <Panel label={`Группы · ${groups.length} шт.`} meta={canEdit ? undefined : "только чтение"}>
          {canEdit && (
            <div className="mb-6">
              <GroupCreateForm />
            </div>
          )}
          <div className="c-well overflow-x-auto p-2">
            <Table>
              <TableHeader>
                <TableRow className="border-border/60">
                  <TableHead className="c-label">Группа</TableHead>
                  <TableHead className="c-label text-right">Агентов</TableHead>
                  <TableHead className="c-label">Checksum конфигурации</TableHead>
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
                      >
                        {g.name}
                      </Link>
                    </TableCell>
                    <TableCell className="text-right font-mono text-xs">{g.count ?? 0}</TableCell>
                    <TableCell className="font-mono text-xs text-muted-foreground">
                      {g.configSum ?? "—"}
                    </TableCell>
                    {isAdmin && (
                      <TableCell className="text-right">
                        {g.name !== "default" && (
                          <ConfirmActionForm
                            action={deleteGroupAction}
                            title={`Удалить группу «${g.name}»?`}
                            description="Её агенты вернутся в default, agent.conf группы будет потерян."
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
        </Panel>
      )}
    </>
  );
}
