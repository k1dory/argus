import Link from "next/link";
import { FolderCog, RotateCw, ScrollText } from "lucide-react";
import { Led, Panel, StatTile } from "@/components/console/panel";
import { AgentGroupAdd } from "@/components/console/manage-forms";
import { ConfirmActionForm } from "@/components/console/action-form";
import { AgentWizard } from "@/components/console/agent-wizard";
import { Button } from "@/components/ui/button";
import { Badge } from "@/components/ui/badge";
import {
  Table,
  TableBody,
  TableCell,
  TableHead,
  TableHeader,
  TableRow,
} from "@/components/ui/table";
import {
  agentGroupAction,
  restartAgentAction,
  restartManagerAction,
} from "@/lib/manage-actions";
import { listAgents, listGroups, managerInfo, type WzAgent, type WzGroup } from "@/lib/wazuh-api";
import { requirePageSession, ROLE_RANK } from "@/lib/auth";
import { formatTs } from "@/lib/shared/time";

export const dynamic = "force-dynamic";
export const metadata = { title: "Управление Wazuh" };

function statusColor(status: string): string {
  if (status === "active") return "var(--status-ok)";
  if (status === "disconnected") return "var(--status-err)";
  return "var(--status-warn)";
}

export default async function ManagePage() {
  const session = await requirePageSession();
  // analyst: агенты и группы; admin: рестарт менеджера, правила, agent.conf; viewer: чтение.
  const canEdit = ROLE_RANK[session.role] >= ROLE_RANK.analyst;
  const isAdmin = session.role === "admin";
  let agents: WzAgent[] = [];
  let groups: WzGroup[] = [];
  let manager: { version: string } | null = null;
  let offline: string | null = null;
  try {
    [agents, groups, manager] = await Promise.all([listAgents(), listGroups(), managerInfo()]);
  } catch (err) {
    console.error("manage:", err instanceof Error ? err.message : err);
    offline = "Wazuh API недоступен";
  }
  const groupNames = groups.map((g) => g.name);
  const active = agents.filter((a) => a.status === "active").length;
  // Адрес менеджера для команд установки: явный WAZUH_MANAGER_HOST или хост из
  // WAZUH_API_URL — раскрывается только тем, кто может ставить агентов (analyst+).
  const managerHost = canEdit
    ? process.env.WAZUH_MANAGER_HOST || (() => { try { return new URL(process.env.WAZUH_API_URL ?? "").hostname; } catch { return ""; } })()
    : "";

  return (
    <>
      <div className="flex flex-wrap items-center justify-between gap-4">
        <h1 className="text-3xl tracking-tight">Управление</h1>
        <div className="flex flex-wrap gap-2">
          <Button asChild variant="secondary" size="sm">
            <Link href="/wazuh/manage/groups">
              <FolderCog strokeWidth={1.5} />
              Группы
            </Link>
          </Button>
          <Button asChild variant="secondary" size="sm">
            <Link href="/wazuh/manage/rules">
              <ScrollText strokeWidth={1.5} />
              Правила
            </Link>
          </Button>
        </div>
      </div>

      {canEdit && !offline && (
        <Panel label="Добавить агента" meta="команда установки, как в Wazuh dashboard">
          <AgentWizard version={manager?.version ?? ""} managerHost={managerHost} groups={groupNames} passwordRequired={process.env.WAZUH_REGISTRATION_PASSWORD_SET === "1"} />
        </Panel>
      )}

      {offline ? (
        <Panel label="Менеджер Wazuh не подключён">
          <p className="text-sm text-destructive">{offline}</p>
          <p className="mt-3 max-w-2xl text-sm text-muted-foreground">
            Укажите доступный адрес менеджера в WAZUH_API_URL и учётные данные
            WAZUH_API_USER / WAZUH_API_PASSWORD в .env. После подключения здесь
            появятся агенты, группы и команда установки нужной версии. Подробности — в журнале web.
          </p>
        </Panel>
      ) : (
        <>
          <div className="grid grid-cols-2 gap-6 md:grid-cols-4">
            <StatTile label="Менеджер" value={manager?.version ?? "—"} />
            <StatTile
              label="Агентов"
              value={String(agents.length)}
            />
            <StatTile
              label="Активных"
              value={String(active)}
              led={active === agents.length ? "var(--status-ok)" : "var(--status-warn)"}
            />
            <StatTile label="Групп" value={String(groups.length)} />
          </div>

          <Panel
            label="Агенты · регистрация и keepalive — штатные, как в Wazuh"
            meta={canEdit ? "агент 000 — сам менеджер" : "только чтение"}
          >
            {isAdmin && (
              <div className="mb-4">
                <ConfirmActionForm
                  action={restartManagerAction}
                  title="Перезапустить менеджер Wazuh?"
                  description="Обработка событий прервётся на время рестарта."
                  confirmLabel="Перезапустить"
                  successText="Менеджер перезапускается"
                >
                  <Button type="submit" variant="secondary" size="sm">
                    <RotateCw strokeWidth={1.5} />
                    Перезапустить менеджер
                  </Button>
                </ConfirmActionForm>
              </div>
            )}
            <div className="c-well overflow-x-auto p-2">
              <Table>
                <TableHeader>
                  <TableRow className="border-border/60">
                    <TableHead className="c-label">ID</TableHead>
                    <TableHead className="c-label">Агент</TableHead>
                    <TableHead className="c-label">Статус</TableHead>
                    <TableHead className="c-label">Версия</TableHead>
                    <TableHead className="c-label">Группы</TableHead>
                    <TableHead className="c-label">Keepalive</TableHead>
                    {canEdit && <TableHead className="c-label text-right">Действия</TableHead>}
                  </TableRow>
                </TableHeader>
                <TableBody>
                  {agents.map((a) => (
                    <TableRow key={a.id} className="border-border/40">
                      <TableCell className="font-mono text-xs">{a.id}</TableCell>
                      <TableCell>
                        <div className="text-sm">{a.name}</div>
                        <div className="font-mono text-xs text-muted-foreground">
                          {a.ip ?? "—"} {a.os?.name ? `· ${a.os.name}` : ""}
                        </div>
                      </TableCell>
                      <TableCell>
                        <span className="flex items-center gap-2 font-mono text-xs">
                          <Led color={statusColor(a.status)} />
                          {a.status}
                        </span>
                      </TableCell>
                      <TableCell className="font-mono text-xs">{a.version ?? "—"}</TableCell>
                      <TableCell>
                        <div className="flex flex-wrap items-center gap-1">
                          {(a.group ?? []).map((g) =>
                            canEdit && a.id !== "000" ? (
                              <ConfirmActionForm
                                key={g}
                                action={agentGroupAction}
                                title={`Убрать ${a.name} из группы ${g}?`}
                                description="Конфигурация группы перестанет применяться к агенту."
                                confirmLabel="Убрать"
                                successText={`${a.name} убран из ${g}`}
                                className="inline"
                              >
                                <input type="hidden" name="agent_id" value={a.id} />
                                <input type="hidden" name="group_id" value={g} />
                                <input type="hidden" name="op" value="remove" />
                                <button
                                  type="submit"
                                  title={`Убрать ${a.name} из группы ${g}`}
                                  className="cursor-pointer"
                                >
                                  <Badge
                                    variant="outline"
                                    className="border-border font-mono text-muted-foreground hover:border-[var(--status-err)]/40 hover:text-[var(--status-err)]"
                                  >
                                    {g} ×
                                  </Badge>
                                </button>
                              </ConfirmActionForm>
                            ) : (
                              <Badge key={g} variant="outline" className="border-border font-mono text-muted-foreground">{g}</Badge>
                            ),
                          )}
                        </div>
                      </TableCell>
                      <TableCell className="font-mono text-xs whitespace-nowrap">
                        {a.lastKeepAlive?.startsWith("9999") ? "—" : formatTs(a.lastKeepAlive)}
                      </TableCell>
                      {canEdit && (
                        <TableCell>
                          <div className="flex items-center justify-end gap-1">
                            {a.id !== "000" && (
                              <AgentGroupAdd
                                agentId={a.id}
                                groups={groupNames.filter((g) => !(a.group ?? []).includes(g))}
                              />
                            )}
                            {a.id !== "000" && (
                              <ConfirmActionForm
                                action={restartAgentAction}
                                title={`Перезапустить агента ${a.name}?`}
                                description="Сбор событий прервётся на несколько секунд."
                                confirmLabel="Перезапустить"
                                successText={`Агент ${a.name} перезапускается`}
                                className="inline"
                              >
                                <input type="hidden" name="agent_id" value={a.id} />
                                <Button
                                  type="submit"
                                  variant="ghost"
                                  size="icon"
                                  title={`Перезапустить агента ${a.name}`}
                                >
                                  <RotateCw strokeWidth={1.5} />
                                  <span className="sr-only">Перезапустить агента</span>
                                </Button>
                              </ConfirmActionForm>
                            )}
                          </div>
                        </TableCell>
                      )}
                    </TableRow>
                  ))}
                </TableBody>
              </Table>
            </div>
            {!canEdit && (
              <p className="mt-3 text-xs text-muted-foreground">
                Перезапуск агентов и группы — роль аналитика; рестарт менеджера, правила и agent.conf — администратор.
              </p>
            )}
          </Panel>
        </>
      )}
    </>
  );
}
