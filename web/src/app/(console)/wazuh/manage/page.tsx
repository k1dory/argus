import Link from "next/link";
import { FolderCog, Plus, RotateCw, ScrollText, X } from "lucide-react";
import { Ago } from "@/components/console/ago";
import { Empty, PageHeader, Panel, StatTile } from "@/components/console/panel";
import { FilterTabs } from "@/components/console/filter-tabs";
import { AgentGroupAdd } from "@/components/console/manage-forms";
import { ConfirmActionForm } from "@/components/console/action-form";
import { AgentWizard } from "@/components/console/agent-wizard";
import { ServiceUnavailable } from "@/components/console/service-unavailable";
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
import { fmtNum } from "@/lib/shared/time";
import { cn } from "@/lib/utils";
import { realKeepalive, sortByStatus } from "../_shared/agents";
import { wazuhAgentHref } from "../_shared/links";
import { AgentStatusBadge } from "../_shared/status-badge";

export const dynamic = "force-dynamic";
export const metadata = { title: "Управление Wazuh" };

/** Keepalive давнее 10 минут — агент, скорее всего, замолчал. */
const KEEPALIVE_STALE_MS = 10 * 60_000;
/** Не на связи: отключён или ни разу не подключался. */
const isOffline = (s: string) => s === "disconnected" || s === "never_connected";

export default async function ManagePage({ searchParams }: PageProps<"/wazuh/manage">) {
  const session = await requirePageSession();
  const sp = await searchParams;
  // analyst: агенты и группы; admin: рестарт менеджера, правила, agent.conf; viewer: чтение.
  const canEdit = ROLE_RANK[session.role] >= ROLE_RANK.analyst;
  const isAdmin = session.role === "admin";
  const onlyOffline = sp.status === "offline";
  const wizardOpen = sp.add === "1";
  let agents: WzAgent[] = [];
  let groups: WzGroup[] = [];
  let manager: { version: string } | null = null;
  let error: string | null = null;
  try {
    [agents, groups, manager] = await Promise.all([listAgents(), listGroups(), managerInfo()]);
  } catch (err) {
    error = err instanceof Error ? err.message : String(err);
    console.error("manage:", error);
  }
  const groupNames = groups.map((g) => g.name);
  const offline = agents.filter((a) => isOffline(a.status)).length;
  // Сначала проблемы: отключённые, не подключавшиеся, ожидающие, затем активные.
  const sorted = sortByStatus(agents);
  const rows = onlyOffline ? sorted.filter((a) => isOffline(a.status)) : sorted;
  // Адрес менеджера для команд установки: явный WAZUH_MANAGER_HOST или хост из
  // WAZUH_API_URL — раскрывается только тем, кто может ставить агентов (analyst+).
  const managerHost = canEdit
    ? process.env.WAZUH_MANAGER_HOST || (() => { try { return new URL(process.env.WAZUH_API_URL ?? "").hostname; } catch { return ""; } })()
    : "";
  const now = new Date();

  return (
    <>
      <PageHeader
        title="Управление Wazuh"
        subtitle="Агенты, группы и собственные правила менеджера Wazuh."
        actions={
          <div className="flex flex-wrap items-center gap-2">
            {canEdit && !error && (
              <Button asChild size="sm">
                <Link href="/wazuh/manage?add=1#add-agent">
                  <Plus strokeWidth={1.5} />
                  Добавить агента
                </Link>
              </Button>
            )}
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
            {isAdmin && !error && (
              <ConfirmActionForm
                action={restartManagerAction}
                title="Перезапустить менеджер Wazuh?"
                description="Обработка событий от всех агентов прервётся на время перезапуска."
                confirmLabel="Перезапустить"
                successText="Менеджер перезапускается"
                className="inline"
              >
                <Button type="submit" variant="ghost" size="sm">
                  <RotateCw strokeWidth={1.5} />
                  Перезапустить менеджер
                </Button>
              </ConfirmActionForm>
            )}
          </div>
        }
      />

      {error ? (
        <ServiceUnavailable service="wazuh" what="список агентов и групп" reason={error} />
      ) : (
        <>
          <div className="grid grid-cols-2 gap-6 md:grid-cols-4">
            <StatTile label="Менеджер" value={manager?.version ?? "—"} size="sm" sub="версия" />
            <StatTile label="Агентов" value={fmtNum(agents.length)} sub="вместе с менеджером" />
            <StatTile
              label="Не на связи"
              value={fmtNum(offline)}
              tone={offline > 0 ? "err" : "ok"}
              sub="отключены или ни разу не подключались"
              href={offline > 0 ? "/wazuh/manage?status=offline" : undefined}
            />
            <StatTile label="Групп" value={fmtNum(groups.length)} />
          </div>

          <Panel label={`Агенты · ${fmtNum(rows.length)}`} meta={canEdit ? "агент 000 — сам менеджер" : "только чтение"}>
            <FilterTabs
              label="Какие агенты показать"
              className="mb-4"
              current={onlyOffline ? "offline" : "all"}
              items={[
                { key: "all", label: "Все", href: "/wazuh/manage", count: agents.length },
                { key: "offline", label: "Не на связи", href: "/wazuh/manage?status=offline", count: offline },
              ]}
            />
            {rows.length === 0 ? (
              <Empty
                title={onlyOffline ? "Все агенты на связи" : "Агентов пока нет"}
                hint={onlyOffline ? "Отключённых и не подключавшихся агентов нет." : canEdit ? "Добавьте первого агента — команда установки ниже." : "Агентов добавляет аналитик или администратор."}
              />
            ) : (
              <div className="c-well overflow-x-auto p-2">
                <Table>
                  <TableHeader>
                    <TableRow className="border-border/60">
                      <TableHead className="c-label">Агент</TableHead>
                      <TableHead className="c-label">Статус</TableHead>
                      <TableHead className="c-label">Связь</TableHead>
                      <TableHead className="c-label">Версия</TableHead>
                      <TableHead className="c-label">Группы</TableHead>
                      {canEdit && <TableHead className="c-label text-right">Действия</TableHead>}
                    </TableRow>
                  </TableHeader>
                  <TableBody>
                    {rows.map((a) => {
                      const keepalive = realKeepalive(a.lastKeepAlive);
                      return (
                        <TableRow
                          key={a.id}
                          className={cn("border-border/40", a.status === "disconnected" && "bg-[var(--status-err)]/[0.06] shadow-[inset_2px_0_0_var(--status-err)]")}
                        >
                          <TableCell>
                            <Link href={wazuhAgentHref(a.name)} className="text-sm hover:underline" title={`Алерты агента ${a.name}`}>{a.name}</Link>
                            <div className="font-mono text-xs text-muted-foreground">
                              {[a.id, a.ip].filter(Boolean).join(" · ")}
                              {a.os?.name ? <span className="font-sans"> · {a.os.name}</span> : null}
                            </div>
                          </TableCell>
                          <TableCell><AgentStatusBadge status={a.status} /></TableCell>
                          <TableCell className="text-xs">
                            {keepalive ? <Ago ts={keepalive} now={now} staleAfterMs={KEEPALIVE_STALE_MS} /> : <span className="text-muted-foreground">—</span>}
                          </TableCell>
                          <TableCell className="font-mono text-xs">{a.version ?? "—"}</TableCell>
                          <TableCell>
                            <div className="flex flex-wrap items-center gap-1">
                              {(a.group ?? []).map((g) => (
                                <Badge key={g} variant="outline" className="gap-1 border-border font-mono text-muted-foreground">
                                  {g}
                                  {canEdit && a.id !== "000" && (
                                    <ConfirmActionForm
                                      action={agentGroupAction}
                                      title={`Убрать ${a.name} из группы ${g}?`}
                                      description="Настройки группы перестанут применяться к агенту."
                                      confirmLabel="Убрать"
                                      successText={`${a.name} убран из группы ${g}`}
                                      className="inline-flex"
                                    >
                                      <input type="hidden" name="agent_id" value={a.id} />
                                      <input type="hidden" name="group_id" value={g} />
                                      <input type="hidden" name="op" value="remove" />
                                      <button
                                        type="submit"
                                        title={`Убрать ${a.name} из группы ${g}`}
                                        className="-mr-1 inline-flex size-5 cursor-pointer items-center justify-center rounded-sm hover:bg-[var(--status-err)]/15 hover:text-[var(--status-err)]"
                                      >
                                        <X className="size-3" strokeWidth={2} aria-hidden />
                                        <span className="sr-only">Убрать из группы {g}</span>
                                      </button>
                                    </ConfirmActionForm>
                                  )}
                                </Badge>
                              ))}
                            </div>
                          </TableCell>
                          {canEdit && (
                            <TableCell>
                              <div className="flex items-center justify-end gap-1">
                                {a.id !== "000" && (
                                  <AgentGroupAdd agentId={a.id} groups={groupNames.filter((g) => !(a.group ?? []).includes(g))} />
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
                                    <Button type="submit" variant="ghost" size="icon" title={`Перезапустить агента ${a.name}`}>
                                      <RotateCw strokeWidth={1.5} />
                                      <span className="sr-only">Перезапустить агента</span>
                                    </Button>
                                  </ConfirmActionForm>
                                )}
                              </div>
                            </TableCell>
                          )}
                        </TableRow>
                      );
                    })}
                  </TableBody>
                </Table>
              </div>
            )}
            {!canEdit && (
              <p className="mt-3 text-[13px] text-muted-foreground">
                Перезапуск агентов и группы — роль аналитика; перезапуск менеджера, правила и настройки групп — администратор.
              </p>
            )}
          </Panel>

          {canEdit && (
            <details id="add-agent" open={wizardOpen || agents.length === 0 || undefined} className="win group scroll-mt-6">
              <summary className="flex cursor-pointer items-center gap-2 px-5 py-4 text-sm text-foreground hover:text-[var(--ring)]">
                <span aria-hidden className="inline-block text-muted-foreground transition-transform group-open:rotate-90">›</span>
                Добавить агента
                <span className="text-[13px] text-muted-foreground">— команда установки для нового хоста</span>
              </summary>
              <div className="border-t border-border px-5 py-4">
                <AgentWizard version={manager?.version ?? ""} managerHost={managerHost} groups={groupNames} passwordRequired={process.env.WAZUH_REGISTRATION_PASSWORD_SET === "1"} />
              </div>
            </details>
          )}
        </>
      )}
    </>
  );
}
