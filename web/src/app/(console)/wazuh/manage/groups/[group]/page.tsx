import Link from "next/link";
import { notFound } from "next/navigation";
import { Empty, PageHeader, Panel } from "@/components/console/panel";
import { GroupConfEditor } from "@/components/console/manage-forms";
import { ServiceUnavailable } from "@/components/console/service-unavailable";
import { fmtNum } from "@/lib/shared/time";
import { AgentStatusBadge } from "../../../_shared/status-badge";
import { wazuhAgentHref } from "../../../_shared/links";
import { getGroupConf, groupAgents, WazuhApiError, type WzAgent } from "@/lib/wazuh-api";
import { requirePageSession } from "@/lib/auth";
import { GROUP_NAME_RE } from "@/lib/shared/wazuh-names";

export const dynamic = "force-dynamic";
export const metadata = { title: "Группа агентов" };

const DEFAULT_CONF = `<agent_config>
  <!-- Настройки группы: применятся к её агентам при следующем подключении -->
</agent_config>
`;

export default async function GroupDetailPage({
  params,
}: PageProps<"/wazuh/manage/groups/[group]">) {
  const session = await requirePageSession();
  const isAdmin = session.role === "admin";
  const { group } = await params;
  const name = decodeURIComponent(group);
  // Та же регулярка, что при сохранении: чужое имя в путь API не попадает.
  if (!GROUP_NAME_RE.test(name)) notFound();

  let agents: WzAgent[] = [];
  let conf = DEFAULT_CONF;
  let error: string | null = null;
  try {
    // Шаблон подставляем ТОЛЬКО на 404 (файла ещё нет). Любая другая ошибка
    // (таймаут, 500) должна остановить рендер редактора — иначе «Сохранить»
    // перезапишет живой agent.conf пустой заготовкой.
    [agents, conf] = await Promise.all([
      groupAgents(name),
      getGroupConf(name).catch((err) => {
        if (err instanceof WazuhApiError && err.status === 404) return DEFAULT_CONF;
        throw err;
      }),
    ]);
  } catch (err) {
    if (err instanceof WazuhApiError && err.status === 404) notFound();
    error = err instanceof Error ? err.message : String(err);
    console.error("manage/groups/[group]:", error);
  }

  return (
    <>
      <PageHeader
        title={<>Группа <span className="font-mono">{name}</span></>}
        back={{ href: "/wazuh/manage/groups", label: "Группы агентов" }}
        subtitle="Настройки группы применяются ко всем её агентам при следующем подключении."
      />

      {error ? (
        <ServiceUnavailable service="wazuh" what="агентов и настройки группы" reason={error} />
      ) : (
        <div className="grid gap-6 lg:grid-cols-[1fr_1.4fr]">
          <Panel label={`Агенты в группе · ${fmtNum(agents.length)}`}>
            {agents.length === 0 ? (
              <Empty
                title="В группе нет агентов"
                hint={<>Добавить агента в группу можно на странице <Link href="/wazuh/manage" className="text-[var(--ring)] hover:underline">«Управление Wazuh»</Link>.</>}
              />
            ) : (
              <ul className="space-y-2">
                {agents.map((a) => (
                  <li
                    key={a.id}
                    className="flex items-center gap-3 rounded-md border border-border bg-[var(--surface-deep)] px-3 py-2"
                  >
                    <span className="font-mono text-xs text-muted-foreground">{a.id}</span>
                    <Link href={wazuhAgentHref(a.name)} className="text-sm hover:underline">{a.name}</Link>
                    <AgentStatusBadge status={a.status} />
                    <span className="ml-auto font-mono text-xs text-muted-foreground">
                      {a.version ?? ""}
                    </span>
                  </li>
                ))}
              </ul>
            )}
          </Panel>

          <Panel label="Настройки группы (agent.conf)" meta={isAdmin ? "Ctrl+S — сохранить" : "только чтение — редактирует администратор"}>
            <GroupConfEditor group={name} initialXml={conf} readOnly={!isAdmin} />
          </Panel>
        </div>
      )}
    </>
  );
}
