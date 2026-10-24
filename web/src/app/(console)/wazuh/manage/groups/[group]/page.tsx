import Link from "next/link";
import { notFound } from "next/navigation";
import { ArrowLeft } from "lucide-react";
import { Led, Panel } from "@/components/console/panel";
import { GroupConfEditor } from "@/components/console/manage-forms";
import { Button } from "@/components/ui/button";
import { getGroupConf, groupAgents, WazuhApiError, type WzAgent } from "@/lib/wazuh-api";
import { requirePageSession } from "@/lib/auth";
import { GROUP_NAME_RE } from "@/lib/shared/wazuh-names";

export const dynamic = "force-dynamic";
export const metadata = { title: "Группа агентов" };

const DEFAULT_CONF = `<agent_config>
  <!-- Конфигурация группы; разъедется на агентов при следующем keepalive -->
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
  let offline: string | null = null;
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
    console.error("manage/groups/[group]:", err instanceof Error ? err.message : err);
    offline = "Wazuh API недоступен — подробности в логе консоли";
  }

  return (
    <>
      <div className="flex flex-wrap items-center justify-between gap-4">
        <h1 className="text-3xl tracking-tight">
          Группа <span className="font-mono">{name}</span>
        </h1>
        <Button asChild variant="ghost" size="sm">
          <Link href="/wazuh/manage/groups">
            <ArrowLeft strokeWidth={1.5} />
            Ко всем группам
          </Link>
        </Button>
      </div>

      {offline ? (
        <Panel label="Wazuh manager API · недоступен">
          <p className="text-sm text-destructive">{offline}</p>
        </Panel>
      ) : (
        <div className="grid gap-6 lg:grid-cols-[1fr_1.4fr]">
          <Panel label={`Агенты в группе · ${agents.length} шт.`}>
            {agents.length === 0 ? (
              <p className="text-sm text-muted-foreground">
                Пусто — добавьте агентов на странице «Управление»
              </p>
            ) : (
              <ul className="space-y-2">
                {agents.map((a) => (
                  <li
                    key={a.id}
                    className="flex items-center gap-3 border border-border bg-[var(--surface-deep)] px-3 py-2"
                  >
                    <Led
                      color={a.status === "active" ? "var(--status-ok)" : "var(--status-err)"}
                    />
                    <span className="font-mono text-xs text-muted-foreground">{a.id}</span>
                    <span className="text-sm">{a.name}</span>
                    <span className="ml-auto font-mono text-xs text-muted-foreground">
                      {a.version ?? ""}
                    </span>
                  </li>
                ))}
              </ul>
            )}
          </Panel>

          <Panel label="agent.conf · централизованная конфигурация группы" meta={isAdmin ? "Ctrl+S — сохранить" : "только чтение"}>
            <GroupConfEditor group={name} initialXml={conf} readOnly={!isAdmin} />
          </Panel>
        </div>
      )}
    </>
  );
}
