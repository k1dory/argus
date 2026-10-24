import type { Metadata } from "next";
import { Copyable } from "@/components/console/copyable";
import { searchHref } from "@/lib/shared/search-href";
import { Empty, PageHeader, Panel } from "@/components/console/panel";
import { RangePicker } from "@/components/console/range-picker";
import { StorageUnavailable } from "@/components/console/storage-error";
import {
  Table,
  TableBody,
  TableCell,
  TableHead,
  TableHeader,
  TableRow,
} from "@/components/ui/table";
import { parseRange, safeQuery } from "@/lib/clickhouse";
import { agentsSummary } from "@/lib/queries";
import { fmtNum, formatAgo, formatTs } from "@/lib/shared/time";
import { requirePageSession } from "@/lib/auth";

export const dynamic = "force-dynamic";
export const metadata: Metadata = { title: "Агенты Wazuh" };

export default async function AgentsPage({ searchParams }: PageProps<"/wazuh/agents">) {
  await requirePageSession();
  const range = parseRange((await searchParams).range as string | undefined);
  const r = await safeQuery(() => agentsSummary(range));
  const now = new Date();

  return (
    <>
      <PageHeader title="Агенты Wazuh">
        <RangePicker value={range} />
      </PageHeader>

      {!r.ok ? (
        <StorageUnavailable reason={r.error} />
      ) : (
        <Panel label={`Активность агентов · ${fmtNum(r.data.length)} шт.`} meta="по алертам менеджера; регистрация и группы — в разделе «Управление Wazuh»">
          {r.data.length === 0 ? (
            <Empty>Нет алертов за период — агенты либо молчат, либо не подключены к менеджеру.</Empty>
          ) : (
            <div className="c-well overflow-x-auto p-2">
              <Table>
                <TableHeader>
                  <TableRow className="border-border/60">
                    <TableHead className="c-label">Агент</TableHead>
                    <TableHead className="c-label text-right">Алертов</TableHead>
                    <TableHead className="c-label text-right">Критичных</TableHead>
                    <TableHead className="c-label text-right">Правил</TableHead>
                    <TableHead className="c-label">Последний алерт (UTC)</TableHead>
                  </TableRow>
                </TableHeader>
                <TableBody>
                  {r.data.map((a) => (
                    <TableRow key={a.agent_name} className="border-border/40">
                      <TableCell className="font-medium"><Copyable value={a.agent_name} href={searchHref.agent(a.agent_name)} label="Агент" /></TableCell>
                      <TableCell className="text-right font-mono">{fmtNum(a.alerts)}</TableCell>
                      <TableCell className="text-right font-mono">
                        {a.critical > 0 ? (
                          <span className="font-medium text-[var(--status-err)]">{fmtNum(a.critical)}</span>
                        ) : (
                          "0"
                        )}
                      </TableCell>
                      <TableCell className="text-right font-mono">{fmtNum(a.rules)}</TableCell>
                      <TableCell className="font-mono text-xs" title={formatAgo(a.last_alert, now)}>{formatTs(a.last_alert)}</TableCell>
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
