import type { Metadata } from "next";
import { Copyable } from "@/components/console/copyable";
import { Empty, PageHeader, Panel, StatTile } from "@/components/console/panel";
import { StorageUnavailable } from "@/components/console/storage-error";
import {
  Table,
  TableBody,
  TableCell,
  TableHead,
  TableHeader,
  TableRow,
} from "@/components/ui/table";
import { Badge } from "@/components/ui/badge";
import { cn } from "@/lib/utils";
import { TONE_CLASS, VULN_TONE, toneFor } from "@/components/console/tone";
import { safeQuery } from "@/lib/clickhouse";
import { vulnList, VULN_LIMIT } from "@/lib/queries";
import { vulnSeverityLabel, vulnStatusLabel } from "@/lib/shared/labels";
import { fmtNum, formatTs } from "@/lib/shared/time";
import { requirePageSession } from "@/lib/auth";

export const dynamic = "force-dynamic";
export const metadata: Metadata = { title: "Уязвимости" };

function VulnSeverityBadge({ severity }: { severity: string }) {
  return <Badge variant="outline" className={cn("font-mono", TONE_CLASS[toneFor(VULN_TONE, severity)])}>{vulnSeverityLabel(severity)}</Badge>;
}

export default async function VulnerabilitiesPage() {
  await requirePageSession();
  const r = await safeQuery(() => vulnList());

  return (
    <>
      <PageHeader title="Уязвимости">
        <span className="c-label">vulnerability-detector · окно 30 дней</span>
      </PageHeader>
      {!r.ok ? <StorageUnavailable reason={r.error} /> : <VulnBody vulns={r.data} />}
    </>
  );
}

function VulnBody({ vulns }: { vulns: Awaited<ReturnType<typeof vulnList>> }) {
  const active = vulns.filter((v) => v.status !== "Solved");
  const bySev = (sev: string) => active.filter((v) => v.severity === sev).length;
  return (
    <>
      <div className="grid grid-cols-2 gap-6 md:grid-cols-4">
        <StatTile
          label="Активных CVE"
          value={fmtNum(active.length)}
          led={active.length > 0 ? "var(--status-warn)" : "var(--status-ok)"}
        />
        <StatTile
          label="Критических"
          value={fmtNum(bySev("Critical"))}
          led={bySev("Critical") > 0 ? "var(--status-err)" : "var(--status-ok)"}
        />
        <StatTile label="Высоких" value={fmtNum(bySev("High"))} />
        <StatTile label="Устранено" value={fmtNum(vulns.length - active.length)} />
      </div>

      <Panel label={`CVE по агентам и пакетам · ${fmtNum(vulns.length)} записей`} meta={`не больше ${fmtNum(VULN_LIMIT)}`}>
        {vulns.length === 0 ? (
          <Empty>
            Алертов vulnerability-detector за 30 дней нет — включите модуль в ossec.conf
            менеджера или подождите первого скана.
          </Empty>
        ) : (
          <div className="c-well overflow-x-auto p-2">
            <Table>
              <TableHeader>
                <TableRow className="border-border/60">
                  <TableHead className="c-label">CVE</TableHead>
                  <TableHead className="c-label">Серьёзность</TableHead>
                  <TableHead className="c-label text-right">CVSS</TableHead>
                  <TableHead className="c-label">Пакет</TableHead>
                  <TableHead className="c-label">Агент</TableHead>
                  <TableHead className="c-label">Статус</TableHead>
                  <TableHead className="c-label">Обнаружено (UTC)</TableHead>
                </TableRow>
              </TableHeader>
              <TableBody>
                {vulns.map((v) => (
                  <TableRow key={`${v.cve}|${v.pkg}|${v.agent_name}`} className="border-border/40">
                    <TableCell className="font-mono text-xs">
                      <span className="flex items-center gap-2">
                        <a
                          href={`https://nvd.nist.gov/vuln/detail/${encodeURIComponent(v.cve)}`}
                          target="_blank"
                          rel="noreferrer"
                          className="text-[var(--ring)] hover:underline"
                        >
                          {v.cve}
                        </a>
                        <Copyable value={v.cve} label="CVE" className="text-muted-foreground"><span className="sr-only">копировать</span></Copyable>
                      </span>
                    </TableCell>
                    <TableCell>
                      <VulnSeverityBadge severity={v.severity} />
                    </TableCell>
                    <TableCell className="text-right font-mono text-xs">
                      {v.score > 0 ? fmtNum(v.score, 1) : "—"}
                    </TableCell>
                    <TableCell className="font-mono text-xs">
                      {v.pkg}
                      {v.pkg_version && (
                        <span className="text-muted-foreground"> {v.pkg_version}</span>
                      )}
                    </TableCell>
                    <TableCell className="font-mono text-xs">{v.agent_name ? <Copyable value={v.agent_name} href="/wazuh/agents" label="Агент" /> : "—"}</TableCell>
                    <TableCell>
                      <span className={cn("font-mono text-xs", v.status === "Solved" ? "text-[var(--status-ok)]" : "text-[var(--status-warn)]")}>
                        {vulnStatusLabel(v.status || "Active")}
                      </span>
                    </TableCell>
                    <TableCell className="font-mono text-xs whitespace-nowrap">
                      {formatTs(v.last_seen)}
                    </TableCell>
                  </TableRow>
                ))}
              </TableBody>
            </Table>
          </div>
        )}
      </Panel>
    </>
  );
}
