import type { Metadata } from "next";
import { CheckCircle2, CircleHelp, XCircle } from "lucide-react";
import { Empty, Led, PageHeader, Panel, StatTile } from "@/components/console/panel";
import { Pager } from "@/components/console/pager";
import { StorageUnavailable } from "@/components/console/storage-error";
import {
  Table,
  TableBody,
  TableCell,
  TableHead,
  TableHeader,
  TableRow,
} from "@/components/ui/table";
import { safeQuery } from "@/lib/clickhouse";
import { latestVerdicts, latestVerdictsSummary, type VerdictStatus } from "@/lib/queries";
import { clampPage } from "@/lib/shared/limits";
import { COMPLIANCE_LABELS } from "@/lib/shared/labels";
import { fmtNum, formatAgo, formatTs } from "@/lib/shared/time";
import { requirePageSession } from "@/lib/auth";

export const dynamic = "force-dynamic";
export const metadata: Metadata = { title: "Политики" };

/** Три состояния вердикта — три цвета и три подписи: «нет данных» не выглядит ни нарушением, ни соответствием. */
const STATUS_VIEW: Record<VerdictStatus, { color: string; icon: typeof CheckCircle2 }> = {
  pass: { color: "text-[var(--status-ok)]", icon: CheckCircle2 },
  fail: { color: "text-[var(--status-err)]", icon: XCircle },
  unknown: { color: "text-[var(--status-warn)]", icon: CircleHelp },
};

function StatusCell({ status }: { status: VerdictStatus }) {
  const v = STATUS_VIEW[status];
  const Icon = v.icon;
  return (
    <span className={`flex items-center gap-2 font-mono text-xs ${v.color}`}>
      <Icon strokeWidth={2} className="h-4 w-4" aria-hidden /> {COMPLIANCE_LABELS[status]}
    </span>
  );
}

export default async function PoliciesPage({ searchParams }: PageProps<"/wazuh/policies">) {
  await requirePageSession();
  const page = clampPage((await searchParams).page);
  const r = await safeQuery(() => Promise.all([latestVerdicts(page), latestVerdictsSummary()]));
  const now = new Date();

  if (!r.ok) {
    return (
      <>
        <PageHeader title="Политики" />
        <StorageUnavailable reason={r.error} />
      </>
    );
  }
  const [verdicts, summary] = r.data;
  const known = summary.total - summary.unknown;
  const evaluatedAt = summary.evaluatedAt;
  const compliance = known === 0 ? null : Math.round((100 * (known - summary.failed)) / known);

  return (
    <>
      <PageHeader title="Политики">
        {evaluatedAt && (
          <span className="c-label flex items-center gap-2" title={formatAgo(evaluatedAt, now)}>
            <Led color={summary.failed > 0 ? "var(--status-err)" : summary.unknown > 0 ? "var(--status-warn)" : "var(--status-ok)"} />
            оценка от {formatTs(evaluatedAt)}
          </span>
        )}
      </PageHeader>

      <div className="grid grid-cols-2 gap-6 md:grid-cols-4">
        <StatTile label="Проверок" value={fmtNum(summary.total)} />
        <StatTile
          label="Нарушений"
          value={fmtNum(summary.failed)}
          led={summary.failed > 0 ? "var(--status-err)" : "var(--status-ok)"}
        />
        <StatTile
          label="Неизвестно"
          value={fmtNum(summary.unknown)}
          led={summary.unknown > 0 ? "var(--status-warn)" : "var(--status-ok)"}
          hint="проверка не выполнена: SCA или API Wazuh недоступны — причина в колонке «Нарушения»"
        />
        <StatTile
          label="Соответствие"
          value={compliance === null ? "—" : fmtNum(compliance)}
          unit={compliance === null ? undefined : "%"}
          hint="доля соблюдённых среди выполненных проверок; «неизвестно» не учитывается"
        />
      </div>

      <Panel label="Вердикты Policy-as-Code (OPA/Rego) · последний раунд policyd" meta={summary.unknown > 0 ? `${fmtNum(summary.unknown)} без данных` : undefined}>
        {summary.total === 0 ? (
          <Empty>Вердиктов пока нет — policyd ещё не дотянулся до Wazuh API или не завершил первый раунд.</Empty>
        ) : (
          <div className="c-well overflow-x-auto p-2">
            <Table>
              <TableHeader>
                <TableRow className="border-border/60">
                  <TableHead className="c-label">Статус</TableHead>
                  <TableHead className="c-label">Объект</TableHead>
                  <TableHead className="c-label">Политика</TableHead>
                  <TableHead className="c-label">Нарушения / причина</TableHead>
                </TableRow>
              </TableHeader>
              <TableBody>
                {verdicts.map((v) => (
                  <TableRow key={`${v.policy}|${v.entity_type}|${v.entity_id}`} className="border-border/40">
                    <TableCell><StatusCell status={v.status} /></TableCell>
                    <TableCell className="whitespace-normal">
                      <span className="font-mono text-xs text-muted-foreground">
                        [{v.entity_type}]
                      </span>{" "}
                      {v.entity_name}
                    </TableCell>
                    <TableCell className="font-mono text-xs">{v.policy}</TableCell>
                    <TableCell className={`max-w-lg whitespace-normal text-sm ${v.status === "unknown" ? "text-muted-foreground" : ""}`}>
                      {v.violations.length > 0 ? v.violations.join("; ") : "—"}
                    </TableCell>
                  </TableRow>
                ))}
              </TableBody>
            </Table>
          </div>
        )}
        <Pager page={page} pages={Math.max(1, Math.ceil(summary.total / 1000))} total={summary.total} pageSize={1000} href={(p) => `/policies?page=${p}`} />
      </Panel>
    </>
  );
}
