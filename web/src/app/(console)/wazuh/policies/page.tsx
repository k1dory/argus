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
import { latestVerdicts, latestVerdictsSummary, POLICY_PAGE_SIZE, type VerdictStatus } from "@/lib/queries";
import { policiesPageHref } from "../_shared/links";
import { clampPage } from "@/lib/shared/limits";
import { COMPLIANCE_LABELS } from "@/lib/shared/labels";
import { fmtNum, formatAgo, formatTs } from "@/lib/shared/time";
import { Badge } from "@/components/ui/badge";
import { TONE_CLASS } from "@/components/console/tone";
import { requirePageSession } from "@/lib/auth";

export const dynamic = "force-dynamic";
export const metadata: Metadata = { title: "Политики" };

/** Три состояния вердикта — три цвета и три подписи: «нет данных» не выглядит ни нарушением, ни соответствием. */
const STATUS_VIEW: Record<VerdictStatus, { color: string; icon: typeof CheckCircle2 }> = {
  pass: { color: "text-[var(--status-ok)]", icon: CheckCircle2 },
  fail: { color: "text-[var(--status-err)]", icon: XCircle },
  unknown: { color: "text-[var(--status-warn)]", icon: CircleHelp },
};

/** Тип объекта проверки — по-человечески; неизвестный тип показывается как есть. */
const ENTITY_TYPE_LABELS: Record<string, string> = { agent: "агент", group: "группа", user: "пользователь", sca: "проверка SCA", manager: "менеджер" };

/** Сколько нарушений показывать сразу; остальные — под «ещё N». */
const VIOLATIONS_SHOWN = 3;

function Violations({ items }: { items: string[] }) {
  if (items.length === 0) return <>—</>;
  const head = items.slice(0, VIOLATIONS_SHOWN);
  const rest = items.slice(VIOLATIONS_SHOWN);
  return (
    <ul className="space-y-1">
      {head.map((v, i) => <li key={i}>{v}</li>)}
      {rest.length > 0 && (
        <li>
          <details>
            <summary className="cursor-pointer text-muted-foreground hover:text-foreground">ещё {fmtNum(rest.length)}</summary>
            <ul className="mt-1 space-y-1">{rest.map((v, i) => <li key={i}>{v}</li>)}</ul>
          </details>
        </li>
      )}
    </ul>
  );
}

function StatusCell({ status }: { status: VerdictStatus }) {
  const v = STATUS_VIEW[status];
  const Icon = v.icon;
  return (
    <span className={`flex items-center gap-2 text-xs whitespace-nowrap ${v.color}`}>
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
      <PageHeader title="Политики" subtitle="Автоматические проверки агентов и групп Wazuh на соответствие правилам безопасности.">
        {evaluatedAt && (
          <span className="flex items-center gap-2 text-[13px] text-muted-foreground" title={formatAgo(evaluatedAt, now)}>
            <Led color={summary.failed > 0 ? "var(--status-err)" : summary.unknown > 0 ? "var(--status-warn)" : "var(--status-ok)"} />
            {summary.failed > 0 ? "есть нарушения" : summary.unknown > 0 ? "часть не проверена" : "всё соблюдено"} · оценка от <span className="font-mono">{formatTs(evaluatedAt)}</span>
          </span>
        )}
      </PageHeader>

      <div className="grid grid-cols-2 gap-6 md:grid-cols-4">
        <StatTile label="Проверок" value={fmtNum(summary.total)} />
        <StatTile
          label="Нарушений"
          value={fmtNum(summary.failed)}
          led={summary.total === 0 ? undefined : summary.failed > 0 ? "var(--status-err)" : "var(--status-ok)"}
        />
        <StatTile
          label="Неизвестно"
          value={fmtNum(summary.unknown)}
          led={summary.total === 0 ? undefined : summary.unknown > 0 ? "var(--status-warn)" : "var(--status-ok)"}
          note={summary.unknown > 0 ? "проверка не выполнена — причина в таблице" : undefined}
        />
        <StatTile
          label="Соответствие"
          value={compliance === null ? "—" : fmtNum(compliance)}
          unit={compliance === null ? undefined : "%"}
          sub="среди выполненных проверок"
        />
      </div>

      <Panel label="Результаты проверок" meta={summary.total > 0 ? `${fmtNum(summary.total)} · нарушения сверху` : undefined}>
        {summary.total === 0 ? (
          <Empty title="Результатов проверок пока нет" hint="Они появятся после первой оценки — обычно через несколько минут после подключения менеджера Wazuh." />
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
                  <TableRow
                    key={`${v.policy}|${v.entity_type}|${v.entity_id}`}
                    className={v.status === "fail" ? "border-border/40 bg-[var(--status-err)]/[0.06] shadow-[inset_2px_0_0_var(--status-err)]" : "border-border/40"}
                  >
                    <TableCell><StatusCell status={v.status} /></TableCell>
                    <TableCell className="whitespace-normal">
                      <Badge variant="outline" className={`mr-2 align-middle ${TONE_CLASS.muted}`}>
                        {ENTITY_TYPE_LABELS[v.entity_type] ?? v.entity_type}
                      </Badge>
                      {v.entity_name}
                    </TableCell>
                    <TableCell className="font-mono text-xs">{v.policy}</TableCell>
                    <TableCell className={`max-w-lg whitespace-normal text-sm ${v.status === "unknown" ? "text-muted-foreground" : ""}`}>
                      <Violations items={v.violations} />
                    </TableCell>
                  </TableRow>
                ))}
              </TableBody>
            </Table>
          </div>
        )}
        {summary.total > POLICY_PAGE_SIZE && (
          <Pager page={page} pages={Math.ceil(summary.total / POLICY_PAGE_SIZE)} total={summary.total} pageSize={POLICY_PAGE_SIZE} href={policiesPageHref} />
        )}
      </Panel>
    </>
  );
}
