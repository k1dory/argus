import type { Metadata } from "next";
import { ShieldCheck } from "lucide-react";
import { Copyable } from "@/components/console/copyable";
import { Empty, PageHeader, Panel, StatTile } from "@/components/console/panel";
import { FilterTabs } from "@/components/console/filter-tabs";
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
import { TONE_CLASS, TONE_COLOR, VULN_TONE, toneFor, type Tone } from "@/components/console/tone";
import { safeQuery } from "@/lib/clickhouse";
import { parseVulnStatus, vulnList, vulnSummary, VULN_LIMIT, type VulnStatusFilter, type VulnSummary } from "@/lib/queries";
import { vulnSeverityLabel, vulnStatusLabel } from "@/lib/shared/labels";
import { fmtNum, formatTs } from "@/lib/shared/time";
import { requirePageSession } from "@/lib/auth";
import { RangeFilters } from "@/components/console/range-filters";
import { RangePicker } from "@/components/console/range-picker";
import { describeChips, timeLabel, type TimeFilter } from "@/lib/shared/filters";
import { parseVulnRanges, VULN_MAX_DAYS, VULN_RANGE_FIELDS, vulnRangeChips } from "@/lib/shared/page-filters";
import { wazuhAgentHref } from "../_shared/links";

export const dynamic = "force-dynamic";
export const metadata: Metadata = { title: "Уязвимости" };

/** Статус CVE: «ожидает» — не активная угроза, а приглушённое состояние. */
const VULN_STATUS_TONE: Record<string, Tone> = { active: "warn", solved: "ok", pending: "muted" };

function VulnSeverityBadge({ severity }: { severity: string }) {
  return <Badge variant="outline" className={cn("font-mono", TONE_CLASS[toneFor(VULN_TONE, severity)])}>{vulnSeverityLabel(severity)}</Badge>;
}

/** «за 30 дней» / «за интервал 2026-10-01 00:00 — сейчас UTC». */
function periodText(t: TimeFilter): string {
  const v = timeLabel(t);
  if (!v) return `за ${VULN_MAX_DAYS} дней`;
  return t.from ? `за интервал ${v}` : `за ${v}`;
}

export default async function VulnerabilitiesPage({ searchParams }: PageProps<"/wazuh/vulnerabilities">) {
  const session = await requirePageSession();
  const sp = await searchParams;
  // Окно обнаружения (по умолчанию 30 дней, не шире 30), серьёзность не ниже/не выше, CVSS от–до.
  const ranges = parseVulnRanges(sp);
  const status = parseVulnStatus(sp.status);
  // Период уже назван в пустом состоянии («за 7 дней»), поэтому «по фильтрам» — только пороги.
  const filtersText = describeChips(vulnRangeChips(ranges).filter((c) => c.key !== "time"));
  const f = { time: ranges.time, severity: ranges.severity, cvss: ranges.cvss };
  const r = await safeQuery(() => Promise.all([vulnList({ ...f, status }), vulnSummary(f)]));
  const isAdmin = session.role === "admin";

  const qs = new URLSearchParams();
  for (const [k, v] of Object.entries(sp)) if (typeof v === "string" && v) qs.set(k, v);
  const statusHref = (s: VulnStatusFilter) => {
    const next = new URLSearchParams(qs);
    if (s === "active") next.delete("status");
    else next.set("status", s);
    const q = next.toString();
    return q ? `/wazuh/vulnerabilities?${q}` : "/wazuh/vulnerabilities";
  };

  return (
    <>
      <PageHeader title="Уязвимости">
        <RangePicker value={ranges.time.range} />
      </PageHeader>
      <Panel label="Фильтры" meta={`период — не больше ${VULN_MAX_DAYS} дней`}>
        <RangeFilters time timeLabel="Обнаружено, точный интервал UTC" fields={VULN_RANGE_FIELDS} idPrefix="vuln" />
      </Panel>
      {!r.ok ? (
        <StorageUnavailable reason={r.error} />
      ) : (
        <VulnBody
          vulns={r.data[0]}
          summary={r.data[1]}
          status={status}
          statusHref={statusHref}
          filtersText={filtersText}
          period={periodText(ranges.time)}
          isAdmin={isAdmin}
        />
      )}
    </>
  );
}

function VulnBody({
  vulns,
  summary,
  status,
  statusHref,
  filtersText,
  period,
  isAdmin,
}: {
  vulns: Awaited<ReturnType<typeof vulnList>>;
  summary: VulnSummary;
  status: VulnStatusFilter;
  statusHref: (s: VulnStatusFilter) => string;
  filtersText: string;
  period: string;
  isAdmin: boolean;
}) {
  // Итоги — отдельный агрегат без LIMIT; таблица — первые VULN_LIMIT строк выбранной вкладки.
  const truncated = vulns.length >= VULN_LIMIT;
  const shown = status === "active" ? summary.active : status === "solved" ? summary.solved : summary.total;
  const activeTone: Tone = summary.critical > 0 ? "err" : summary.high > 0 ? "warn" : summary.active > 0 ? "neutral" : "ok";
  return (
    <>
      <div className="grid grid-cols-2 gap-6 md:grid-cols-4">
        <StatTile label="Активных CVE" value={fmtNum(summary.active)} led={TONE_COLOR[activeTone]} />
        <StatTile label="Критических" value={fmtNum(summary.critical)} tone={summary.critical > 0 ? "err" : "ok"} sub="среди активных" />
        <StatTile label="Высоких" value={fmtNum(summary.high)} tone={summary.high > 0 ? "warn" : undefined} sub="среди активных" />
        <StatTile label="Устранено" value={fmtNum(summary.solved)} />
      </div>

      <Panel
        label={`CVE по агентам и пакетам · ${fmtNum(shown)}`}
        meta={truncated ? `показаны первые ${fmtNum(VULN_LIMIT)} из ${fmtNum(shown)}` : "по убыванию CVSS"}
      >
        <FilterTabs
          label="Статус уязвимостей"
          className="mb-4"
          current={status}
          items={[
            { key: "active", label: "Активные", href: statusHref("active"), count: summary.active },
            { key: "solved", label: "Устранённые", href: statusHref("solved"), count: summary.solved },
            { key: "all", label: "Все", href: statusHref("all"), count: summary.total },
          ]}
        />
        {truncated && (
          <p role="status" className="mb-3 text-[13px] text-[var(--status-warn)]">
            В таблице первые {fmtNum(VULN_LIMIT)} записей из {fmtNum(shown)} — самые опасные по CVSS. Итоги в плитках посчитаны по всем. Сузьте фильтры, чтобы увидеть остальные.
          </p>
        )}
        {vulns.length === 0 && filtersText ? (
          <Empty title="Нет CVE по фильтрам" hint={`${filtersText}, ${period}. Ослабьте пороги или расширьте период.`} />
        ) : vulns.length === 0 && status !== "active" && summary.total > 0 ? (
          <Empty title={`Устранённых уязвимостей ${period} нет`} hint="Активные — на вкладке «Активные»." />
        ) : vulns.length === 0 ? (
          <Empty
            icon={ShieldCheck}
            title={summary.total > 0 ? `Активных уязвимостей ${period} нет` : `Уязвимостей ${period} не найдено`}
            hint={
              summary.total > 0
                ? `Все найденные CVE устранены — они на вкладке «Устранённые».`
                : isAdmin
                  ? "Если сканер уязвимостей не включён, включите модуль vulnerability-detector в ossec.conf менеджера Wazuh; результаты появятся после первого скана."
                  : "Если сканер уязвимостей не включён, попросите администратора включить его — результаты появятся после первого скана."
            }
          />
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
                  <TableHead className="c-label">Последнее обнаружение (UTC)</TableHead>
                </TableRow>
              </TableHeader>
              <TableBody>
                {vulns.map((v) => {
                  const st = v.status || "Active";
                  const critical = v.severity === "Critical" && st !== "Solved";
                  return (
                    <TableRow
                      key={`${v.cve}|${v.pkg}|${v.agent_name}`}
                      data-critical={critical || undefined}
                      className={cn("border-border/40", critical && "bg-[var(--status-err)]/[0.06] shadow-[inset_2px_0_0_var(--status-err)]")}
                    >
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
                      <TableCell className="font-mono text-xs">{v.agent_name ? <Copyable value={v.agent_name} href={wazuhAgentHref(v.agent_name)} label="Агент" /> : "—"}</TableCell>
                      <TableCell>
                        <span className="text-xs" style={{ color: TONE_COLOR[toneFor(VULN_STATUS_TONE, st)] }}>
                          {vulnStatusLabel(st)}
                        </span>
                      </TableCell>
                      <TableCell className="font-mono text-xs whitespace-nowrap">
                        {formatTs(v.last_seen)}
                      </TableCell>
                    </TableRow>
                  );
                })}
              </TableBody>
            </Table>
          </div>
        )}
      </Panel>
    </>
  );
}
