// Сканы снаружи — одной строкой-сводкой над очередью; подробности (первые
// группы по уровню и числу адресов, раскрытая подсеть, групповые действия) —
// в раскрывающемся блоке. Серверный компонент; раскрыт сам, если в адресе
// выбрана подсеть или страница групп.
import Link from "next/link";
import { ChevronRight } from "lucide-react";
import { Ago } from "@/components/console/ago";
import { LevelBadge, StatusBadge } from "@/components/console/incident-badges";
import { Led } from "@/components/console/panel";
import { LEVEL_TONE, TONE_COLOR, toneFor } from "@/components/console/tone";
import type { ScanGroup, ScanSummary } from "@/lib/argus-queries";
import { BLOCK_LABEL, type BlockState } from "@/lib/shared/scan-groups";
import { incidentLevelLabel } from "@/lib/shared/labels";
import { plural } from "@/lib/shared/incident-view";
import { fmtNum } from "@/lib/shared/time";
import { cn } from "@/lib/utils";

const linkCls = "text-[var(--ring)] hover:underline";
const th = "c-label px-2 py-1.5 text-left font-normal";
const td = "px-2 py-1.5 align-top";

export type ScanSubnetRow = { incident_id: string; actor_name: string; rule_id: string; rule_title: string; last_ts: string; level: string; status: string; owner: string };

/** Подпись группы: один адрес — сам адрес, иначе подсеть. */
export const groupLabel = (g: ScanGroup): string => (g.addresses === 1 && g.sample ? g.sample : g.subnet);

export function ScanSummaryBlock({
  summary, groups, groupsError, pageSize, gpage, subnet, now, href, children,
}: {
  summary: ScanSummary;
  groups: ScanGroup[];
  groupsError: boolean;
  pageSize: number;
  gpage: number;
  subnet?: string;
  now: Date;
  href: (patch: Record<string, string | undefined>) => string;
  /** Раскрытая подсеть (её инциденты и групповые действия). */
  children?: React.ReactNode;
}) {
  const color = summary.level ? TONE_COLOR[toneFor(LEVEL_TONE, summary.level)] : "var(--text-tertiary)";
  const facts = [
    `${fmtNum(summary.subnets)} ${plural(summary.subnets, ["подсеть", "подсети", "подсетей"])}`,
    `${fmtNum(summary.incidents)} ${plural(summary.incidents, ["инцидент", "инцидента", "инцидентов"])}`,
    summary.level && `макс. уровень ${incidentLevelLabel(summary.level)}`,
    summary.unassigned > 0 && `без ответственного ${fmtNum(summary.unassigned)}`,
  ].filter(Boolean);
  return (
    <details open={Boolean(subnet) || gpage > 1} className="group min-w-0 rounded-[10px] border border-border bg-[var(--surface-deep)]">
      <summary className="flex cursor-pointer list-none flex-wrap items-center gap-x-3 gap-y-1 px-4 py-2.5 text-sm [&::-webkit-details-marker]:hidden">
        <Led color={color} />
        <span className="font-medium text-foreground">Сканы снаружи</span>
        <span className="min-w-0 text-muted-foreground">{facts.join(" · ")}</span>
        <span className="ml-auto inline-flex items-center gap-1 text-[13px] text-[var(--ring)]">
          <span className="group-open:hidden">Показать</span>
          <span className="hidden group-open:inline">Скрыть</span>
          <ChevronRight className="size-3.5 transition-transform group-open:rotate-90" strokeWidth={1.5} aria-hidden />
        </span>
      </summary>
      <div className="border-t border-border px-4 pb-4 pt-3">
        <p className="mb-3 text-[13px] text-muted-foreground">
          Сканирование портов и перебор входа с внешних адресов сгруппированы по подсетям — в очереди их нет.{" "}
          <Link href={href({ scans: "list", subnet: undefined })} className={linkCls}>Показать в очереди по одному</Link>
        </p>
        {groupsError ? <p className="text-[13px] text-destructive">Группы сканов временно недоступны; очередь — без них.</p>
          : groups.length === 0 ? <p className="text-[13px] text-muted-foreground">Открытых сканов по этим условиям нет.</p>
          : (
            <div className="overflow-x-auto">
              <table className="w-full text-[13px]">
                <caption className="sr-only">Сканы снаружи по подсетям</caption>
                <thead>
                  <tr className="border-b border-border/60">
                    <th scope="col" className={th}>Откуда</th>
                    <th scope="col" className={th}>Адресов / инцидентов</th>
                    <th scope="col" className={th}>Что делали</th>
                    <th scope="col" className={th}>Последний</th>
                    <th scope="col" className={th}>Уровень</th>
                    <th scope="col" className={th}>Без ответственного</th>
                    <th scope="col" className={th}><span className="sr-only">Действие</span></th>
                  </tr>
                </thead>
                <tbody>
                  {groups.map((g) => {
                    const open = g.subnet === subnet;
                    return (
                      <tr key={g.subnet} className={cn("border-b border-border/40", open && "bg-[var(--surface-elevated)]")}>
                        <td className={cn(td, "font-mono text-[12px] whitespace-nowrap")} title={g.addresses === 1 ? `подсеть ${g.subnet}` : undefined}>{groupLabel(g)}</td>
                        <td className={cn(td, "font-mono text-[12px] tabular-nums")}>{fmtNum(g.addresses)} / {fmtNum(g.incidents)}</td>
                        <td className={cn(td, "text-[var(--fg-2)]")} title={g.rules.join(", ")}><Titles items={g.titles?.length ? g.titles : g.rules} /></td>
                        <td className={td}><Ago ts={g.last_ts} now={now} className="text-muted-foreground" /></td>
                        <td className={td}><LevelBadge level={g.level} /></td>
                        <td className={cn(td, "font-mono text-[12px] tabular-nums")}>{fmtNum(g.unassigned)}</td>
                        <td className={cn(td, "text-right")}>
                          <Link href={href({ subnet: open ? undefined : g.subnet })} aria-expanded={open} className={linkCls}>{open ? "свернуть" : "раскрыть"}</Link>
                        </td>
                      </tr>
                    );
                  })}
                </tbody>
              </table>
            </div>
          )}
        {!groupsError && (gpage > 1 || groups.length === pageSize) && (
          <div className="mt-2 flex flex-wrap gap-3 text-[13px]">
            <span className="text-muted-foreground">группы {fmtNum((gpage - 1) * pageSize + 1)}–{fmtNum((gpage - 1) * pageSize + groups.length)} из {fmtNum(summary.subnets)}</span>
            {gpage > 1 && <Link href={href({ gpage: gpage > 2 ? String(gpage - 1) : undefined, subnet: undefined, spage: undefined })} className={linkCls}>← предыдущие</Link>}
            {groups.length === pageSize && <Link href={href({ gpage: String(gpage + 1), subnet: undefined, spage: undefined })} className={linkCls}>следующие →</Link>}
          </div>
        )}
        {children}
      </div>
    </details>
  );
}

/** Инциденты раскрытой подсети компактной таблицей. */
export function ScanSubnetTable({ rows, blocks, now }: { rows: ScanSubnetRow[]; blocks: Record<string, BlockState>; now: Date }) {
  return (
    <div className="overflow-x-auto rounded-md border border-border/60">
      <table className="w-full text-[13px]">
        <thead>
          <tr className="border-b border-border/60">
            <th scope="col" className={th}>Инцидент</th>
            <th scope="col" className={th}>Адрес</th>
            <th scope="col" className={th}>Что</th>
            <th scope="col" className={th}>Последнее</th>
            <th scope="col" className={th}>Уровень</th>
            <th scope="col" className={th}>Статус</th>
            <th scope="col" className={th}>Ответственный</th>
            <th scope="col" className={th}>Блокировка</th>
          </tr>
        </thead>
        <tbody>
          {rows.map((row) => {
            const st = blocks[row.incident_id] ?? "none";
            return (
              <tr key={row.incident_id} className="border-b border-border/40">
                <td className={cn(td, "font-mono text-[12px] whitespace-nowrap")}><Link href={`/incidents/${row.incident_id}`} className={linkCls}>{row.incident_id}</Link></td>
                <td className={cn(td, "font-mono text-[12px] break-all")}>{row.actor_name}</td>
                <td className={td} title={row.rule_id}>{row.rule_title || row.rule_id}</td>
                <td className={td}><Ago ts={row.last_ts} now={now} className="text-muted-foreground" /></td>
                <td className={td}><LevelBadge level={row.level} /></td>
                <td className={td}><StatusBadge status={row.status} /></td>
                <td className={td}>{row.owner || <span className="text-muted-foreground">не назначен</span>}</td>
                <td className={cn(td, st === "blocked" ? "text-[var(--status-err)]" : st === "failed" ? "text-[var(--status-warn)]" : "text-muted-foreground")}>{BLOCK_LABEL[st]}</td>
              </tr>
            );
          })}
        </tbody>
      </table>
    </div>
  );
}

/** Первые названия правил группы и «ещё N» — у групп бывают сотни разных правил. */
function Titles({ items, max = 3 }: { items: string[]; max?: number }) {
  const rest = items.length - max;
  return <span className="line-clamp-2">{items.slice(0, max).join(", ")}{rest > 0 && <span className="text-muted-foreground"> и ещё {fmtNum(rest)}</span>}</span>;
}
