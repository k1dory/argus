// Строка очереди инцидентов лентой: «что · кто · где · когда». Полоса и фон —
// по срочности (просрочено/критический — красным, высокий — жёлтой полосой);
// вся строка — ссылка на карточку. Серверный компонент.
//
// Отличие от общего FeedRow: третья строка (короткий вердикт или итог
// закрытия), правая колонка из двух строк (время + срок/ответственный) и
// полоса без фона для «высокого». Кандидат на расширение FeedRow (extra, stripe).
import Link from "next/link";
import { CircleCheck, CircleDot, EyeOff, OctagonAlert, TriangleAlert, type LucideIcon } from "lucide-react";
import { Ago } from "@/components/console/ago";
import { LevelBadge, StatusBadge } from "@/components/console/incident-badges";
import { cn } from "@/lib/utils";
import { reactionDeadline } from "@/lib/shared/incident-sla";
import { formatSpan, incidentUrgency, isFinalStatus, overdueMs } from "@/lib/shared/incident-view";
import { formatTs } from "@/lib/shared/time";

export type IncidentRowData = {
  incident_id: string; created_at: string; first_ts: string; rule_id: string; rule_title: string;
  level: string; status: string; owner: string; actor_name: string; node: string; sources: string[]; pii: number;
};

/** Что под заголовком третьей строкой: вердикт модели, итог закрытия или пометка. */
export type IncidentRowNote =
  | { kind: "verdict"; text: string }
  | { kind: "closure"; text: string; title?: string }
  | { kind: "hint"; text: string };

const ICON: Record<string, LucideIcon> = { critical: OctagonAlert, high: TriangleAlert };

export function IncidentRow({ row, now, note, blind = false }: { row: IncidentRowData; now: Date; note?: IncidentRowNote; blind?: boolean }) {
  const urgency = incidentUrgency(row, now);
  const final = isFinalStatus(row.status);
  const late = overdueMs(row, now);
  const red = urgency === "overdue" || (urgency === "urgent" && row.level === "critical");
  const Icon = final ? CircleCheck : ICON[row.level] ?? CircleDot;
  const iconColor = final ? "var(--text-tertiary)" : row.level === "critical" ? "var(--status-err)" : row.level === "high" ? "var(--status-warn)" : "var(--fg-2)";
  const deadline = row.status === "new" ? reactionDeadline(row.created_at, row.level) : null;
  const meta = [row.actor_name, row.node, row.sources.join(" + ")].filter(Boolean);
  return (
    <li data-urgency={urgency}>
      <Link
        href={`/incidents/${row.incident_id}`}
        className={cn(
          "flex items-start gap-3.5 rounded-md px-3 py-2.5 transition-colors focus-visible:outline-2 focus-visible:outline-offset-[-2px] focus-visible:outline-[var(--ring)]",
          red ? "bg-[color-mix(in_oklab,var(--status-err)_7%,transparent)] shadow-[inset_2px_0_0_var(--status-err)] hover:bg-[color-mix(in_oklab,var(--status-err)_12%,transparent)]"
            : urgency === "urgent" ? "shadow-[inset_2px_0_0_var(--status-warn)] hover:bg-[var(--surface-elevated)]"
            : "hover:bg-[var(--surface-elevated)]",
        )}
      >
        <Icon className="mt-0.5 size-[18px] shrink-0" style={{ color: iconColor }} strokeWidth={1.5} aria-hidden />
        <div className="min-w-0 flex-1">
          <div className="flex min-w-0 flex-wrap items-center gap-x-2 gap-y-1">
            <span className={cn("min-w-0 truncate text-[15px] font-medium", final ? "text-[var(--fg-2)]" : "text-foreground")}>{row.rule_title || row.rule_id}</span>
            <LevelBadge level={row.level} />
            {row.status !== "new" && <StatusBadge status={row.status} />}
            {late !== null && (
              <span className="rounded-md border border-[var(--status-err)]/50 px-1.5 text-[12px] leading-5 text-[var(--status-err)]">Просрочено на {formatSpan(late)}</span>
            )}
            {row.pii === 1 && <span className="text-[12px] text-[var(--status-warn)]" title="В событиях есть персональные данные">перс. данные</span>}
          </div>
          <div className="mt-0.5 flex min-w-0 flex-wrap items-center gap-x-4 text-[13px] leading-5 text-muted-foreground">
            {meta.length === 0 && <span>субъект и узел не определены</span>}
            {meta.map((m, i) => <span key={i} className={cn("min-w-0 max-w-full truncate", i === 0 && "text-[var(--fg-2)]")}>{m}</span>)}
            <span className="font-mono text-[12px] text-[var(--text-tertiary)]" title={`${row.rule_id} · начало ${formatTs(row.first_ts)}`}>{row.incident_id}</span>
            {blind && <EyeOff className="size-3.5 shrink-0 text-[var(--text-tertiary)]" strokeWidth={1.5} aria-label="Разбор вслепую: подсказки модели скрыты до завершения" role="img" />}
          </div>
          {note && (
            <p className={cn("mt-0.5 line-clamp-1 text-[13px]", note.kind === "verdict" ? "text-[var(--fg-2)]" : "text-muted-foreground")} title={note.kind === "closure" ? note.title : note.text}>
              {note.text}
            </p>
          )}
        </div>
        <div className="flex shrink-0 flex-col items-end gap-0.5 text-right">
          <Ago ts={row.created_at} now={now} className="text-[13px] text-[var(--fg-2)]" />
          <span className="text-[12px] text-muted-foreground">
            {final ? null : row.owner ? `у ${row.owner}` : deadline && late === null ? `реакция до ${formatTs(deadline, "time")}` : "без ответственного"}
          </span>
        </div>
      </Link>
    </li>
  );
}
