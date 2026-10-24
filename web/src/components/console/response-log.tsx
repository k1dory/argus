import type { ResponseLogRow } from "@/lib/argus-queries";
import { cn } from "@/lib/utils";
import { OUTCOME_LABELS } from "@/lib/shared/labels";
import { formatTs } from "@/lib/shared/time";
import { Copyable } from "./copyable";
import { searchHref } from "@/lib/shared/search-href";
import { TONE_CLASS, type Tone } from "./tone";

const MODE_TONE: Record<string, Tone> = { ips: "err", manual: "warn", simulate: "neutral", ids: "muted" };
const MODE_LABEL: Record<string, string> = { ips: "IPS", manual: "оператор", simulate: "симуляция", ids: "IDS" };

/** Журнал реагирования: кто, кого, чем и по-настоящему ли. */
export function ResponseLog({ rows, compact = false }: { rows: ResponseLogRow[]; compact?: boolean }) {
  if (rows.length === 0) return <p className="text-xs text-muted-foreground">пусто — ни одной автоблокировки или симуляции</p>;
  return (
    <div className="c-well max-h-80 overflow-auto p-2 font-mono text-xs">
      <table className="w-full">
        <thead>
          <tr className="border-b border-border/60 text-left">
            <th scope="col" className="c-label py-1 pr-3">время</th>
            <th scope="col" className="c-label py-1 pr-3">режим</th>
            {!compact && <th scope="col" className="c-label py-1 pr-3">инцидент</th>}
            <th scope="col" className="c-label py-1 pr-3">адрес</th>
            <th scope="col" className="c-label py-1 pr-3">исполнитель</th>
            <th scope="col" className="c-label py-1 pr-3">итог</th>
            <th scope="col" className="c-label py-1">детали</th>
          </tr>
        </thead>
        <tbody>
          {rows.map((r) => {
            const simulated = r.dry_run || r.mode === "simulate";
            return (
              <tr key={`${r.ts}|${r.incident_id}|${r.ip}|${r.executor}|${r.detail}`} className="border-b border-border/40 align-top">
                <td className="whitespace-nowrap py-1 pr-3 text-muted-foreground">{formatTs(r.ts)}</td>
                <td className="py-1 pr-3"><span className={cn("inline-block border px-1.5 text-[11px]", TONE_CLASS[simulated ? "neutral" : MODE_TONE[r.mode] ?? "muted"])}>{simulated ? "симуляция" : MODE_LABEL[r.mode] ?? r.mode}</span></td>
                {!compact && <td className="py-1 pr-3">{r.incident_id}</td>}
                <td className="py-1 pr-3"><Copyable value={r.ip} href={searchHref.srcip(r.ip)} label="IP" /></td>
                <td className="py-1 pr-3 text-muted-foreground">{r.executor}</td>
                <td className={cn("py-1 pr-3", r.ok ? "text-[var(--status-ok)]" : "text-destructive")}>{r.ok ? OUTCOME_LABELS.ok : OUTCOME_LABELS.error}</td>
                <td className="py-1 text-muted-foreground">{r.detail}{r.reason && !compact ? ` · ${r.reason}` : ""}</td>
              </tr>
            );
          })}
        </tbody>
      </table>
    </div>
  );
}
