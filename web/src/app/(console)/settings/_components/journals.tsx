// Журналы страницы «Настройки»: реагирование — лентой по дням (как в
// референсе), действия — таблицей с заголовками и человеческими подписями.
// Ничего не обрезается по ширине: длинные пояснения переносятся.
import Link from "next/link";
import { FlaskConical, ShieldBan, ShieldCheck, ShieldX, Timer } from "lucide-react";
import { Empty } from "@/components/console/panel";
import { FeedDay, FeedList, FeedRow } from "@/components/console/feed";
import { TONE_CLASS, type Tone } from "@/components/console/tone";
import type { AuditRow, ResponseLogRow } from "@/lib/argus-queries";
import { groupFeedByDay } from "@/lib/shared/feed";
import { auditActionLabel, responseView } from "@/lib/shared/settings-view";
import { formatTs } from "@/lib/shared/time";
import { cn } from "@/lib/utils";

const MODE_TONE: Record<string, Tone> = { ips: "err", manual: "warn", simulate: "neutral", ids: "muted" };
const MODE_LABEL: Record<string, string> = { ips: "IPS", manual: "оператор", simulate: "симуляция", ids: "IDS" };

// FeedRow усекает заголовок и части второй строки; в журналах важен текст целиком —
// разрешаем перенос (локально: общий FeedRow пока без такого режима).
const WRAP = "[&_.truncate]:whitespace-normal [&_.truncate]:break-words";

function IncidentLink({ id }: { id: string }) {
  if (!id) return null;
  return (
    <Link href={`/incidents/${encodeURIComponent(id)}`} title={id} className="inline-block max-w-[14ch] overflow-hidden text-ellipsis whitespace-nowrap align-bottom font-mono text-[var(--ring)] hover:underline">
      {id}
    </Link>
  );
}

export function ResponseFeed({ rows, now }: { rows: ResponseLogRow[]; now: Date }) {
  if (rows.length === 0) return <Empty title="Журнал пуст" hint="Здесь появятся автоблокировки, симуляции и ручные блокировки оператора." />;
  return (
    <FeedList label="Журнал реагирования" className={cn("max-h-[36rem] overflow-y-auto", WRAP)}>
      {groupFeedByDay(rows, (r) => r.ts, now).map((g) => (
        <FeedDay key={g.key} heading={g.heading} sticky>
          {g.items.map((r) => {
            const v = responseView(r);
            const simulated = Boolean(r.dry_run) || r.mode === "simulate";
            const icon = v.kind === "simulate" ? FlaskConical : v.kind === "unblock" ? ShieldCheck : v.flagged ? ShieldX : v.tone === "warn" ? Timer : ShieldBan;
            return (
              <FeedRow
                key={`${r.ts}|${r.incident_id}|${r.ip}|${r.executor}|${r.detail}`}
                icon={icon}
                tone={v.tone}
                flagged={v.flagged}
                title={v.title}
                badge={
                  <span className={cn("shrink-0 rounded-sm border px-1.5 text-[11px] leading-4", TONE_CLASS[simulated ? "neutral" : MODE_TONE[r.mode] ?? "muted"])}>
                    {simulated ? "симуляция" : MODE_LABEL[r.mode] ?? r.mode}
                  </span>
                }
                meta={[
                  r.incident_id ? <IncidentLink id={r.incident_id} /> : null,
                  r.actor === "argus-engine" ? "движок" : r.actor,
                  v.note,
                  r.reason ? `причина: ${r.reason}` : null,
                ]}
                time={formatTs(r.ts, "time").slice(0, 5)}
                timeTitle={formatTs(r.ts)}
              />
            );
          })}
        </FeedDay>
      ))}
    </FeedList>
  );
}

export function AuditTable({ rows }: { rows: AuditRow[] }) {
  if (rows.length === 0) return <Empty title="Журнал пуст" hint="Здесь появятся входы, смена статусов, блокировки и другие действия в консоли." />;
  return (
    <div className="c-well max-h-[40rem] overflow-auto p-2">
      <table className="w-full table-fixed text-sm">
        <colgroup>
          <col className="w-[7.5rem]" />
          <col className="w-[11rem]" />
          <col className="w-[15rem]" />
          <col className="w-[11rem]" />
          <col />
        </colgroup>
        <thead className="sticky top-0 bg-[var(--surface-deep)]">
          <tr className="border-b border-border/60 text-left">
            <th scope="col" className="c-label py-1.5 pr-3 font-normal">Когда</th>
            <th scope="col" className="c-label py-1.5 pr-3 font-normal">Кто</th>
            <th scope="col" className="c-label py-1.5 pr-3 font-normal">Действие</th>
            <th scope="col" className="c-label py-1.5 pr-3 font-normal">Объект</th>
            <th scope="col" className="c-label py-1.5 font-normal">Подробности</th>
          </tr>
        </thead>
        <tbody>
          {rows.map((a, i) => {
            const { label, failed } = auditActionLabel(a.action);
            return (
              <tr key={i} className="border-b border-border/40 align-top">
                <td className="py-1.5 pr-3 font-mono text-[12px] whitespace-nowrap text-muted-foreground" title={formatTs(a.ts)}>{formatTs(a.ts, "short")}</td>
                <td className="py-1.5 pr-3 font-mono text-[12px] break-words">{a.user}</td>
                <td className={cn("py-1.5 pr-3 break-words", failed ? "text-[var(--status-err)]" : "text-foreground")} title={a.action}>{label}</td>
                <td className="py-1.5 pr-3 font-mono text-[12px] break-all">
                  {a.target.startsWith("INC-") ? <IncidentLink id={a.target} /> : a.target}
                </td>
                <td className="py-1.5 text-[13px] break-words text-muted-foreground">{a.detail}</td>
              </tr>
            );
          })}
        </tbody>
      </table>
    </div>
  );
}
