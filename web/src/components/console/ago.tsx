import { cn } from "@/lib/utils";
import { formatAgo, formatTs, toDate } from "@/lib/shared/time";

/**
 * Относительное время «12 мин назад» в `<time>`; точное UTC — в title и
 * dateTime. staleAfterMs — порог, после которого время подсвечивается
 * тоном внимания (давно не было keepalive, старая оценка).
 */
export function Ago({
  ts,
  now,
  staleAfterMs,
  className,
}: {
  ts: string | number | Date | null | undefined;
  /** Опорное «сейчас» (для тестов и согласованности на странице). */
  now?: Date;
  staleAfterMs?: number;
  className?: string;
}) {
  const d = toDate(ts);
  if (!d) return <span className={cn("text-muted-foreground", className)}>—</span>;
  const ref = now ?? new Date();
  const stale = staleAfterMs !== undefined && ref.getTime() - d.getTime() > staleAfterMs;
  return (
    <time
      dateTime={formatTs(d, "iso")}
      title={formatTs(d)}
      className={cn("whitespace-nowrap tabular-nums", stale && "text-[var(--status-warn)]", className)}
    >
      {formatAgo(d, ref)}
    </time>
  );
}
