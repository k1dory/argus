import { cn } from "@/lib/utils";
import { formatAgo, formatTs, toDate } from "@/lib/shared/time";

/**
 * Относительное время «12 мин назад» в `<time>`; точное UTC — в title и
 * dateTime. staleAfterMs — порог, после которого время подсвечивается
 * тоном внимания (давно не было keepalive, старая оценка).
 *
 * Относительное время и подсветка — только при переданном now (снимок
 * «сейчас» с сервера): иначе разметка сервера и первого клиентского
 * рендера разошлась бы (гидрация). Без now — точное время «25.11 06:12».
 */
export function Ago({
  ts,
  now,
  staleAfterMs,
  className,
}: {
  ts: string | number | Date | null | undefined;
  /** Опорное «сейчас» — снимок с сервера; без него показывается точное время. */
  now?: Date;
  staleAfterMs?: number;
  className?: string;
}) {
  const d = toDate(ts);
  if (!d) return <span className={cn("text-muted-foreground", className)}>—</span>;
  const stale = now !== undefined && staleAfterMs !== undefined && now.getTime() - d.getTime() > staleAfterMs;
  return (
    <time
      dateTime={formatTs(d, "iso")}
      title={formatTs(d)}
      className={cn("whitespace-nowrap tabular-nums", stale && "text-[var(--status-warn)]", className)}
    >
      {now ? formatAgo(d, now) : formatTs(d, "short")}
    </time>
  );
}
