import { Skeleton } from "@/components/ui/skeleton";
import { Panel } from "@/components/console/panel";

/** Скелеты в стиле окна консоли: рамка настоящая, содержимое — полосы. */

export function StatRowSkeleton({ count = 4 }: { count?: number }) {
  return (
    <div className="grid grid-cols-2 gap-6 md:grid-cols-4" aria-hidden>
      {Array.from({ length: count }, (_, i) => (
        <div key={i} className="win p-5">
          <Skeleton className="h-3 w-24" />
          <Skeleton className="mt-4 h-8 w-16" />
        </div>
      ))}
    </div>
  );
}

export function TableSkeleton({ rows = 8, label = "загрузка" }: { rows?: number; label?: string }) {
  return (
    <Panel label={label} meta="…">
      <div className="space-y-2" aria-hidden>
        <Skeleton className="h-3 w-full" />
        {Array.from({ length: rows }, (_, i) => (
          <Skeleton key={i} className="h-6 w-full" style={{ opacity: 1 - i / (rows + 2) }} />
        ))}
      </div>
    </Panel>
  );
}

export function ChartSkeleton({ label = "загрузка", height = 288 }: { label?: string; height?: number }) {
  return (
    <Panel label={label} meta="…">
      <div className="flex items-end gap-1" style={{ height }} aria-hidden>
        {Array.from({ length: 36 }, (_, i) => (
          <Skeleton key={i} className="w-full" style={{ height: `${20 + ((i * 37) % 60)}%` }} />
        ))}
      </div>
    </Panel>
  );
}

export function PanelSkeleton({ label = "загрузка", lines = 4 }: { label?: string; lines?: number }) {
  return (
    <Panel label={label} meta="…">
      <div className="space-y-3" aria-hidden>
        {Array.from({ length: lines }, (_, i) => (
          <Skeleton key={i} className="h-4" style={{ width: `${90 - i * 12}%` }} />
        ))}
      </div>
    </Panel>
  );
}

/** Скелет всей страницы: заголовок, плитки, окно. */
export function PageSkeleton() {
  return (
    <div className="space-y-8" role="status" aria-live="polite" aria-label="Загрузка страницы">
      <div className="flex flex-wrap items-center justify-between gap-4">
        <Skeleton className="h-9 w-48" />
        <Skeleton className="h-7 w-64" />
      </div>
      <StatRowSkeleton />
      <ChartSkeleton />
      <TableSkeleton />
      <span className="sr-only">Загрузка…</span>
    </div>
  );
}
