import { Database } from "lucide-react";
import { Led, Panel } from "@/components/console/panel";

/**
 * Хранилище недоступно: вместо падения дерева страницы — окно с короткой
 * причиной. Шапка и навигация остаются, разделы без ClickHouse работают.
 */
export function StorageUnavailable({ reason, label = "Хранилище недоступно" }: { reason: string; label?: string }) {
  return (
    <Panel label={label} meta="clickhouse">
      <div className="flex items-start gap-3">
        <Database strokeWidth={1.5} className="mt-0.5 h-4 w-4 shrink-0 text-muted-foreground" aria-hidden />
        <div className="space-y-2">
          <p className="flex items-center gap-2 text-sm text-foreground">
            <Led color="var(--status-err)" />
            {reason}
          </p>
          <p className="text-sm text-muted-foreground">
            Данные появятся, как только ClickHouse ответит. Проверьте контейнер <span className="font-mono">clickhouse</span> и переменные CLICKHOUSE_* консоли; полный текст ошибки — в журнале контейнера <span className="font-mono">web</span>.
          </p>
        </div>
      </div>
    </Panel>
  );
}
