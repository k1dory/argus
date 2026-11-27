import { ServiceUnavailable } from "@/components/console/service-unavailable";

/**
 * Хранилище недоступно: вместо падения дерева страницы — окно ошибки.
 * Шапка и навигация остаются, разделы без ClickHouse работают. Обёртка над
 * ServiceUnavailable (service="clickhouse"); текст ошибки виден только admin.
 */
export function StorageUnavailable({ reason, label, what, admin }: { reason: string; label?: string; what?: string; admin?: boolean }) {
  return <ServiceUnavailable service="clickhouse" reason={reason} label={label} what={what} admin={admin} />;
}
