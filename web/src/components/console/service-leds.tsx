import { Led } from "@/components/console/panel";
import { clickhouseState, engineState } from "@/lib/clickhouse";

/** LED состояния ClickHouse и движка в шапке: SELECT 1 / healthz, таймаут 2 с, кэш 10 с. */
export async function ServiceLeds() {
  const [ch, engine] = await Promise.all([clickhouseState(), engineState()]);
  const items = [
    { key: "ch", label: "clickhouse", state: ch },
    { key: "engine", label: "движок", state: engine },
  ];
  return (
    <ul className="flex items-center gap-3" aria-label="Состояние служб">
      {items.map((it) => (
        <li key={it.key} className="flex items-center gap-1.5 text-[12px] text-muted-foreground" title={it.state.detail}>
          <Led color={it.state.ok ? "var(--status-ok)" : "var(--status-err)"} />
          <span className="hidden xl:inline">{it.label}</span>
          <span className="sr-only">{it.state.detail}</span>
        </li>
      ))}
    </ul>
  );
}
