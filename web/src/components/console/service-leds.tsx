import Link from "next/link";
import { Led } from "@/components/console/panel";
import { clickhouseState, engineState } from "@/lib/clickhouse";

/**
 * Состояние ClickHouse и движка в шапке: SELECT 1 / healthz, таймаут 2 с, кэш 10 с.
 * Исправная служба — точка и подпись (на телефоне — сокращённая); отказавшая —
 * красная пилюля «… недоступен», ссылка на «Источники».
 */
export async function ServiceLeds() {
  const [ch, engine] = await Promise.all([clickhouseState(), engineState()]);
  const items = [
    { key: "ch", label: "хранилище", short: "БД", down: "хранилище недоступно", state: ch },
    { key: "engine", label: "движок", short: "движок", down: "движок недоступен", state: engine },
  ];
  return (
    <ul className="flex flex-wrap items-center gap-x-3 gap-y-1" aria-label="Состояние служб">
      {items.map((it) =>
        it.state.ok ? (
          <li key={it.key} className="flex items-center gap-1.5 text-[12px] text-muted-foreground" title={it.state.detail}>
            <Led color="var(--status-ok)" />
            <span className="hidden sm:inline">{it.label}</span>
            <span className="sm:hidden" aria-hidden>{it.short}</span>
            <span className="sr-only">{it.state.detail}</span>
          </li>
        ) : (
          <li key={it.key}>
            <Link
              href="/sources"
              title={it.state.detail}
              className="inline-flex items-center gap-1.5 rounded-md border border-[var(--status-err)]/40 bg-[var(--status-err)]/10 px-2 py-0.5 text-[12px] font-medium text-[var(--status-err)] transition-colors hover:bg-[var(--status-err)]/20"
            >
              <Led color="var(--status-err)" />
              {it.down}
              <span className="sr-only">: {it.state.detail}</span>
            </Link>
          </li>
        ),
      )}
    </ul>
  );
}
