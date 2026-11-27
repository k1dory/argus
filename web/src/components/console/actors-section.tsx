// Общие кусочки страниц раздела «Субъекты» (список, «Кому принадлежит»):
// переключатель периода вкладками, ячейка персоны в две строки, таблица в
// колодце. Серверные компоненты без состояния. Кандидаты в общий фундамент
// (PersonCell, DataWell) — см. ревью раздела, п. 5.
import Link from "next/link";
import { FilterTabs } from "@/components/console/filter-tabs";
import { Badge } from "@/components/ui/badge";
import { Table } from "@/components/ui/table";
import { RANGES } from "@/lib/shared/ranges";
import type { ActorRange } from "@/lib/shared/actors";
import { cn } from "@/lib/utils";

const PERIODS: ActorRange[] = ["24h", "7d", "30d"];

/** Единственное управление периодом на странице: вкладки-ссылки, текущая — aria-current. */
export function ActorPeriodTabs({ current, href, label = "Период" }: { current: ActorRange | ""; href: (r: ActorRange) => string; label?: string }) {
  return <FilterTabs label={label} current={current} items={PERIODS.map((r) => ({ key: r, label: RANGES[r].label, href: href(r) }))} />;
}

/** Ссылка в паспорт с сохранением периода. */
export const passportHref = (id: string, range: ActorRange): string => `/actors/${encodeURIComponent(id)}?range=${range}`;

/** «Кому принадлежит» с периодом. */
export const lookupHref = (v: string, range: ActorRange): string => `/actors/lookup?v=${encodeURIComponent(v)}&range=${range}`;

/** Персона в две строки: имя (ссылка в паспорт), ниже id моноширинным и пометка «служебная». */
export function PersonCell({ id, display, kind, range, className }: { id: string; display?: string; kind?: string; range: ActorRange; className?: string }) {
  return (
    <div className={cn("min-w-0", className)}>
      <Link href={passportHref(id, range)} className="text-[var(--ring)] hover:underline">{display || id}</Link>
      <div className="flex flex-wrap items-center gap-1.5">
        <span className="font-mono text-xs break-all text-[var(--text-tertiary)]">{id}</span>
        {kind === "service" && <Badge variant="outline" className="h-4 px-1.5 text-[11px]">служебная</Badge>}
      </div>
    </div>
  );
}

/** Таблица в колодце с горизонтальной прокруткой: длинные адреса не рвут панель. */
export function DataWell({ children, className }: { children: React.ReactNode; className?: string }) {
  return (
    <div className={cn("c-well overflow-x-auto p-2", className)}>
      <Table>{children}</Table>
    </div>
  );
}
