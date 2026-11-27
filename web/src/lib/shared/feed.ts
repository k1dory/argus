// Группировка строк ленты по дням UTC (порядок строк сохраняется) — общая
// для лент паспорта, инцидентов, журнала. Чистая функция, без React.
import { dayHeading, formatTs, utcDayKey } from "./time";

export type FeedDayGroup<T> = { key: string; heading: string; items: T[] };

export function groupFeedByDay<T>(items: readonly T[], at: (item: T) => string | number | Date | null | undefined, now: Date = new Date()): FeedDayGroup<T>[] {
  const out: FeedDayGroup<T>[] = [];
  for (const it of items) {
    const ts = at(it);
    const k = utcDayKey(ts);
    const key = k === null ? "—" : formatTs(ts, "date");
    const last = out[out.length - 1];
    if (last && last.key === key) last.items.push(it);
    else out.push({ key, heading: k === null ? "Без даты" : dayHeading(ts, now), items: [it] });
  }
  return out;
}
