// Единое форматирование времени и чисел консоли. Все таймстампы ClickHouse —
// UTC (DateTime64 без зоны); показываем их в UTC с явной пометкой зоны, чтобы
// график, таблица и внешние системы SOC сходились по времени.

export type TsMode = "full" | "date" | "time" | "short" | "datetime";

export function toDate(value: string | number | Date | null | undefined): Date | null {
  if (value == null || value === "") return null;
  if (value instanceof Date) return Number.isNaN(value.getTime()) ? null : value;
  if (typeof value === "number") return new Date(value < 1e12 ? value * 1000 : value);
  // ClickHouse отдаёт "2026-09-13 18:05:07.123" без зоны — это UTC.
  const s = /^\d{4}-\d{2}-\d{2}[ T]\d{2}:\d{2}(:\d{2})?/.test(value) && !/[zZ]|[+-]\d{2}:?\d{2}$/.test(value)
    ? value.replace(" ", "T") + "Z"
    : value;
  const d = new Date(s);
  return Number.isNaN(d.getTime()) ? null : d;
}

const pad = (n: number) => String(n).padStart(2, "0");

/**
 * formatTs("2026-09-13 18:05:07") → "2026-09-13 18:05:07 UTC";
 * "datetime" → "2026-09-13 18:05" (без секунд и зоны, для лент);
 * "short" → "09-13 18:05"; "time" → "18:05:07"; "date" → "2026-09-13";
 * "iso" → ISO 8601 для `<time dateTime>`, на пустую/битую дату — undefined
 * (атрибут не ставится), остальные режимы на неё дают "—".
 */
export function formatTs(value: string | number | Date | null | undefined, mode: "iso"): string | undefined;
export function formatTs(value: string | number | Date | null | undefined, mode?: TsMode): string;
export function formatTs(value: string | number | Date | null | undefined, mode: TsMode | "iso" = "full"): string | undefined {
  const d = toDate(value);
  if (mode === "iso") return d ? d.toISOString() : undefined;
  if (!d) return "—";
  const date = `${d.getUTCFullYear()}-${pad(d.getUTCMonth() + 1)}-${pad(d.getUTCDate())}`;
  const time = `${pad(d.getUTCHours())}:${pad(d.getUTCMinutes())}`;
  const sec = pad(d.getUTCSeconds());
  switch (mode) {
    case "date":
      return date;
    case "time":
      return `${time}:${sec}`;
    case "short":
      return `${date.slice(5)} ${time}`;
    case "datetime":
      return `${date} ${time}`;
    default:
      return `${date} ${time}:${sec} UTC`;
  }
}

/** Подпись оси/тултипа графика: на коротких диапазонах ЧЧ:ММ, на длинных — ММ-ДД ЧЧ:ММ. */
export function formatAxisTs(value: string | number | Date, longRange: boolean): string {
  const d = toDate(value);
  if (!d) return String(value);
  // "short" уже без секунд; "time" — ЧЧ:ММ:СС, секунды отрезаем.
  return longRange ? formatTs(d, "short") : formatTs(d, "time").slice(0, 5);
}

/** Длинный ли диапазон для подписей оси: ключ диапазона или точный интервал. */
export function isLongRange(range: string | undefined, from?: string): boolean {
  return Boolean(from) || range === "7d" || range === "30d";
}

/** Относительное время: "2 мин назад", "3 ч назад", "5 дн назад". */
export function formatAgo(value: string | number | Date | null | undefined, now: Date = new Date()): string {
  const d = toDate(value);
  if (!d) return "—";
  const s = Math.max(0, Math.round((now.getTime() - d.getTime()) / 1000));
  if (s < 60) return `${s} с назад`;
  if (s < 3600) return `${Math.floor(s / 60)} мин назад`;
  if (s < 86400) return `${Math.floor(s / 3600)} ч назад`;
  return `${Math.floor(s / 86400)} дн назад`;
}

/** Числа с разделителями по-русски: 1 234 567. */
export function fmtNum(n: number | string | null | undefined, digits = 0): string {
  const v = typeof n === "string" ? Number(n) : n;
  if (v == null || Number.isNaN(v)) return "—";
  return v.toLocaleString("ru-RU", { maximumFractionDigits: digits, minimumFractionDigits: digits });
}

/** Длительность в мс → «12 мс» / «1,4 с». */
export function fmtMs(ms: number): string {
  if (!Number.isFinite(ms)) return "—";
  return ms < 1000 ? `${Math.round(ms)} мс` : `${fmtNum(ms / 1000, 1)} с`;
}
