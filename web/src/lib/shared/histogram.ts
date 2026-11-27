// Подписи гистограммы по времени: «красивый» верх оси Y, короткая запись
// больших чисел, деления оси X по календарю (сутки, 3 часа…) и длительность
// столбика человеческими словами. Чистые функции — общие для журнала и поиска.
import { fmtNum } from "./time";

const MANTISSAS = [1, 1.2, 1.5, 2, 2.5, 3, 4, 5, 6, 7.5, 8, 10];

/** Наименьшее «круглое» число ≥ n: 70 054 → 75 000, 14 → 15, 0 → 1. */
export function niceCeil(n: number): number {
  if (!(n > 0)) return 1;
  const p = 10 ** Math.floor(Math.log10(n));
  for (const m of MANTISSAS) if (m * p >= n - 1e-9) return Math.round(m * p * 1000) / 1000;
  return 10 * p;
}

/** Короткая запись: 75 000 → «75 тыс.», 1 200 000 → «1,2 млн», до 10 000 — как есть. */
export function compactNum(n: number): string {
  const trim = (x: number) => fmtNum(Math.round(x * 10) / 10, Number.isInteger(Math.round(x * 10) / 10) ? 0 : 1);
  if (n >= 1_000_000) return `${trim(n / 1_000_000)} млн`;
  if (n >= 10_000) return `${trim(n / 1000)} тыс.`;
  return fmtNum(n, Number.isInteger(n) ? 0 : 1);
}

/** Длительность столбика: 30 → «30 мин», 240 → «4 ч», 1440 → «1 дн.». */
export function bucketLabel(minutes: number): string {
  if (minutes < 60) return `${minutes} мин`;
  if (minutes < 1440) return `${fmtNum(minutes / 60, minutes % 60 ? 1 : 0)} ч`;
  return `${fmtNum(minutes / 1440, minutes % 1440 ? 1 : 0)} дн.`;
}

const MIN = 60_000;
const STEPS = [5, 10, 15, 30, 60, 120, 180, 360, 720, 1440, 2880, 10080].map((m) => m * MIN);
const WEEKDAYS = ["вс", "пн", "вт", "ср", "чт", "пт", "сб"];
const pad = (n: number) => String(n).padStart(2, "0");

export type AxisTick = { ms: number; pos: number; label: string };

/**
 * Деления оси X по календарю UTC: шаг — наименьший из 5 мин … 7 дн., при
 * котором делений не больше maxTicks. Подпись суток — «пн 20», часов — «09:00»;
 * полночь внутри часовой шкалы тоже подписывается днём. pos — доля ширины 0..1.
 */
export function timeTicks(startMs: number, endMs: number, maxTicks = 8): AxisTick[] {
  const span = endMs - startMs;
  if (!(span > 0)) return [];
  const step = STEPS.find((s) => span / s <= maxTicks) ?? STEPS[STEPS.length - 1];
  const out: AxisTick[] = [];
  for (let ms = Math.ceil(startMs / step) * step; ms <= endMs; ms += step) {
    const d = new Date(ms);
    const midnight = d.getUTCHours() === 0 && d.getUTCMinutes() === 0;
    const label = step >= 1440 * MIN || midnight ? `${WEEKDAYS[d.getUTCDay()]} ${d.getUTCDate()}` : `${pad(d.getUTCHours())}:${pad(d.getUTCMinutes())}`;
    out.push({ ms, pos: (ms - startMs) / span, label });
  }
  return out;
}
