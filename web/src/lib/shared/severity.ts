// Пороги серьёзности по индексам поиска — одно место для SQL-гистограммы,
// бейджей и тонов: уровень правила Wazuh 0..15, серьёзность события 0..10.
import type { Tone } from "@/components/console/tone";

export type SeverityThresholds = { medium: number; high: number; critical: number };
export const SEVERITY: Record<"alerts" | "events", SeverityThresholds> = {
  alerts: { medium: 4, high: 7, critical: 12 },
  events: { medium: 3, high: 5, critical: 8 },
};

export function severityTone(t: SeverityThresholds, v: number): Tone {
  if (v >= t.critical) return "err";
  if (v >= t.high) return "warn";
  if (v >= t.medium) return "neutral";
  return "muted";
}

/** Верх шкалы индекса: уровень правила Wazuh — до 15, серьёзность события — до 10. */
export const SEVERITY_MAX: Record<"alerts" | "events", number> = { alerts: 15, events: 10 };

export type SeverityBand = { key: "critical" | "high" | "low"; label: string; range: string };

/**
 * Полосы гистограммы по порогам индекса — та же таблица, что у SQL-ряда
 * (low < high ≤ high < critical ≤ critical) и у тонов бейджей. Подписи
 * легенды строятся только отсюда: шкала Wazuh не попадёт на график событий.
 */
export function severityBands(t: SeverityThresholds, max: number): SeverityBand[] {
  const span = (a: number, b: number) => (a === b ? String(a) : `${a}–${b}`);
  return [
    { key: "critical", label: "критичные", range: span(t.critical, max) },
    { key: "high", label: "высокие", range: span(t.high, t.critical - 1) },
    { key: "low", label: "остальные", range: span(0, t.high - 1) },
  ];
}
