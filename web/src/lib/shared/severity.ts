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
