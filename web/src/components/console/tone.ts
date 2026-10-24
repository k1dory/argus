// Тона бейджей по семантике дизайн-системы: красный — ошибка/критично,
// оранжевый — внимание, зелёный — успех, серый — нейтрально. Только токены.
import { SEVERITY } from "@/lib/shared/severity";

export type Tone = "err" | "warn" | "ok" | "neutral" | "muted";

export const TONE_CLASS: Record<Tone, string> = {
  err: "border-[var(--status-err)]/40 bg-[var(--status-err)]/10 text-[var(--status-err)]",
  warn: "border-[var(--status-warn)]/40 bg-[var(--status-warn)]/10 text-[var(--status-warn)]",
  ok: "border-[var(--status-ok)]/40 bg-[var(--status-ok)]/10 text-[var(--status-ok)]",
  neutral: "border-[var(--fg-2)]/40 bg-[var(--fg-2)]/10 text-[var(--fg-2)]",
  muted: "border-border bg-transparent text-muted-foreground",
};

export const LEVEL_TONE: Record<string, Tone> = { critical: "err", high: "warn", medium: "neutral", low: "muted" };
export const STATUS_TONE: Record<string, Tone> = {
  escalated: "err", new: "neutral", in_progress: "neutral", waiting_owner: "warn", observing: "warn", closed: "ok", false_positive: "ok",
};
/** Серьёзность CVE (Critical/High/Medium/Low) — те же тона, ключи в нижнем регистре. */
export const VULN_TONE: Record<string, Tone> = { critical: "err", high: "warn", medium: "neutral", low: "muted", untriaged: "muted" };
/** Статус агента Wazuh. */
export const AGENT_STATUS_TONE: Record<string, Tone> = { active: "ok", disconnected: "err", never_connected: "muted", pending: "warn" };

export const toneFor = (map: Record<string, Tone>, key: string): Tone => map[key.toLowerCase()] ?? "muted";
/** Уровень правила Wazuh (число) → тон; пороги — в lib/shared/severity. */
export const ruleLevelTone = (level: number): Tone => (level >= SEVERITY.alerts.critical ? "err" : level >= SEVERITY.alerts.high ? "warn" : "muted");
