// Тона бейджей по семантике дизайн-системы: красный — ошибка/критично,
// жёлтый — внимание, синий — новое, зелёный — успех, серый — нейтрально.
// Только токены.
import { SEVERITY } from "@/lib/shared/severity";

/**
 * err — ошибка/критично; warn — внимание; info — новое, ждёт взгляда;
 * ok — успех; neutral — обычное; plain — «низкое», но читаемое (не путать
 * с отключённым); muted — неизвестно/неприменимо.
 */
export type Tone = "err" | "warn" | "info" | "ok" | "neutral" | "plain" | "muted";

/** Контурный бейдж: рамка и текст тона, лёгкая подложка. */
export const TONE_CLASS: Record<Tone, string> = {
  err: "border-[var(--status-err)]/40 bg-[var(--status-err)]/10 text-[var(--status-err)]",
  warn: "border-[var(--status-warn)]/40 bg-[var(--status-warn)]/10 text-[var(--status-warn)]",
  info: "border-[var(--status-info)]/50 bg-[var(--status-info)]/10 text-[var(--status-info)]",
  ok: "border-[var(--status-ok)]/40 bg-[var(--status-ok)]/10 text-[var(--status-ok)]",
  neutral: "border-[var(--fg-2)]/40 bg-[var(--fg-2)]/10 text-[var(--fg-2)]",
  plain: "border-[var(--border-strong)] bg-transparent text-[var(--fg-2)]",
  muted: "border-border bg-transparent text-muted-foreground",
};

/** Статусы — только контур, без подложки: ось «статус» не путается с осью «уровень» (заливка). */
export const TONE_OUTLINE_CLASS: Record<Tone, string> = {
  err: "border-[var(--status-err)]/60 bg-transparent text-[var(--status-err)]",
  warn: "border-[var(--status-warn)]/60 bg-transparent text-[var(--status-warn)]",
  info: "border-[var(--status-info)]/60 bg-transparent text-[var(--status-info)]",
  ok: "border-[var(--status-ok)]/50 bg-transparent text-[var(--status-ok)]",
  neutral: "border-[var(--fg-2)]/40 bg-transparent text-[var(--fg-2)]",
  plain: "border-[var(--border-strong)] bg-transparent text-[var(--fg-2)]",
  muted: "border-border bg-transparent text-muted-foreground",
};

/** Заливка тоном, текст цвета холста — для главного сигнала (критичный/высокий уровень). */
export const TONE_SOLID_CLASS: Partial<Record<Tone, string>> = {
  err: "border-[var(--status-err)] bg-[var(--status-err)] text-[var(--background)]",
  warn: "border-[var(--status-warn)] bg-[var(--status-warn)] text-[var(--background)]",
  info: "border-[var(--status-info)] bg-[var(--status-info)] text-[var(--background)]",
  ok: "border-[var(--status-ok)] bg-[var(--status-ok)] text-[var(--background)]",
};

/** Цвет текста/иконки тона (для Led, значений плиток, иконок строк ленты). */
export const TONE_COLOR: Record<Tone, string> = {
  err: "var(--status-err)",
  warn: "var(--status-warn)",
  info: "var(--status-info)",
  ok: "var(--status-ok)",
  neutral: "var(--fg-2)",
  plain: "var(--fg-2)",
  muted: "var(--muted-foreground)",
};

export const LEVEL_TONE: Record<string, Tone> = { critical: "err", high: "warn", medium: "neutral", low: "plain" };
export const STATUS_TONE: Record<string, Tone> = {
  escalated: "err", new: "info", in_progress: "neutral", waiting_owner: "warn", observing: "warn", closed: "ok", false_positive: "ok",
};
/** Серьёзность CVE (Critical/High/Medium/Low) — те же тона, ключи в нижнем регистре. */
export const VULN_TONE: Record<string, Tone> = { critical: "err", high: "warn", medium: "neutral", low: "plain", untriaged: "muted" };
/** Статус агента Wazuh. */
export const AGENT_STATUS_TONE: Record<string, Tone> = { active: "ok", disconnected: "err", never_connected: "muted", pending: "warn" };

export const toneFor = (map: Record<string, Tone>, key: string): Tone => map[key.toLowerCase()] ?? "muted";
/** Уровень правила Wazuh (число) → тон; пороги — в lib/shared/severity. */
export const ruleLevelTone = (level: number): Tone => (level >= SEVERITY.alerts.critical ? "err" : level >= SEVERITY.alerts.high ? "warn" : "muted");
