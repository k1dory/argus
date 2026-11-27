// Статус источника для страницы «Источники» и «Обзора»: молчит/работает,
// группы, вкладки по статусу и одна человеческая фраза вместо трёх колонок
// («Молчит 3 ч · обычно шлёт непрерывно»). Чистые функции, без React.
import { formatDuration, formatRhythm } from "./source-health";

export type SourceStatusKey = "all" | "silent" | "alive";
export const SOURCE_STATUS_KEYS: readonly SourceStatusKey[] = ["all", "silent", "alive"];

export function parseSourceStatus(v: unknown): SourceStatusKey {
  return v === "silent" || v === "alive" ? v : "all";
}

type Row = { alive: number; rhythm_sec: number | null; silent_for_sec: number; eps_60s: number; events_1h: number };

/** Обычный ритм словами: «обычно шлёт непрерывно», «обычно раз в 2 ч», «ритм ещё не известен». */
export function rhythmPhrase(rhythmSec: number | null): string {
  if (rhythmSec === null) return "ритм ещё не известен";
  return `обычно шлёт ${formatRhythm(rhythmSec)}`;
}

/**
 * Первая часть фразы — статус: «Молчит 3 ч» / «Работает»; вторая — ритм.
 * Работающему важнее поток, молчащему — сколько он молчит и как обычно шлёт.
 */
export function sourceStatusPhrase(h: Row): { head: string; rhythm: string } {
  if (!h.alive) return { head: `Молчит ${formatDuration(h.silent_for_sec)}`, rhythm: rhythmPhrase(h.rhythm_sec) };
  return { head: "Работает", rhythm: rhythmPhrase(h.rhythm_sec) };
}

/** Поток: «1,2 соб/с», при нуле — «—». */
export function flowText(eps: number): string {
  if (!Number.isFinite(eps) || eps <= 0) return "—";
  return `${eps.toLocaleString("ru-RU", { maximumFractionDigits: eps < 10 ? 1 : 0 })} соб/с`;
}

/** Молчащие — по длительности тишины (дольше всех — сверху); работающие — порядок как пришёл. */
export function splitByStatus<T extends Row>(rows: readonly T[]): { silent: T[]; alive: T[] } {
  const silent = rows.filter((r) => !r.alive).sort((a, b) => b.silent_for_sec - a.silent_for_sec);
  const alive = rows.filter((r) => Boolean(r.alive));
  return { silent, alive };
}
