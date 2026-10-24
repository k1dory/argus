// Клампы числовых параметров запросов — одна функция для страниц, API и
// server actions. Значение вне диапазона или не число → запасное.
export function clampInt(v: unknown, min: number, max: number, fallback: number): number {
  const n = Math.floor(Number(v ?? fallback));
  if (!Number.isFinite(n)) return fallback;
  return Math.min(max, Math.max(min, n));
}

/** Номер страницы списков и API: 1…1000. */
export const MAX_API_PAGE = 1000;
export const clampPage = (v: unknown): number => clampInt(v, 1, MAX_API_PAGE, 1);

/** Уровень правила Wazuh: 0…15. */
export const MAX_LEVEL = 15;
export const clampLevel = (v: unknown): number => clampInt(v, 0, MAX_LEVEL, 0);
