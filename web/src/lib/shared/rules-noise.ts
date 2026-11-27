// Шумность правил корреляции по статистике ложных за 30 дней: порядок
// таблицы «Правила корреляции» и порог подсветки. Чистые функции — их
// проверяют тесты без рендера.

export type RuleFpStat = { total: number; false_positive: number };

/** Подсвечивать долю ложных: не меньше половины при хотя бы 5 инцидентах. */
export const NOISY_SHARE = 0.5;
export const NOISY_MIN_N = 5;

export function fpShare(s: RuleFpStat | undefined): number {
  return s && s.total > 0 ? s.false_positive / s.total : 0;
}

export function isNoisy(s: RuleFpStat | undefined): boolean {
  return Boolean(s && s.total >= NOISY_MIN_N && fpShare(s) >= NOISY_SHARE);
}

/**
 * Сначала шумные: доля ложных по убыванию, при равной доле — больше
 * инцидентов выше; правила без инцидентов за 30 дней — в конце. Исходный
 * порядок (порядок движка) сохраняется внутри равных.
 */
export function sortByNoise<T>(items: readonly T[], id: (item: T) => string, stats: Record<string, RuleFpStat | undefined>): T[] {
  return items
    .map((item, i) => ({ item, i, s: stats[id(item)] }))
    .sort((a, b) => {
      const at = a.s?.total ?? 0, bt = b.s?.total ?? 0;
      if ((at === 0) !== (bt === 0)) return at === 0 ? 1 : -1;
      const d = fpShare(b.s) - fpShare(a.s);
      if (d !== 0) return d;
      if (bt !== at) return bt - at;
      return a.i - b.i;
    })
    .map((x) => x.item);
}
