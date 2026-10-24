// CSS-переменные серий графика собираются в <style> строкой — значит, ни один
// пользовательский ключ (значение колонки ClickHouse) не должен туда попасть.
// Ключи серий — только идентификаторы [A-Za-z0-9_-]; цвет — токен или hex.

const KEY_RE = /^[A-Za-z0-9_-]{1,64}$/;
const COLOR_RE = /^(var\(--[A-Za-z0-9-]{1,48}\)|#[0-9a-fA-F]{3,8}|[a-zA-Z]{1,24})$/;

export type ChartColorConfig = Record<string, { color?: string }>;

export function isSafeChartKey(key: string): boolean {
  return KEY_RE.test(key);
}

export function isSafeChartColor(color: string): boolean {
  return COLOR_RE.test(color);
}

/** Стабильный безопасный ключ серии по индексу: s0, s1, … Оригинал — в label. */
export function seriesSlug(index: number): string {
  return `s${index}`;
}

/** Тело <style> для контейнера графика; небезопасные пары молча пропускаются. */
export function chartStyleCss(chartId: string, config: ChartColorConfig): string {
  if (!/^[A-Za-z0-9_-]{1,80}$/.test(chartId)) return "";
  const lines = Object.entries(config)
    .filter(([key, item]) => Boolean(item?.color) && isSafeChartKey(key) && isSafeChartColor(String(item.color)))
    .map(([key, item]) => `  --color-${key}: ${item.color};`);
  if (lines.length === 0) return "";
  return `[data-chart=${chartId}] {\n${lines.join("\n")}\n}`;
}
