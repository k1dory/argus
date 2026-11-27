// Состояние экрана дашборда без React: окно времени (пресет или точный
// интервал), общая ошибка панелей, перехват ссылок при несохранённых правках
// и удаление панели с возвратом. Всё чистое — проверяется тестами.
import { parseTimeFilter, type SearchParamsLike, type TimeFilter } from "./filters";
import type { RangeKey } from "./ranges";

export type BoardTime = {
  time: TimeFilter;
  /** Пресет для подсветки в RangePicker; при точном интервале — undefined (ни один пресет не горит). */
  picker?: RangeKey;
  /** Пресет, от которого считаются шаги и подписи осей; при точном интервале — последний выбранный или 24 ч. */
  range: RangeKey;
  /** Окно для запросов панелей: пресет или точный интервал. */
  window: RangeKey | TimeFilter;
  /** Точный интервал задан. */
  exact: boolean;
  /** Строка запроса для ссылок «Редактировать»/«К дашборду», сохраняющая окно. */
  query: string;
};

/**
 * Окно доски из URL. Раньше пресет «24 часа» подсвечивался и при точном
 * интервале (range = time.range ?? "24h" уходил в RangePicker), хотя данные
 * показаны за другое окно.
 */
export function boardTime(sp: SearchParamsLike, now = Date.now()): BoardTime {
  const time = parseTimeFilter(sp, { defaultRange: "24h" }, now);
  const range = time.range ?? "24h";
  const exact = Boolean(time.from);
  const q = new URLSearchParams();
  if (exact) {
    q.set("from", time.from!);
    if (time.to) q.set("to", time.to);
  } else q.set("range", range);
  return { time, picker: exact ? undefined : range, range, window: exact ? time : range, exact, query: q.toString() };
}

/** «27.11 08:00 — 27.11 12:00» для чипа интервала; без конца — «… — сейчас». */
export function intervalLabel(t: TimeFilter): string | null {
  if (!t.from) return null;
  const short = (v: string) => {
    const m = /^(\d{4})-(\d{2})-(\d{2})T(\d{2}):(\d{2})/.exec(v);
    return m ? `${m[3]}.${m[2]} ${m[4]}:${m[5]}` : v;
  };
  return `${short(t.from)} — ${t.to ? short(t.to) : "сейчас"}`;
}

type ErrLike = { error?: string; errorDetail?: string };

/**
 * Одна причина на всю доску: все панели упали с одинаковой ошибкой
 * (обычно — не настроена учётная запись только для чтения). Тогда над
 * сеткой одна плашка, а не N одинаковых красных абзацев.
 */
export function commonPanelError(results: readonly ErrLike[]): { error: string; detail?: string } | null {
  if (results.length < 2) return null;
  const first = results[0].error;
  if (!first || !results.every((r) => r.error === first)) return null;
  return { error: first, detail: results.find((r) => r.errorDetail)?.errorDetail };
}

/** Человеческая фраза о причине для всех ролей; технический текст — только администратору. */
export function humanPanelError(error: string): { text: string; admin: string | null } {
  if (/CLICKHOUSE_RO_|read-only пользователь не настроен/i.test(error)) {
    return {
      text: "Доска не может читать данные: для дашбордов не настроена учётная запись только для чтения.",
      admin: "Задайте CLICKHOUSE_RO_USER и CLICKHOUSE_RO_PASSWORD в окружении консоли и перезапустите её.",
    };
  }
  return { text: "Доска не может читать данные: хранилище событий не ответило на запросы панелей.", admin: null };
}

/**
 * Куда уводит клик, если его надо перехватить из-за несохранённых правок.
 * null — клик не трогаем: не ссылка, новая вкладка, модификаторы, скачивание,
 * чужой сайт, переход по якорю на той же странице.
 */
export function guardedHref(
  click: { button: number; metaKey?: boolean; ctrlKey?: boolean; shiftKey?: boolean; altKey?: boolean; defaultPrevented?: boolean },
  anchor: { href: string; target?: string; download?: boolean } | null,
  location: { href: string; origin: string },
): string | null {
  if (!anchor || click.defaultPrevented || click.button !== 0) return null;
  if (click.metaKey || click.ctrlKey || click.shiftKey || click.altKey) return null;
  if (anchor.download || (anchor.target && anchor.target !== "_self")) return null;
  let url: URL;
  try {
    url = new URL(anchor.href, location.href);
  } catch {
    return null;
  }
  if (url.origin !== location.origin) return null;
  const here = new URL(location.href);
  if (url.pathname === here.pathname && url.search === here.search) return null;
  return url.pathname + url.search + url.hash;
}

/** Удаление панели с возможностью вернуть её на то же место. */
export function removeAt<T>(list: readonly T[], i: number): { list: T[]; removed: T | undefined } {
  return { list: list.filter((_, j) => j !== i), removed: list[i] };
}

export function restoreAt<T extends { id: string }>(list: readonly T[], item: T, i: number): T[] {
  if (list.some((x) => x.id === item.id)) return [...list];
  const at = Math.max(0, Math.min(i, list.length));
  return [...list.slice(0, at), item, ...list.slice(at)];
}

/** Подпись колонки SQL для читателя: source_class → «Source class». Имена с пробелами (AS "Событий") — как есть. */
export function columnLabel(c: string): string {
  if (/\s/.test(c) || !c.includes("_")) return c;
  const s = c.replace(/_+/g, " ").trim();
  return s ? s[0].toUpperCase() + s.slice(1) : c;
}

/** Варианты автообновления в редакторе вместо свободного ввода «30s». */
export const REFRESH_OPTIONS: { value: string; label: string }[] = [
  { value: "off", label: "Выключено" },
  { value: "30s", label: "30 с" },
  { value: "60s", label: "1 мин" },
  { value: "300s", label: "5 мин" },
  { value: "900s", label: "15 мин" },
];
