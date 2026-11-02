/**
 * Память прокрутки страниц консоли между полными загрузками (F5, «назад» после
 * ухода с сайта). Страница консоли приходит потоком: сначала скелет, потом
 * таблица, поэтому штатное восстановление браузера срабатывает на короткой
 * странице и оставляет её наверху. Здесь положение хранится по адресу
 * (путь + query) в sessionStorage и возвращается, когда документ дорос до него.
 */

export const SCROLL_STORE_KEY = "argus-scroll:v1";
/** Сколько адресов помнить: дальше вытесняются самые старые. */
export const SCROLL_MAX_ENTRIES = 40;
/** Запись старше — не восстанавливается (вкладку открыли «с утра»). */
export const SCROLL_MAX_AGE_MS = 6 * 60 * 60 * 1000;
/** Сколько ждать, пока поток дорисует страницу до сохранённой высоты. */
export const SCROLL_RESTORE_TIMEOUT_MS = 8_000;

export type ScrollEntry = { y: number; at: number };
type Store = Record<string, ScrollEntry>;
type StorageLike = Pick<Storage, "getItem" | "setItem">;

/** Ключ страницы: путь и query, без фрагмента. */
export function scrollKey(pathname: string, search: string): string {
  const q = search && search !== "?" ? (search.startsWith("?") ? search : `?${search}`) : "";
  return `${pathname}${q}`;
}

function readStore(storage: StorageLike): Store {
  try {
    const raw = storage.getItem(SCROLL_STORE_KEY);
    if (!raw) return {};
    const parsed: unknown = JSON.parse(raw);
    if (!parsed || typeof parsed !== "object" || Array.isArray(parsed)) return {};
    const out: Store = {};
    for (const [k, v] of Object.entries(parsed as Record<string, unknown>)) {
      const e = v as Partial<ScrollEntry> | null;
      if (e && Number.isFinite(e.y) && Number.isFinite(e.at) && (e.y as number) >= 0) out[k] = { y: e.y as number, at: e.at as number };
    }
    return out;
  } catch {
    return {};
  }
}

/** Сохранить положение; хранилище недоступно или переполнено — молча пропустить. */
export function saveScroll(storage: StorageLike, key: string, y: number, now: number): void {
  if (!Number.isFinite(y) || y < 0) return;
  const store = readStore(storage);
  if (y === 0) delete store[key];
  else store[key] = { y: Math.round(y), at: now };
  const keys = Object.keys(store);
  if (keys.length > SCROLL_MAX_ENTRIES) {
    keys.sort((a, b) => store[a].at - store[b].at);
    for (const k of keys.slice(0, keys.length - SCROLL_MAX_ENTRIES)) delete store[k];
  }
  try {
    storage.setItem(SCROLL_STORE_KEY, JSON.stringify(store));
  } catch {
    // Квота или запрет хранилища — прокрутка не важнее работы страницы.
  }
}

/** Положение для восстановления или null: нет записи, она устарела или нулевая. */
export function loadScroll(storage: StorageLike, key: string, now: number): number | null {
  const e = readStore(storage)[key];
  if (!e || e.y <= 0) return null;
  if (now - e.at > SCROLL_MAX_AGE_MS || e.at > now + 60_000) return null;
  return e.y;
}

/**
 * Восстанавливать только при полной загрузке того же адреса: перезагрузка или
 * «назад/вперёд» в документ. Обычный переход по ссылке открывает страницу сверху.
 */
export function shouldRestore(navigationType: string | undefined): boolean {
  return navigationType === "reload" || navigationType === "back_forward";
}

export type RestoreEnv = {
  /** Наибольшая доступная прокрутка сейчас (scrollHeight − innerHeight). */
  maxScroll: () => number;
  scrollTo: (y: number) => void;
  now: () => number;
};

/**
 * Один шаг восстановления. Возвращает true, когда работа окончена: дошли до
 * цели или вышло время (тогда прокручиваем, сколько позволяет документ).
 */
export function restoreStep(env: RestoreEnv, target: number, startedAt: number): boolean {
  const max = env.maxScroll();
  if (max >= target) {
    env.scrollTo(target);
    return true;
  }
  if (env.now() - startedAt >= SCROLL_RESTORE_TIMEOUT_MS) {
    if (max > 0) env.scrollTo(max);
    return true;
  }
  return false;
}
