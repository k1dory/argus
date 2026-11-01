// Live-tail журнала: один такт опроса GET /api/events/tail как чистая функция
// над fetch, курсором и состоянием ленты. Компонент EventFeed только применяет
// результат к своим ref/state — логика догона, 429 и ошибок проверяется без DOM.
import { journalParams, mergeTail, type IncidentRef, type JournalEvent, type JournalFilters, type TailState } from "./journal";
import { formatTs } from "./time";

export const TAIL_EVERY_MS = 5_000;
/** Сколько порций (по 100) забрать подряд за один такт, если сервер говорит more. */
export const CATCHUP_ROUNDS = 4;
export const MAX_ROWS = 500;
/** Пауза по 429: Retry-After в пределах 5–60 с; без заголовка или с мусором — 5 с. */
export const THROTTLE_MIN_SEC = 5;
export const THROTTLE_MAX_SEC = 60;

export type TailBody = { rows?: JournalEvent[]; incidents?: Record<string, IncidentRef[]>; cursor?: string; more?: boolean; pending?: number; error?: string };

export type TailInput = {
  filters: JournalFilters;
  /** Курсор «received_at|id» — откуда спрашивать. */
  cursor: string;
  state: TailState;
  signal?: AbortSignal;
  fetchFn?: typeof fetch;
  rounds?: number;
  maxRows?: number;
};

export type TailResult = {
  /** Курсор после такта: двигается только успешным ответом; ошибка или 429 — прежний. */
  cursor: string;
  state: TailState;
  added: JournalEvent[];
  trimmed: number;
  /** Сколько ещё ждёт на сервере (последний ответ с more); 0 — догнали. */
  pending: number;
  /** Секунды паузы по 429; 0 — лимита не было. */
  throttled: number;
  incidents: Record<string, IncidentRef[]>;
  /** Порция после первой не удалась: результат — то, что успели забрать до неё
   *  (курсор, строки, инциденты), а текст ошибки — для статуса. null — без ошибок. */
  error: string | null;
};

export function throttleSeconds(retryAfter: string | null | undefined): number {
  return Math.min(THROTTLE_MAX_SEC, Math.max(THROTTLE_MIN_SEC, Number(retryAfter) || THROTTLE_MIN_SEC));
}

/** URL такта: фильтры панели без интервала (tail — всегда «сейчас») и курсор. */
export function tailUrl(filters: JournalFilters, cursor: string): string {
  const params = journalParams(filters, { range: undefined, from: undefined, to: undefined });
  params.set("cursor", cursor);
  return `/api/events/tail?${params.toString()}`;
}

/**
 * Один такт: порции подряд, пока сервер отвечает more (не больше rounds).
 * 429 — не ошибка: курсор стоит, возвращается пауза по Retry-After. Не-2xx,
 * не-JSON или сетевой сбой на первой порции — исключение (следующий такт спросит
 * то же место). Сбой на следующей порции не отменяет уже забранные: результат
 * несёт продвинутый курсор и строки, а error — текст сбоя. Отменённый signal
 * останавливает догон между порциями.
 */
export async function pollTail(input: TailInput): Promise<TailResult> {
  const { filters, signal, fetchFn = fetch, rounds = CATCHUP_ROUNDS, maxRows = MAX_ROWS } = input;
  let { cursor, state } = input;
  const added: JournalEvent[] = [];
  const incidents: Record<string, IncidentRef[]> = {};
  let trimmed = 0;
  let pending = 0;
  for (let round = 0; round < rounds && !signal?.aborted; round++) {
    let res: Response;
    let body: TailBody;
    try {
      res = await fetchFn(tailUrl(filters, cursor), { cache: "no-store", signal });
      body = (await res.json()) as TailBody;
      if (res.status !== 429 && !res.ok) throw new Error(body.error ?? `HTTP ${res.status}`);
    } catch (e) {
      if (round === 0) throw e;
      return { cursor, state, added, trimmed, pending, throttled: 0, incidents, error: e instanceof Error ? e.message : "ошибка" };
    }
    if (res.status === 429) {
      return { cursor, state, added, trimmed, pending, throttled: throttleSeconds(res.headers.get("Retry-After")), incidents, error: null };
    }
    cursor = body.cursor ?? cursor;
    const merged = mergeTail(state, body.rows ?? [], maxRows);
    state = { rows: merged.rows, seen: merged.seen };
    added.push(...merged.added);
    trimmed += merged.trimmed;
    pending = body.more ? body.pending ?? 0 : 0;
    if (body.incidents) Object.assign(incidents, body.incidents);
    if (!body.more) break;
  }
  return { cursor, state, added, trimmed, pending, throttled: 0, incidents, error: null };
}

export type TailStatus = { at: string; added: number; pending: number; trimmed: number; throttled: number; error: string | null };

/** Накопление статуса между тактами: суммы added/trimmed, последние pending/throttled. */
export function nextStatus(prev: TailStatus | null, r: Pick<TailResult, "added" | "trimmed" | "pending" | "throttled"> & { error?: string | null }, at = new Date().toISOString()): TailStatus {
  return { at, added: (prev?.added ?? 0) + r.added.length, trimmed: (prev?.trimmed ?? 0) + r.trimmed, pending: r.pending, throttled: r.throttled, error: r.error ?? null };
}

export function errorStatus(prev: TailStatus | null, e: unknown, at = new Date().toISOString()): TailStatus {
  return { at, added: prev?.added ?? 0, trimmed: prev?.trimmed ?? 0, pending: prev?.pending ?? 0, throttled: 0, error: e instanceof Error ? e.message : "ошибка" };
}

/** Подпись состояния ленты рядом с кнопкой live-tail. */
export function tailStatusText(status: TailStatus | null, live: boolean, liveAllowed: boolean): string {
  if (!liveAllowed) return "live-tail недоступен для прошлого интервала";
  if (!status) return live ? "ждём новые события…" : "лента зафиксирована на момент загрузки";
  if (status.error) return `ошибка обновления: ${status.error} — повторим через ${TAIL_EVERY_MS / 1000} с, события не пропадут`;
  if (status.throttled) return `пауза ${status.throttled} с, догоняем — события не пропадут`;
  return `обновлено ${formatTs(status.at, "time")} UTC · пришло с начала live ${status.added}${status.pending ? ` · догоняем, в очереди ещё ${status.pending}` : ""}`;
}
