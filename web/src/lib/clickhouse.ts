import "server-only";
import { CH_ERROR_NAMES } from "./clickhouse-error-names";

// Серверный доступ к ClickHouse по HTTP-интерфейсу — тот же путь,
// которым пишут shipper и policyd. Чтение — chQuery, единственная запись
// консоли — мьюты правил и настройки через chCommand. Только с сервера.
const CH_URL = process.env.CLICKHOUSE_URL ?? "http://localhost:8123";
const CH_DB = process.env.CLICKHOUSE_DB ?? "argus";
const CH_USER = process.env.CLICKHOUSE_USER ?? "default";
const CH_PASSWORD = process.env.CLICKHOUSE_PASSWORD ?? "";
// У пользователя консоли в ClickHouse ограничено число одновременных запросов.
// Несколько открытых карточек не должны исчерпывать этот лимит и выдавать 503.
const CH_MAX_INFLIGHT = 8;

/** Ожидание слота прервано: истёк maxWaitMs или клиент ушёл (signal). */
export class LimiterWaitError extends Error {
  readonly reason: "timeout" | "aborted";
  constructor(reason: "timeout" | "aborted") {
    super(reason === "timeout" ? "очередь запросов занята" : "запрос отменён");
    this.name = "LimiterWaitError";
    this.reason = reason;
  }
}

export type LimiterOptions = { signal?: AbortSignal; maxWaitMs?: number };

/**
 * Не больше max одновременных fn на процесс; остальные ждут в очереди (FIFO).
 * Слот освобождается и после ошибки fn. Ожидание можно ограничить по времени
 * и отменить сигналом — тогда LimiterWaitError, а fn не вызывается.
 */
export function createLimiter(max: number) {
  let inflight = 0;
  const waiters: Array<() => void> = [];
  return async function run<T>(fn: () => Promise<T>, opts: LimiterOptions = {}): Promise<T> {
    if (inflight < max) inflight++;
    else {
      await new Promise<void>((resolve, reject) => {
        const { signal, maxWaitMs } = opts;
        let timer: ReturnType<typeof setTimeout> | null = null;
        const cleanup = () => {
          if (timer) clearTimeout(timer);
          signal?.removeEventListener("abort", onAbort);
        };
        const go = () => {
          cleanup();
          resolve();
        };
        const fail = (reason: "timeout" | "aborted") => {
          const i = waiters.indexOf(go);
          if (i >= 0) waiters.splice(i, 1);
          cleanup();
          reject(new LimiterWaitError(reason));
        };
        const onAbort = () => fail("aborted");
        if (signal?.aborted) return fail("aborted");
        signal?.addEventListener("abort", onAbort, { once: true });
        if (maxWaitMs != null) timer = setTimeout(() => fail("timeout"), maxWaitMs);
        waiters.push(go);
      });
    }
    try {
      return await fn();
    } finally {
      const next = waiters.shift();
      if (next) next(); // слот переходит следующему, inflight не меняется
      else inflight--;
    }
  };
}

const chLimit = createLimiter(CH_MAX_INFLIGHT);

/** Потолок одного запроса консоли: сервер (max_execution_time) и клиент (AbortSignal) согласованы. */
export const CH_TIMEOUT_MS = 30_000;
const DEFAULT_SETTINGS: Record<string, string | number> = { max_execution_time: 30 };

/** Настройки запроса; null — не передавать (и умолчание консоли тоже): значение
 *  задаёт профиль пользователя. Нужно для SQL, исполнимого и от argus_ro, у которого
 *  readonly = 1 отклоняет любую настройку, отличную от профиля. null убирает и параметр
 *  из CLICKHOUSE_URL. */
export type ChSettings = Record<string, string | number | null>;

/**
 * Ошибка хранилища для пользователя: короткая причина без SQL и без внутренностей
 * сервера. Полный текст — только в console.error на сервере.
 */
export class ClickHouseError extends Error {
  readonly status: number | null;
  readonly code: number | null;
  constructor(message: string, status: number | null = null, code: number | null = null) {
    super(message);
    this.name = "ClickHouseError";
    this.status = status;
    this.code = code;
  }
}

/** Строковые литералы SQL → «…» (для журнала: SQL пишет консоль, но литерал мог прийти
 *  от пользователя). К тексту исключений ClickHouse не применяется — он не выводится. */
function maskSqlLiterals(sql: string): string {
  return sql.replace(/'(?:\\.|''|[^'\\])*'/g, "'…'");
}

/** Ошибка ClickHouse для журнала и пользователя: только код, имя исключения из
 *  константного списка ClickHouse 24.8 по этому коду и HTTP-статус. Текст исключения
 *  не выводится вовсе: он цитирует данные запроса (строку INSERT, параметр, значение
 *  колонки) — замаскировать его регулярками надёжно нельзя (вложенные кавычки, обрезка,
 *  JSON-обёртка). Полный текст — в system.query_log по query_id. */
/** Код в теле ответа-ошибки (HTTP не 2xx): «Code: N. DB::Exception», «Poco::Exception.
 *  Code: N,», «std::exception. Code: N,», в том числе в {"exception": "…"}. Тело успешного
 *  ответа на исключение не разбирается: с wait_end_of_query=1 ClickHouse при любой ошибке
 *  отвечает HTTP-ошибкой с X-ClickHouse-Exception-Code, а «Code: 1.» в данных — это данные. */
const CH_ERROR_CODE_RE = /^(?:\{"exception":\s*")?(?:Poco::Exception\. |std::exception\. )?Code:\s*(\d+)[.,]/m;

/** X-ClickHouse-Exception-Code — только целое число; иначе (мусор, «__proto__») — нет кода. */
export function headerChCode(value: string | null): number | null {
  return value && /^\d{1,6}$/.test(value.trim()) && Number(value) > 0 ? Number(value) : null;
}

export function shortChError(text: string, status: number | null, headerCode: number | null = null): { message: string; code: number | null } {
  const parsed = Number(CH_ERROR_CODE_RE.exec(text)?.[1] ?? NaN);
  const code = headerCode && headerCode > 0 ? headerCode : Number.isFinite(parsed) ? parsed : null;
  if (code != null) {
    const name = Object.hasOwn(CH_ERROR_NAMES, code) ? CH_ERROR_NAMES[code] : undefined;
    return { message: name ? `код ${code} (${name})` : `код ${code}`, code };
  }
  if (status === 401 || status === 403) return { message: "доступ к ClickHouse отклонён (учётные данные консоли)", code: null };
  if (status) return { message: `ClickHouse ответил HTTP ${status}`, code: null };
  return { message: "запрос не выполнен", code: null };
}

function connectionError(e: unknown): ClickHouseError {
  const name = e instanceof Error ? e.name : "";
  if (name === "TimeoutError" || name === "AbortError") return new ClickHouseError(`ClickHouse не ответил за ${CH_TIMEOUT_MS / 1000} с`);
  const cause = (e as { cause?: { code?: string } } | null)?.cause?.code;
  if (cause === "ECONNREFUSED" || cause === "ENOTFOUND" || cause === "EAI_AGAIN") return new ClickHouseError("ClickHouse недоступен: нет соединения");
  return new ClickHouseError("ClickHouse недоступен");
}

/** Типы, значения которых ClickHouse читает из param_* в экранированном текстовом
 *  формате (как TSV): «\a» там — управляющий символ, «\\» — один обратный слэш. */
const STRING_PARAM_TYPE = /^(?:(?:Nullable|LowCardinality)\(\s*)*(?:String|FixedString\(\s*\d+\s*\))(?:\s*\))*$/;
const PARAM_PLACEHOLDER = /\{\s*([A-Za-z_][A-Za-z0-9_]*)\s*:\s*([^{}]+?)\s*\}/g;
const ESCAPED: Record<string, string> = { "\\": "\\\\", "\t": "\\t", "\n": "\\n", "\r": "\\r", "\0": "\\0", "\b": "\\b", "\f": "\\f" };

/** Значение строкового параметра в экранированном формате ClickHouse. */
export function escapeChString(value: string): string {
  return value.replace(/[\\\t\n\r\0\b\f]/g, (c) => ESCAPED[c]);
}

/** Имя параметра → тип из плейсхолдеров {name:Type} запроса. */
export function paramTypes(sql: string): Map<string, string> {
  const types = new Map<string, string>();
  for (const m of sql.matchAll(PARAM_PLACEHOLDER)) types.set(m[1], m[2]);
  return types;
}

/** Значение param_* для URL: строки (String, FixedString, Nullable/LowCardinality
 *  от них) экранируются по формату ClickHouse — иначе «dir\logs\auth» доходит с
 *  управляющим символом вместо «\a», а «\%» из экранирования LIKE теряет слэш.
 *  Остальные типы — как есть: числа и даты экранирования не содержат, а литералы
 *  Array(String) вызывающий собирает сам, со своими кавычками и экранированием. */
export function encodeParam(value: string | number, type: string | undefined): string {
  const text = String(value);
  return type !== undefined && STRING_PARAM_TYPE.test(type.trim()) ? escapeChString(text) : text;
}

/** Параметров в URL не больше стольких байт — остальное телом (см. chFetchWithSlot). */
export const PARAMS_IN_URL_MAX = 64 * 1024;
/** Предел значения поля формы ClickHouse (http_max_field_value_size, 128 КиБ на 24.8) с запасом. */
export const FORM_FIELD_MAX = 120 * 1024;
/** URI запроса не длиннее стольких байт: http_max_uri_size (1 MiB) с запасом. */
export const URI_MAX = 1000 * 1024;

/** URL в пределах ClickHouse: весь URI и каждое поле — в том виде, в каком уходят. */
function urlFits(url: URL): boolean {
  if (Buffer.byteLength(url.pathname + url.search, "utf8") > URI_MAX) return false;
  return url.search.slice(1).split("&").every((part) => part.length - part.indexOf("=") - 1 <= FORM_FIELD_MAX);
}

/** Граница multipart, которой нет ни в одной части. */
function multipartBoundary(parts: string[]): string {
  for (;;) {
    const b = `argus-${crypto.randomUUID()}`;
    if (!parts.some((p) => p.includes(b))) return b;
  }
}

function chFetch(sql: string, params: Record<string, string | number>, settings: ChSettings, format: string | null): Promise<string> {
  return chLimit(() => chFetchWithSlot(sql, params, settings, format));
}

async function chFetchWithSlot(sql: string, params: Record<string, string | number>, settings: ChSettings, format: string | null): Promise<string> {
  let url = new URL(CH_URL);
  // null убирает настройку совсем, в том числе заданную в самом CLICKHOUSE_URL.
  for (const [key, value] of Object.entries({ ...DEFAULT_SETTINGS, ...settings })) {
    if (value === null) url.searchParams.delete(key);
    else url.searchParams.set(key, String(value));
  }
  url.searchParams.set("database", CH_DB);
  if (format) url.searchParams.set("default_format", format);
  // Ответ буферизуется на сервере до конца запроса: ошибка посреди выдачи приходит HTTP-
  // ошибкой с X-ClickHouse-Exception-Code, а не строкой в конце тела со статусом 200.
  url.searchParams.set("wait_end_of_query", "1");
  const types = paramTypes(sql);
  const encoded = Object.entries(params).map(([key, value]) => [`param_${key}`, encodeParam(value, types.get(key))] as const);
  // Параметры — в URL, пока он короткий; большие (массивы значений сотен персон) — телом
  // multipart/form-data вместе с запросом: URI ClickHouse не длиннее 1 MiB
  // (http_max_uri_size), и запрос с тысячей персон иначе получил бы HTTP 414. Только для
  // чтения: у INSERT в теле — данные. У каждого поля формы предел FORM_FIELD_MAX: в
  // multipart — сырое значение (и запрос — тоже поле), в URL — percent-encoded строка, до
  // декодирования (HTMLForm::readQuery). Поэтому вариант с URL проверяется по URL,
  // собранному тем же URLSearchParams, а не по оценке: «~» там уже %7E.
  let body: string = sql;
  let contentType = "text/plain";
  const isInsert = /^\s*INSERT\b/i.test(sql);
  const withParams = new URL(url);
  for (const [key, value] of encoded) withParams.searchParams.set(key, value);
  const fitsUrl = urlFits(withParams);
  // В multipart уходят только query и param_*: настройки и поля CLICKHOUSE_URL остаются в
  // URL, и он сам должен помещаться (log_comment из 15 000 иероглифов — 135 КБ в URL).
  const fitsForm = urlFits(url) && Buffer.byteLength(sql, "utf8") <= FORM_FIELD_MAX
    && encoded.every(([, v]) => Buffer.byteLength(v, "utf8") <= FORM_FIELD_MAX);
  const short = Buffer.byteLength(withParams.search, "utf8") - Buffer.byteLength(url.search, "utf8") <= PARAMS_IN_URL_MAX;
  // INSERT: данные в теле, параметры — всегда в URL, и он проверяется так же.
  const transport = isInsert ? (fitsUrl ? "url" : null)
    : short && fitsUrl ? "url" : fitsForm ? "form" : fitsUrl ? "url" : null;
  if (transport === null) {
    // Ни так, ни так ClickHouse запрос не примет (414 или «Field value too long») — ошибка
    // здесь, с размерами, а не непонятный ответ сервера. В журнал — только размеры и SQL без данных.
    const message = `запрос не помещается в HTTP ClickHouse: SQL ${Buffer.byteLength(sql, "utf8")} байт, параметров ${encoded.length}, URL ${Buffer.byteLength(withParams.pathname + withParams.search, "utf8")} байт`;
    console.error(`clickhouse: ${message}`, "\nSQL:", sqlForLog(sql));
    throw new ClickHouseError(message, null, null);
  }
  if (transport === "form") {
    const boundary = multipartBoundary([sql, ...encoded.map(([, v]) => v)]);
    contentType = `multipart/form-data; boundary=${boundary}`;
    body = [["query", sql] as const, ...encoded].map(([name, value]) =>
      `--${boundary}\r\nContent-Disposition: form-data; name="${name}"\r\n\r\n${value}\r\n`).join("") + `--${boundary}--\r\n`;
  } else {
    url = withParams;
  }
  let resp: Response;
  try {
    resp = await fetch(url, {
      method: "POST",
      headers: {
        Authorization: "Basic " + Buffer.from(`${CH_USER}:${CH_PASSWORD}`).toString("base64"),
        "Content-Type": contentType,
      },
      body,
      cache: "no-store",
      signal: AbortSignal.timeout(CH_TIMEOUT_MS),
    });
  } catch (e) {
    console.error("clickhouse:", e instanceof Error ? `${e.name}: ${e.message}` : e);
    throw connectionError(e);
  }
  let text: string;
  try {
    text = await resp.text();
  } catch (e) {
    console.error("clickhouse response:", e);
    throw connectionError(e);
  }
  // ClickHouse may append an exception after sending HTTP 200. JSONEachRow
  // escapes newlines within values: only a standalone exception line counts.
  // Ошибка — только по HTTP-статусу и заголовку (wait_end_of_query=1, см. выше).
  const headerCode = headerChCode(resp.headers.get("X-ClickHouse-Exception-Code"));
  if (!resp.ok || headerCode != null) {
    // Ни тело ответа, ни текст исключения в журнал не идут (строки результата и
    // цитаты данных) — только код, имя, статус, query_id и SQL без данных.
    const { message, code } = shortChError(resp.ok ? "" : text, resp.status, headerCode);
    const queryId = resp.headers.get("X-ClickHouse-Query-Id") ?? "";
    console.error(`clickhouse ${resp.status}: ${message}${queryId ? ` query_id=${queryId}` : ""}`, "\nSQL:", sqlForLog(sql));
    throw new ClickHouseError(message, resp.status, code);
  }
  return text;
}

/** SQL для журнала. INSERT несёт данные в теле (FORMAT JSONEachRow, VALUES, SELECT с
 *  литералами) — в лог идёт только заголовок «INSERT INTO таблица (колонки)». В прочих
 *  запросах строковые литералы заменяются на «…»; значения параметров идут в URL и сюда
 *  не попадают. */
export function sqlForLog(sql: string): string {
  const insert = /^\s*INSERT\b/i.test(sql) ? /\b(FORMAT|VALUES|SELECT|WITH)\b|\/\*|--/i.exec(sql) : null;
  const head = insert ? `${sql.slice(0, insert.index).trimEnd()} <данные не логируются>` : maskSqlLiterals(sql);
  return head.slice(0, 500);
}

/** settings — серверные настройки ClickHouse на запрос (max_execution_time и т.п.). */
export async function chQuery<T>(sql: string, params: Record<string, string | number> = {}, settings: ChSettings = {}): Promise<T[]> {
  const text = await chFetch(sql, params, settings, "JSONEachRow");
  try {
    return text
      .split("\n")
      .filter(Boolean)
      .map((line) => JSON.parse(line) as T);
  } catch (e) {
    // SyntaxError JSON.parse цитирует фрагмент входа (данные) в message и stack.
    if (e instanceof SyntaxError) {
      console.error("clickhouse: ответ не JSONEachRow", "\nSQL:", sqlForLog(sql));
      throw new ClickHouseError("ответ ClickHouse не JSON");
    }
    throw e;
  }
}

/** Запрос без результата (INSERT/DDL); параметры — тем же server-side binding. */
export async function chCommand(sql: string, params: Record<string, string | number> = {}, settings: ChSettings = {}): Promise<void> {
  await chFetch(sql, params, settings, null);
}

export type SafeResult<T> = { ok: true; data: T; error: null } | { ok: false; data: null; error: string };

/**
 * Страница не должна падать целиком из-за хранилища: `{data, error}` вместо
 * исключения. Ошибка — короткая причина для панели «Хранилище недоступно».
 */
export async function safeQuery<T>(fn: () => Promise<T>): Promise<SafeResult<T>> {
  try {
    return { ok: true, data: await fn(), error: null };
  } catch (e) {
    if (e instanceof ClickHouseError) return { ok: false, data: null, error: e.message };
    // Ошибки навигации Next (redirect/notFound) должны пройти сквозь обёртку.
    if (e && typeof e === "object" && "digest" in e && typeof (e as { digest?: unknown }).digest === "string") throw e;
    console.error("safeQuery:", e);
    return { ok: false, data: null, error: "запрос к хранилищу не выполнен" };
  }
}

/* ===== Состояние служб для LED в шапке ===== */

export type ServiceState = { ok: boolean; detail: string; checkedAt: number };
const PING_TTL_MS = 10_000;
const PING_TIMEOUT_MS = 2_000;
const pingCache = new Map<string, Promise<ServiceState>>();

/** Кэш promise на 10 с: параллельные рендеры делят одну проверку. */
function pinged(key: string, make: () => Promise<ServiceState>): Promise<ServiceState> {
  const cur = pingCache.get(key);
  if (cur) {
    return cur.then((s) => {
      if (Date.now() - s.checkedAt < PING_TTL_MS) return s;
      const next = make();
      pingCache.set(key, next);
      return next;
    });
  }
  const p = make();
  pingCache.set(key, p);
  return p;
}

function pingFail(prefix: string, e: unknown): ServiceState {
  const timeout = e instanceof Error && (e.name === "TimeoutError" || e.name === "AbortError");
  return { ok: false, detail: `${prefix}: ${timeout ? "нет ответа за 2 с" : "нет соединения"}`, checkedAt: Date.now() };
}

/** SELECT 1 с таймаутом 2 с — дёшево для каждого рендера layout. */
export function clickhouseState(): Promise<ServiceState> {
  return pinged("clickhouse", async () => {
    const started = Date.now();
    try {
      const url = new URL(CH_URL);
      url.searchParams.set("query", "SELECT 1");
      url.searchParams.set("wait_end_of_query", "1");
      const resp = await fetch(url, {
        headers: { Authorization: "Basic " + Buffer.from(`${CH_USER}:${CH_PASSWORD}`).toString("base64") },
        cache: "no-store",
        signal: AbortSignal.timeout(PING_TIMEOUT_MS),
      });
      await resp.body?.cancel();
      // Исправность — статус 2xx и нет кода исключения в заголовке (как в chFetch).
      const code = headerChCode(resp.headers.get("X-ClickHouse-Exception-Code"));
      const ok = resp.ok && code == null;
      return { ok, detail: ok ? `ClickHouse отвечает · ${Date.now() - started} мс` : `ClickHouse: ${shortChError("", resp.status, code).message}`, checkedAt: Date.now() };
    } catch (e) {
      return pingFail("ClickHouse", e);
    }
  });
}

/** /healthz движка корреляции — тем же образом. */
export function engineState(): Promise<ServiceState> {
  const base = (process.env.ENGINE_URL ?? "http://localhost:8090").replace(/\/$/, "");
  return pinged("engine", async () => {
    const started = Date.now();
    try {
      const resp = await fetch(`${base}/healthz`, { cache: "no-store", signal: AbortSignal.timeout(PING_TIMEOUT_MS) });
      return { ok: resp.ok, detail: resp.ok ? `движок отвечает · ${Date.now() - started} мс` : `движок: HTTP ${resp.status}`, checkedAt: Date.now() };
    } catch (e) {
      return pingFail("движок", e);
    }
  });
}

export { RANGES, parseRange, type RangeKey } from "./shared/ranges";
