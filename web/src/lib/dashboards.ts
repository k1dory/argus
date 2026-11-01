// Конструктор дашбордов «как в Grafana»: панели с SQL к ClickHouse, макросы
// времени, сетка 24 колонки. Запросы панелей выполняются от read-only
// пользователя argus_ro: readonly=1 и лимиты заданы в его профиле, — оператор
// пишет любой SELECT, но ничего кроме SELECT выполнить не может.
import "server-only";
import { promises as fs } from "fs";
import path from "path";
import { chCommand, chExceptionIndex, chQuery, createLimiter, headerChCode, LimiterWaitError, shortChError } from "./clickhouse";
import { RANGES, type RangeKey } from "./shared/ranges";
import { normalizeSpec, refreshSeconds, SPEC_LIMITS, SpecError, type DashboardSpec, type Panel, type PanelType } from "./shared/dashboard-spec";
import { wazuhEnabled } from "./integrations";

export { normalizeSpec, refreshSeconds, SpecError, type DashboardSpec, type Panel, type PanelType };

export type DashboardRow = {
  id: string;
  title: string;
  updated_at: string;
  updated_by: string;
  provisioned: number;
  spec: string;
};

const CH_URL = process.env.CLICKHOUSE_URL ?? "http://localhost:8123";
const CH_DB = process.env.CLICKHOUSE_DB ?? "argus";
// Запросы панелей — ТОЛЬКО от read-only пользователя: без него панели не
// выполняются (fail-closed), чтобы SELECT аналитика не шёл под админом.
const RO_USER = process.env.CLICKHOUSE_RO_USER ?? "";
const RO_PASSWORD = process.env.CLICKHOUSE_RO_PASSWORD ?? "";
const DASHBOARDS_DIR = path.resolve(/*turbopackIgnore: true*/ process.env.DASHBOARDS_DIR ?? "../dashboards");
const PANEL_TIMEOUT_MS = 25_000;
/** То же, что max_result_rows в профиле argus_ro. */
const PANEL_MAX_ROWS = 5000;
// У argus_ro max_concurrent_queries_for_user = 4, а дашборд рисует все панели
// разом: без очереди лишние получают «Too many simultaneous queries» (код 202).
// Очередь — на процесс консоли (несколько экземпляров делят лимит ClickHouse),
// с запасом в один слот: ClickHouse освобождает слот чуть позже, чем клиент
// получает ответ. Ждать слот дольше PANEL_QUEUE_WAIT_MS панель не будет.
const PANEL_MAX_INFLIGHT = 3;
const PANEL_QUEUE_WAIT_MS = 20_000;
const panelLimit = createLimiter(PANEL_MAX_INFLIGHT);

const ID_RE = /^[a-z0-9][a-z0-9-]{1,63}$/;
// DDL/DML и табличные функции с доступом наружу (url/remote/s3/file…) — второй
// рубеж: на ClickHouse 24.8 readonly=1 сам запрещает и запись, и табличные
// функции. Имя функции или базы может стоять в кавычках: `url`(, "system".
const FORBIDDEN = /\b(insert|alter|drop|create|truncate|rename|grant|revoke|kill|attach|detach|optimize|exchange)\b|[`"]?\b(url|remote|remoteSecure|s3|file|hdfs|mysql|postgresql|jdbc|odbc|executable|input|cluster|clusterAllReplicas)\b[`"]?\s*\(|[`"]?\bsystem\b[`"]?\s*\./i;

// Heredoc-строка ClickHouse: $$…$$ или $tag$…$tag$. Макросы $__from, $__timeFilter( не подходят.
const HEREDOC_RE = /^\$([A-Za-z_][A-Za-z0-9_]*)?\$/;
// Типографские кавычки ClickHouse тоже считает кавычками строк и имён.
const UNICODE_QUOTES = "\u2018\u2019\u201C\u201D";

export type SqlScan =
  | { ok: true; code: string; noComments: string }
  | { ok: false; error: string };

/**
 * Разбор запроса на литералы и комментарии — для поиска «;»:
 * `arrayStringConcat(x, '; ')` — один запрос, а не два.
 * code — без строк, имён в кавычках и комментариев; noComments — без
 * комментариев, строки на месте (для FORBIDDEN: `url/ * * /(` не проходит).
 * Экранирование как в ClickHouse: `\'` и удвоенная кавычка. Чего разбор не
 * понимает наверняка (heredoc, типографские кавычки, `#` без пробела), то он
 * отклоняет: ошибка разбора не должна прятать от проверки кусок запроса.
 */
export function scanSql(sql: string): SqlScan {
  let code = "";
  let noComments = "";
  let i = 0;
  while (i < sql.length) {
    const c = sql[i];
    if (c === "'" || c === '"' || c === "`") {
      let j = i + 1;
      while (j < sql.length) {
        if (sql[j] === "\\") j += 2;
        else if (sql[j] === c && sql[j + 1] === c) j += 2;
        else if (sql[j] === c) break;
        else j++;
      }
      if (j >= sql.length) return { ok: false, error: "Незакрытая кавычка или комментарий" };
      code += " ";
      noComments += sql.slice(i, j + 1);
      i = j + 1;
      continue;
    }
    let commentEnd = -1;
    if (c === "-" && sql[i + 1] === "-") {
      const nl = sql.indexOf("\n", i);
      commentEnd = nl < 0 ? sql.length : nl;
    } else if (c === "#") {
      if (sql[i + 1] !== " " && sql[i + 1] !== "!") return { ok: false, error: "Неподдерживаемый синтаксис: «#»" };
      const nl = sql.indexOf("\n", i);
      commentEnd = nl < 0 ? sql.length : nl;
    } else if (c === "/" && sql[i + 1] === "*") {
      // ClickHouse вкладывает /* */: считаем глубину, комментарий кончается на
      // «*/» нулевой глубины. Не закрытый — отказ.
      let depth = 1;
      let j = i + 2;
      while (j < sql.length && depth > 0) {
        if (sql[j] === "/" && sql[j + 1] === "*") { depth++; j += 2; }
        else if (sql[j] === "*" && sql[j + 1] === "/") { depth--; j += 2; }
        else j++;
      }
      if (depth > 0) return { ok: false, error: "Незакрытая кавычка или комментарий" };
      commentEnd = j;
    }
    if (commentEnd >= 0) {
      code += " ";
      noComments += " ";
      i = commentEnd;
      continue;
    }
    if (c === "$" && HEREDOC_RE.test(sql.slice(i))) return { ok: false, error: "Неподдерживаемый синтаксис: heredoc-строка $…$" };
    if (UNICODE_QUOTES.includes(c)) return { ok: false, error: "Неподдерживаемый синтаксис: типографские кавычки" };
    code += c;
    noComments += c;
    i++;
  }
  return { ok: true, code, noComments };
}

export function validateSql(sql: string): string | null {
  const s = sql.trim();
  if (!s) return "Пустой запрос";
  if (s.length > SPEC_LIMITS.maxSqlLen) return "Слишком длинный запрос";
  const scan = scanSql(s);
  if (!scan.ok) return scan.error;
  if (scan.code.includes(";")) return "Один запрос без «;»";
  if (!/^(select|with)\b/i.test(s)) return "Разрешены только SELECT / WITH";
  // По исходному тексту и по тексту без комментариев: `url/**/(` ловится вторым.
  if (FORBIDDEN.test(s) || FORBIDDEN.test(scan.noComments)) return "Запрос содержит запрещённое ключевое слово";
  return null;
}

/** Макросы как в Grafana: $__timeFilter(col), $__timeInterval(col), $__from, $__to, $__interval. */
export function expandMacros(sql: string, range: RangeKey): string {
  const { hours, bucketMinutes } = RANGES[range];
  const from = `now() - INTERVAL ${hours} HOUR`;
  return sql
    .replace(/\$__timeFilter\(\s*([A-Za-z0-9_.]+)\s*\)/g, (_m, col) => `(${col} >= ${from} AND ${col} <= now())`)
    .replace(/\$__timeInterval\(\s*([A-Za-z0-9_.]+)\s*\)/g, (_m, col) => `toStartOfInterval(${col}, INTERVAL ${bucketMinutes} MINUTE)`)
    .replace(/\$__from\b/g, from)
    .replace(/\$__to\b/g, "now()")
    .replace(/\$__interval\b/g, `INTERVAL ${bucketMinutes} MINUTE`);
}

/**
 * error — «код N (ИМЯ)» для всех; errorDetail — query_id запроса (полный текст ошибки
 * оператор смотрит в system.query_log), страница отдаёт его тем, кто правит дашборд.
 * Тело ответа ClickHouse не передаётся: текст исключения цитирует данные.
 */
/** truncated — ответ неполный: обрезан до PANEL_MAX_ROWS строк или оборван посреди JSON. */
export type PanelData = { columns: string[]; rows: Record<string, unknown>[]; error?: string; errorDetail?: string; ms: number; cached?: boolean; truncated?: boolean };

/** Кэш результата панели на интервал автообновления: ключ — sql+range, живёт в памяти процесса.
 *  Потолки: по числу записей, по суммарному размеру (оценка через JSON) и по
 *  строкам одного результата — таблица на 5 000 широких строк в кэш не идёт. */
const panelCache = new Map<string, { at: number; bytes: number; data: PanelData }>();
const PANEL_CACHE_MAX = 500;
const PANEL_CACHE_MAX_BYTES = 64 * 1024 * 1024;
const PANEL_CACHE_MAX_ROWS = 2000;
let panelCacheBytes = 0;

function panelCacheDelete(key: string): void {
  const e = panelCache.get(key);
  if (!e) return;
  panelCacheBytes -= e.bytes;
  panelCache.delete(key);
}

/** Положить в кэш, если результат не слишком большой; вытесняет самые старые записи. */
export function panelCachePut(key: string, data: PanelData, now = Date.now()): boolean {
  if (data.rows.length > PANEL_CACHE_MAX_ROWS) return false;
  const bytes = JSON.stringify(data).length;
  if (bytes > PANEL_CACHE_MAX_BYTES) return false;
  panelCacheDelete(key);
  for (const oldest of panelCache.keys()) {
    if (panelCache.size < PANEL_CACHE_MAX && panelCacheBytes + bytes <= PANEL_CACHE_MAX_BYTES) break;
    panelCacheDelete(oldest); // Map хранит порядок вставки: первые — самые старые
  }
  panelCache.set(key, { at: now, bytes, data });
  panelCacheBytes += bytes;
  return true;
}

export function panelCacheGet(key: string, ttlMs: number, now = Date.now()): PanelData | null {
  const hit = panelCache.get(key);
  return hit && now - hit.at < ttlMs ? hit.data : null;
}

/** Состояние кэша (для тестов и диагностики). */
export function panelCacheStats(): { entries: number; bytes: number } {
  return { entries: panelCache.size, bytes: panelCacheBytes };
}

export function stripPanelDetail(d: PanelData): PanelData {
  if (!d.errorDetail) return d;
  const { errorDetail: _omit, ...rest } = d;
  void _omit;
  return rest;
}

async function executePanel(sql: string, range: RangeKey, signal?: AbortSignal): Promise<PanelData> {
  const err = validateSql(sql);
  if (err) return { columns: [], rows: [], error: err, ms: 0 };
  if (!RO_USER || !RO_PASSWORD) {
    return { columns: [], rows: [], error: "read-only пользователь не настроен (CLICKHOUSE_RO_USER/CLICKHOUSE_RO_PASSWORD)", ms: 0 };
  }
  const url = new URL(CH_URL);
  url.searchParams.set("database", CH_DB);
  url.searchParams.set("default_format", "JSONEachRow");
  // Настроек в запросе нет: при readonly=1 ClickHouse отклоняет любую, что
  // расходится с профилем. Лимиты, break и формат JSON — в профиле argus_ro
  // (scripts/migrate.sh).
  const started = Date.now();
  const timeout = AbortSignal.timeout(PANEL_TIMEOUT_MS);
  try {
    const resp = await fetch(url, {
      method: "POST",
      headers: { Authorization: "Basic " + Buffer.from(`${RO_USER}:${RO_PASSWORD}`).toString("base64"), "Content-Type": "text/plain" },
      body: expandMacros(sql, range),
      cache: "no-store",
      signal: signal ? AbortSignal.any([timeout, signal]) : timeout,
    });
    const text = await resp.text();
    const at = chExceptionIndex(text);
    const headerCode = headerChCode(resp.headers.get("X-ClickHouse-Exception-Code"));
    if (!resp.ok || at >= 0 || headerCode != null) {
      const { message } = shortChError(at >= 0 ? text.slice(at) : resp.ok ? "" : text, resp.status, headerCode);
      const queryId = resp.headers.get("X-ClickHouse-Query-Id") ?? "";
      console.error(`panel query ${resp.status}: ${message}${queryId ? ` query_id=${queryId}` : ""}`);
      return { columns: [], rows: [], error: message, ...(queryId ? { errorDetail: `query_id: ${queryId}` } : {}), ms: Date.now() - started };
    }
    // result_overflow_mode=break режет по блокам, строк бывает больше лимита.
    const lines = text.split("\n").filter(Boolean);
    const rows = lines.slice(0, PANEL_MAX_ROWS).map((l) => JSON.parse(l) as Record<string, unknown>);
    const columns = rows.length ? Object.keys(rows[0]) : [];
    return { columns, rows, ms: Date.now() - started, ...(lines.length > PANEL_MAX_ROWS ? { truncated: true } : {}) };
  } catch (e) {
    if (e instanceof SyntaxError) {
      // e.message цитирует фрагмент ответа (данные, например FORMAT TabSeparated).
      console.error("panel query: ответ не JSONEachRow (оборван или задан другой FORMAT)");
      return { columns: [], rows: [], error: "ответ ClickHouse не JSON (оборван или задан другой FORMAT)", truncated: true, ms: Date.now() - started };
    }
    const name = e instanceof Error ? e.name : "";
    console.error("panel query:", e instanceof Error ? `${e.name}: ${e.message}` : e);
    const error = timeout.aborted || name === "TimeoutError" ? `запрос не уложился в ${PANEL_TIMEOUT_MS / 1000} с`
      : name === "AbortError" ? "запрос отменён" : "хранилище недоступно";
    return { columns: [], rows: [], error, ms: Date.now() - started };
  }
}

/**
 * ttlMs — на сколько кэшировать результат (обычно интервал refresh дашборда);
 * 0 — без кэша (предпросмотр в редакторе).
 */
export async function runPanelQuery(sql: string, range: RangeKey, ttlMs = 0, signal?: AbortSignal): Promise<PanelData> {
  const key = `${range} ${sql}`;
  if (ttlMs > 0) {
    const hit = panelCacheGet(key, ttlMs);
    if (hit) return { ...hit, cached: true };
  }
  let data: PanelData;
  const queued = Date.now();
  try {
    data = await panelLimit(() => executePanel(sql, range, signal), { signal, maxWaitMs: PANEL_QUEUE_WAIT_MS });
  } catch (e) {
    if (!(e instanceof LimiterWaitError)) throw e;
    const error = e.reason === "timeout" ? `очередь панелей занята дольше ${PANEL_QUEUE_WAIT_MS / 1000} с` : "запрос отменён";
    return { columns: [], rows: [], error, ms: Date.now() - queued };
  }
  if (ttlMs > 0 && !data.error) panelCachePut(key, data);
  return data;
}

/* ===== CRUD ===== */

const LATEST = `SELECT id, argMax(title, updated_at) AS title, max(updated_at) AS updated_max,
  argMax(updated_by, updated_at) AS updated_by, argMax(provisioned, updated_at) AS provisioned,
  argMax(spec, updated_at) AS spec, argMax(deleted, updated_at) AS deleted FROM console_dashboards`;

export async function listDashboards(): Promise<DashboardRow[]> {
  await seedProvisioned();
  const rows = await chQuery<DashboardRow & { updated_max: string; deleted: number }>(
    `${LATEST} GROUP BY id HAVING deleted = 0 ORDER BY provisioned DESC, title LIMIT 500`,
  );
  return rows.map((r) => ({ ...r, updated_at: r.updated_max, provisioned: Number(r.provisioned) }));
}

export async function getDashboard(id: string): Promise<DashboardSpec | null> {
  if (!ID_RE.test(id)) return null;
  await seedProvisioned();
  const rows = await chQuery<{ spec: string; deleted: number }>(`${LATEST} WHERE id = {id:String} GROUP BY id HAVING deleted = 0`, { id });
  if (!rows[0]) return null;
  try {
    return normalizeSpec(JSON.parse(rows[0].spec), id);
  } catch (e) {
    console.error("dashboard spec:", id, e instanceof Error ? e.message : e);
    return null;
  }
}

export async function saveDashboard(spec: DashboardSpec, by: string, provisioned = 0): Promise<string | null> {
  if (!ID_RE.test(spec.id)) return "Идентификатор: латиница, цифры, дефис (2–64)";
  let normalized: DashboardSpec;
  try {
    normalized = normalizeSpec(spec, spec.id);
  } catch (e) {
    return e instanceof SpecError ? e.message : "Спецификация не прошла проверку";
  }
  for (const p of normalized.panels) {
    const err = validateSql(p.sql);
    if (err) return `Панель «${p.title || p.id}»: ${err}`;
  }
  const json = JSON.stringify(normalized);
  if (json.length > SPEC_LIMITS.maxJsonBytes) return `Спецификация больше ${Math.round(SPEC_LIMITS.maxJsonBytes / 1024)} КБ`;
  await chCommand(
    `INSERT INTO console_dashboards (id, title, spec, updated_by, provisioned, deleted)
     SELECT {id:String}, {title:String}, {spec:String}, {by:String}, {prov:UInt8}, 0`,
    { id: normalized.id, title: normalized.title, spec: json, by, prov: provisioned },
  );
  return null;
}

export async function deleteDashboard(id: string, by: string): Promise<void> {
  if (!ID_RE.test(id)) return;
  await chCommand(
    `INSERT INTO console_dashboards (id, title, spec, updated_by, provisioned, deleted)
     SELECT id, title, spec, {by:String}, provisioned, 1 FROM (${LATEST} WHERE id = {id:String} GROUP BY id)`,
    { id, by },
  );
}

// Провижининг как в Grafana: JSON из dashboards/ попадает в таблицу, если
// его там ещё нет или файл новее записи (по mtime). Дашборды модуля Wazuh
// (wazuh-*.json) — только при включённом модуле.

/** Файлы dashboards/, которые провижинятся в этой установке. */
export function provisionableFiles(files: string[], wazuh = wazuhEnabled()): string[] {
  return files.filter((f) => f.endsWith(".json") && (wazuh || !f.startsWith("wazuh-")));
}
let seedPromise: Promise<void> | null = null;
export function seedProvisioned(): Promise<void> {
  // Кэшируем promise, а не флаг: параллельные первые запросы ждут одного
  // прогона, а неудача не выключает провижининг до рестарта.
  seedPromise ??= doSeed().catch((e) => {
    seedPromise = null;
    throw e;
  });
  return seedPromise;
}

async function doSeed(): Promise<void> {
  let files: string[] = [];
  try {
    files = provisionableFiles(await fs.readdir(DASHBOARDS_DIR));
  } catch {
    return;
  }
  const existing = await chQuery<{ id: string; updated_max: string; provisioned: number }>(
    `SELECT id, max(updated_at) AS updated_max, argMax(provisioned, updated_at) AS provisioned FROM console_dashboards GROUP BY id`,
  ); // ошибка чтения — исключение, а не «пусто» (иначе всё пересеется заново)
  const byId = new Map(existing.map((e) => [e.id, e]));
  for (const f of files) {
    try {
      const full = path.join(DASHBOARDS_DIR, f);
      const stat = await fs.stat(full);
      if (stat.size > SPEC_LIMITS.maxJsonBytes) throw new Error(`файл больше ${SPEC_LIMITS.maxJsonBytes} байт`);
      const spec = normalizeSpec(JSON.parse(await fs.readFile(full, "utf8")));
      const ex = byId.get(spec.id);
      const fileTime = stat.mtime.getTime();
      const rowTime = ex ? new Date(ex.updated_max.replace(" ", "T") + "Z").getTime() : 0;
      if (!ex || (Number(ex.provisioned) === 1 && fileTime > rowTime)) {
        const err = await saveDashboard(spec, "provisioning", 1);
        if (err) console.error("dashboards seed:", f, err);
      }
    } catch (e) {
      console.error("dashboards seed:", f, e instanceof Error ? e.message : e);
    }
  }
}
