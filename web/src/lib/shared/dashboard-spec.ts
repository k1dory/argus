// Спецификация дашборда: чистая нормализация без server-only, чтобы одна и та
// же функция проверяла JSON и в редакторе (клиент), и при сохранении (сервер).

export type PanelType = "timeseries" | "bar" | "stat" | "table";

export type Panel = {
  id: string;
  title: string;
  type: PanelType;
  sql: string;
  w: number; // 4..24
  h: number; // строки сетки по 40px, 3..24
  series?: string; // колонка, по которой раскладывать серии (timeseries)
  unit?: string;
};

export type DashboardSpec = {
  id: string;
  title: string;
  description?: string;
  refresh?: string;
  panels: Panel[];
};

export const SPEC_LIMITS = {
  maxPanels: 24,
  minRefreshSec: 10,
  maxRefreshSec: 9999,
  maxJsonBytes: 256 * 1024,
  maxSqlLen: 8000,
} as const;

export const PANEL_TYPES: PanelType[] = ["timeseries", "bar", "stat", "table"];
const PANEL_ID_RE = /^[A-Za-z0-9_-]{1,32}$/;

export class SpecError extends Error {}

function str(v: unknown, max: number): string {
  if (v == null) return "";
  return (typeof v === "string" ? v : String(v)).slice(0, max);
}

function num(v: unknown, min: number, max: number, dflt: number): number {
  const n = Number(v);
  if (v == null || v === "" || !Number.isFinite(n)) return dflt;
  return Math.min(max, Math.max(min, Math.round(n)));
}

/** Строгая нормализация: лишние поля отбрасываются, лимиты — ошибкой, а не молча. */
export function normalizeSpec(input: unknown, id?: string): DashboardSpec {
  if (!input || typeof input !== "object" || Array.isArray(input)) throw new SpecError("Спецификация должна быть JSON-объектом");
  const spec = input as Record<string, unknown>;
  const rawPanels = spec.panels ?? [];
  if (!Array.isArray(rawPanels)) throw new SpecError("Поле panels должно быть массивом");
  if (rawPanels.length > SPEC_LIMITS.maxPanels) throw new SpecError(`Не больше ${SPEC_LIMITS.maxPanels} панелей на дашборд`);
  const seen = new Set<string>();
  const panels: Panel[] = rawPanels.map((raw, i) => {
    const p = (raw && typeof raw === "object" && !Array.isArray(raw) ? raw : {}) as Record<string, unknown>;
    let pid = str(p.id, 32);
    if (!PANEL_ID_RE.test(pid) || seen.has(pid)) pid = `p${i + 1}`;
    while (seen.has(pid)) pid = `${pid}-${i + 1}`;
    seen.add(pid);
    const sql = str(p.sql, SPEC_LIMITS.maxSqlLen + 1);
    if (sql.length > SPEC_LIMITS.maxSqlLen) throw new SpecError(`Панель ${i + 1}: запрос длиннее ${SPEC_LIMITS.maxSqlLen} символов`);
    const type = PANEL_TYPES.includes(p.type as PanelType) ? (p.type as PanelType) : "table";
    const series = str(p.series, 64).trim();
    const unit = str(p.unit, 16).trim();
    return {
      id: pid,
      title: str(p.title, 120),
      type,
      sql,
      w: num(p.w, 4, 24, 12),
      h: num(p.h, 3, 24, 8),
      ...(series ? { series } : {}),
      ...(unit ? { unit } : {}),
    };
  });
  let refresh: string | undefined;
  const rawRefresh = spec.refresh == null ? "" : String(spec.refresh).trim();
  if (rawRefresh) {
    const m = /^(\d{1,4})s$/.exec(rawRefresh);
    if (!m) throw new SpecError("Автообновление: число секунд и «s», например 30s");
    const sec = Number(m[1]);
    if (sec < SPEC_LIMITS.minRefreshSec) throw new SpecError(`Автообновление не чаще ${SPEC_LIMITS.minRefreshSec}s`);
    refresh = `${sec}s`;
  }
  const title = str(spec.title, 120).trim() || "Без названия";
  const description = str(spec.description, 500).trim();
  return {
    id: id ?? str(spec.id, 64),
    title,
    ...(description ? { description } : {}),
    ...(refresh ? { refresh } : {}),
    panels,
  };
}

/** Секунды автообновления из spec.refresh (0 — выключено). */
export function refreshSeconds(spec: Pick<DashboardSpec, "refresh">): number {
  const m = /^(\d{1,4})s$/.exec(spec.refresh ?? "");
  return m ? Number(m[1]) : 0;
}

/** Импорт JSON из редактора: размер, разбор, нормализация — ошибка человеку, не исключение. */
export function parseDashboardJson(text: string, id?: string): { ok: true; spec: DashboardSpec; error: null } | { ok: false; spec: null; error: string } {
  const bytes = new TextEncoder().encode(text).length;
  if (bytes > SPEC_LIMITS.maxJsonBytes) return { ok: false, spec: null, error: `JSON больше ${Math.round(SPEC_LIMITS.maxJsonBytes / 1024)} КБ` };
  let parsed: unknown;
  try {
    parsed = JSON.parse(text);
  } catch (e) {
    return { ok: false, spec: null, error: `JSON не разбирается: ${e instanceof Error ? e.message.slice(0, 120) : "синтаксис"}` };
  }
  try {
    return { ok: true, spec: normalizeSpec(parsed, id), error: null };
  } catch (e) {
    return { ok: false, spec: null, error: e instanceof SpecError ? e.message : "Спецификация не прошла проверку" };
  }
}

/** Ширина панели в колонках сетки на средних экранах (lg…xl): узкие — половина, широкие — вся строка. */
export function panelSpanMedium(w: number): number {
  return w < 12 ? 12 : 24;
}
