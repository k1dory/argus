import { apiGuard, outOfScope } from "@/lib/auth";
import { parseTimeFilter } from "@/lib/shared/filters";
import { clampInt } from "@/lib/shared/limits";
import { checkTriageSearch, stripHidden } from "@/lib/shared/triage";
import { clampPage, MAX_QUERY_LEN, PAGE_SIZE, parseIndex, search, searchExport, toCsv } from "@/lib/search";
import { wazuhEnabled } from "@/lib/integrations";
import { parseSearchLevel } from "@/lib/shared/page-filters";

// GET /api/search?index=alerts|events&q=...&range=24h (period= — синоним)[&from=&to=][&level_min=&level_max=][&page=N][&format=json|csv|export][&limit=N][&raw=0]
// format=json (по умолчанию): страница результатов + гистограмма + фасеты, как в консоли.
// format=export / csv: до 10 000 строк для отчёта (лимит 5 запросов в минуту).
// Доступ: сессия консоли или bearer ARGUS_API_TOKEN; 60 запросов в минуту.
export async function GET(req: Request): Promise<Response> {
  const u = new URL(req.url);
  const g = (k: string) => u.searchParams.get(k) ?? undefined;
  const format = g("format") ?? "json";
  const isExport = format === "csv" || format === "export";
  const guard = await apiGuard(req, isExport ? "export" : "default", { triage: true });
  if (guard.response) return guard.response;
  // Индекс alerts существует только с модулем Wazuh (ARGUS_INTEGRATION_WAZUH).
  if (g("index") === "alerts" && !wazuhEnabled()) return Response.json({ error: "index=alerts недоступен: модуль Wazuh выключен" }, { status: 400 });
  const index = parseIndex(g("index"));
  const level = parseSearchLevel(u.searchParams, index);
  // Окно — тем же парсером, что страница: period — синоним range, несуществующие даты
  // отброшены, границы по порядку, ширина не больше 400 дней, один to — сутки (пресет) до него.
  const time = parseTimeFilter(u.searchParams, { defaultRange: "24h" });
  const input = {
    index,
    q: (g("q") ?? "").slice(0, MAX_QUERY_LEN),
    range: time.range ?? "24h",
    from: time.from,
    to: time.to,
    page: clampPage(g("page")),
    showMuted: g("muted") === "1",
    levelMin: level.min,
    levelMax: level.max,
  };
  // Токен triage-session: только точные фильтры, хотя бы одна сущность
  // своего инцидента, окно не раньше first_ts − 30 дней, до 200 строк, без
  // выгрузки (её отсекает apiGuard) и без исходного JSON.
  const scope = guard.session.triage;
  if (scope) {
    if (u.searchParams.has("include_raw") || u.searchParams.has("raw")) return outOfScope("исходный JSON недоступен");
    const check = checkTriageSearch(scope, { ...input, pageSize: PAGE_SIZE });
    if (!check.ok) {
      return check.status === 403 ? outOfScope(check.detail) : Response.json({ error: check.error, detail: check.detail }, { status: 400 });
    }
    // Фасеты не отдаём: они считаются по всему совпавшему
    // набору, а не по выданным строкам, и показывали бы топ чужих субъектов.
    // bind — обязательная привязка строк к субъекту и узлам инцидента:
    // изоляцию даёт она, проверка якорей и порог только сужают запрос.
    const res = await search({ ...input, from: check.from, to: check.to, showMuted: false, facets: false, bind: scope.bind });
    return Response.json({ ...res, rows: stripHidden(res.rows), facets: [] }, { status: res.error ? 400 : 200 });
  }
  if (isExport) {
    const limit = clampInt(g("limit"), 1, 10000, 10000);
    const { rows, error } = await searchExport(input, limit, g("raw") !== "0"); // raw=0 — без исходного JSON (MCP)
    if (error) return Response.json({ error }, { status: 400 });
    // Имя файла с датой и временем выгрузки — две выгрузки за день не перетирают друг друга.
    const name = `argus-${input.index}-${new Date().toISOString().slice(0, 16).replace(/[:T]/g, "-")}`;
    if (format === "csv") {
      // toCsv добавляет BOM — Excel открывает кириллицу без диалога импорта.
      return new Response(toCsv(rows), { headers: { "Content-Type": "text/csv; charset=utf-8", "Content-Disposition": `attachment; filename="${name}.csv"` } });
    }
    return Response.json({ query: input, rows, exported_at: new Date().toISOString() }, { headers: { "Content-Disposition": `attachment; filename="${name}.json"` } });
  }
  const res = await search(input);
  return Response.json(res, { status: res.error ? 400 : 200 });
}
