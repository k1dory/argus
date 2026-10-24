import { apiGuard, outOfScope } from "@/lib/auth";
import { chQuery } from "@/lib/argus-queries-export";
import { SEARCH_SETTINGS } from "@/lib/search";
import { checkTriageSearch, TRIAGE_MAX_ROWS } from "@/lib/shared/triage";
import { buildLogSql, logScopeQuery, parseLogParams, toLogItem } from "@/lib/shared/log-query";

// GET /api/v1/log — простой журнал событий единой схемы (argus.events) для агентов.
// Параметры: log (source или source_class: ci, k8s, telemetry …), level
// (минимальный: info|low|medium|high|critical → severity ≥ 0|3|5|7|9), actor,
// node, src_ip, action (точные значения), since (длительность 15m/24h/7d, по
// умолчанию 24h, не больше 30d), until (RFC 3339), q (подстрока по object и raw),
// limit (1…1000, по умолчанию 200), format=json|ndjson.
// Ответ: {"items": [{ts, source, source_class, action, outcome, severity, level,
// actor_name, actor_kind, object, node, session_id, src_ip, dst_ip, value, unit,
// attrs}], "count": n}; ndjson — по строке на событие. raw не отдаётся.
// Доступ: сессия консоли или bearer ARGUS_API_TOKEN — без ограничений; токен
// triage-session — только в своей области, как /api/search: нужна хотя бы одна
// сущность инцидента (actor, node, src_ip), окно не раньше first_ts − 30 дней,
// до 200 строк, без свободного текста q, строки привязаны к субъекту и узлам.
export async function GET(req: Request): Promise<Response> {
  const guard = await apiGuard(req, "default", { triage: true });
  if (guard.response) return guard.response;
  const parsed = parseLogParams(new URL(req.url).searchParams);
  if (!parsed.ok) return Response.json({ error: "invalid_value", detail: parsed.error }, { status: 400 });
  const p = parsed.params;
  let window: { fromMs: number; toMs?: number } = { fromMs: p.fromMs, toMs: p.toMs };
  const scope = guard.session.triage;
  if (scope) {
    if (p.q) return Response.json({ error: "invalid_value", detail: "свободный текст q недоступен сессии разбора — только поля" }, { status: 400 });
    p.limit = Math.min(p.limit, TRIAGE_MAX_ROWS);
    const toMinute = (ms: number) => new Date(ms).toISOString().slice(0, 16);
    const check = checkTriageSearch(scope, { index: "events", q: logScopeQuery(p), range: "24h", from: toMinute(p.fromMs), to: toMinute(p.toMs ?? Date.now()), page: 1, pageSize: p.limit });
    if (!check.ok) return check.status === 403 ? outOfScope(check.detail) : Response.json({ error: check.error, detail: check.detail }, { status: 400 });
    window = { fromMs: Date.parse(check.from + ":00Z"), toMs: check.to ? Date.parse(check.to + ":00Z") : undefined };
  }
  const { sql, params } = buildLogSql(p, window, scope?.bind);
  try {
    const rows = await chQuery<Record<string, unknown>>(sql, params, SEARCH_SETTINGS);
    const items = rows.map(toLogItem);
    if (p.format === "ndjson") {
      return new Response(items.map((i) => JSON.stringify(i)).join("\n") + (items.length ? "\n" : ""), { headers: { "Content-Type": "application/x-ndjson; charset=utf-8", "Cache-Control": "no-store" } });
    }
    return Response.json({ items, count: items.length }, { headers: { "Cache-Control": "no-store" } });
  } catch (err) {
    console.error("api/v1/log:", err instanceof Error ? err.message : err);
    return Response.json({ error: "хранилище недоступно или запрос отклонён" }, { status: 503 });
  }
}
