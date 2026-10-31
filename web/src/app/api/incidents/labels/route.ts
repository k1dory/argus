import { apiGuard } from "@/lib/auth";
import { incidentLabels } from "@/lib/argus-queries";

const DATE_RE = /^\d{4}-\d{2}-\d{2}(T\d{2}:\d{2}(:\d{2})?Z?)?$/;
const MAX_LIMIT = 50_000;

// GET /api/incidents/labels?since=2026-11-01&limit=10000 — ответы людей при
// завершении инцидентов: вердикт (или причина и действие DevOps), эскалация,
// верность уровня, признак слепого разбора. Автозакрытия не выдаются. Выгрузка —
// лимит export, сессии разбора закрыта.
export async function GET(req: Request): Promise<Response> {
  const guard = await apiGuard(req, "export");
  if (guard.response) return guard.response;
  const url = new URL(req.url);
  const since = url.searchParams.get("since") ?? "1970-01-01";
  const limitRaw = url.searchParams.get("limit") ?? "10000";
  const limit = Number(limitRaw);
  if (!DATE_RE.test(since) || !/^\d+$/.test(limitRaw) || limit < 1 || limit > MAX_LIMIT) {
    return Response.json({ error: `since — дата ISO 8601 (UTC), limit — 1..${MAX_LIMIT}` }, { status: 400 });
  }
  try {
    const labels = await incidentLabels(since, limit);
    return Response.json({ labels, truncated: labels.length === limit, exported_at: new Date().toISOString() });
  } catch (err) {
    console.error("api/incidents/labels:", err instanceof Error ? err.message : err);
    return Response.json({ error: "хранилище недоступно" }, { status: 503 });
  }
}
