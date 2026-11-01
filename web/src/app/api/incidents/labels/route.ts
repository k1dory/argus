import { apiGuard } from "@/lib/auth";
import { incidentLabels } from "@/lib/argus-queries";
import { decodeLabelCursor, encodeLabelCursor } from "@/lib/label-cursor";

// Дата или дата-время ISO 8601 в UTC: секунды и доли (до наносекунд) необязательны,
// суффикс Z — тоже (время и так UTC). Смещения не принимаются.
const SINCE_RE = /^(\d{4})-(\d{2})-(\d{2})(?:T(\d{2}):(\d{2})(?::(\d{2})(?:\.\d{1,9})?)?Z?)?$/;
const MAX_LIMIT = 50_000;

/** Регулярка пропускает 2026-99-99 и 25:00 — проверяем, что такая дата существует. */
function validSince(since: string): boolean {
  const m = SINCE_RE.exec(since);
  if (!m) return false;
  const [y, mo, d, h = "0", mi = "0", s = "0"] = m.slice(1).map((v) => v ?? undefined);
  const t = new Date(Date.UTC(+y, +mo - 1, +d, +h, +mi, +s));
  return t.getUTCFullYear() === +y && t.getUTCMonth() === +mo - 1 && t.getUTCDate() === +d
    && t.getUTCHours() === +h && t.getUTCMinutes() === +mi && t.getUTCSeconds() === +s;
}

// GET /api/incidents/labels?since=2026-11-01&limit=10000 — ответы людей при
// завершении инцидентов: вердикт (или причина и действие DevOps), эскалация,
// верность уровня, признак слепого разбора. Автозакрытия не выдаются. Продолжение —
// ?cursor=<next_cursor> (позиция (changed_at, incident_id, event_id), однозначна при равном времени).
// Выгрузка — лимит export, сессии разбора закрыта.
export async function GET(req: Request): Promise<Response> {
  const guard = await apiGuard(req, "export");
  if (guard.response) return guard.response;
  const url = new URL(req.url);
  const since = url.searchParams.get("since") ?? "1970-01-01";
  const limitRaw = url.searchParams.get("limit") ?? "10000";
  const cursorRaw = url.searchParams.get("cursor");
  const limit = Number(limitRaw);
  const after = cursorRaw === null ? undefined : decodeLabelCursor(cursorRaw);
  if (!validSince(since) || !/^\d+$/.test(limitRaw) || limit < 1 || limit > MAX_LIMIT || after === null) {
    return Response.json({ error: `since — дата ISO 8601 (UTC), limit — 1..${MAX_LIMIT}, cursor — next_cursor прошлого ответа` }, { status: 400 });
  }
  try {
    const labels = await incidentLabels(since, limit, after);
    const truncated = labels.length === limit;
    return Response.json({
      labels, truncated, next_cursor: truncated ? encodeLabelCursor(labels[labels.length - 1]) : null,
      exported_at: new Date().toISOString(),
    });
  } catch (err) {
    console.error("api/incidents/labels:", err instanceof Error ? err.message : err);
    return Response.json({ error: "хранилище недоступно" }, { status: 503 });
  }
}
