import { apiGuard } from "@/lib/auth";
import { journalTail } from "@/lib/journal";
import { parseJournalParams, parseTailCursor } from "@/lib/shared/journal";

// GET /api/events/tail?cursor=YYYY-MM-DD HH:MM:SS|<id>&q=&source=&host=&sev=&rule=
// Live-tail журнала: события, принятые после курсора (received_at, id), по
// возрастанию, порциями до 100, с теми же фильтрами, что у ленты.
// Ответ: { rows, incidents, cursor, more, pending } — при more=true клиент
// сразу запрашивает следующую порцию. Доступ: сессия консоли или bearer.
export async function GET(req: Request): Promise<Response> {
  const guard = await apiGuard(req, "tail"); // свой лимит: догоняющие порции не съедают общий
  if (guard.response) return guard.response;
  const u = new URL(req.url);
  const cursor = parseTailCursor(u.searchParams.get("cursor"));
  if (!cursor) return Response.json({ error: "cursor: ожидается «YYYY-MM-DD HH:MM:SS|id» (UTC)" }, { status: 400 });
  const res = await journalTail(parseJournalParams(u.searchParams), cursor);
  return Response.json(res, { status: res.error ? 400 : 200, headers: { "Cache-Control": "no-store" } });
}
