import { apiGuard } from "@/lib/auth";
import { incidentsList } from "@/lib/argus-queries";
import { isIncidentStatus } from "@/lib/shared/incidents";
import { clampPage } from "@/lib/shared/limits";
import { isEmptyIncidentRanges, parseIncidentRanges } from "@/lib/shared/page-filters";

// GET /api/incidents?status=&level=&q=&page= — список инцидентов (последняя версия
// каждого). Диапазоны, как в консоли: range=24h|… или from=/to= (UTC, по first_ts),
// level_min=/level_max= (low…critical), events_min=/events_max=.
// Доступ: сессия консоли или bearer ARGUS_API_TOKEN (MCP, скрипты).
export async function GET(req: Request): Promise<Response> {
  const guard = await apiGuard(req);
  if (guard.response) return guard.response;
  const u = new URL(req.url);
  const g = (k: string) => u.searchParams.get(k) ?? undefined;
  const status = g("status");
  const level = g("level");
  const ranges = parseIncidentRanges(u.searchParams);
  try {
    const res = await incidentsList({
      status: isIncidentStatus(status) ? status : undefined,
      // level инцидента — строка из правила (low/medium/high/critical); чужое не пропускаем
      level: level && /^[a-z]{1,16}$/.test(level) ? level : undefined,
      q: g("q")?.slice(0, 200),
      page: clampPage(g("page")),
      ...(isEmptyIncidentRanges(ranges) ? {} : { ranges }),
    });
    return Response.json(res);
  } catch (err) {
    console.error("api/incidents:", err instanceof Error ? err.message : err);
    return Response.json({ error: "хранилище недоступно" }, { status: 503 });
  }
}
