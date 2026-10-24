import { apiGuard } from "@/lib/auth";
import { sourcesHealth } from "@/lib/argus-queries";

// GET /api/sources — живость источников: события за час, EPS, последний heartbeat.
export async function GET(req: Request): Promise<Response> {
  // Живость источников не раскрывает инциденты — доступна и сессии разбора.
  const g = await apiGuard(req, "default", { triage: true });
  if (g.response) return g.response;
  try {
    return Response.json({ sources: await sourcesHealth(), checked_at: new Date().toISOString() });
  } catch (err) {
    console.error("api/sources:", err instanceof Error ? err.message : err);
    return Response.json({ error: "хранилище недоступно" }, { status: 503 });
  }
}
