import { apiGuard } from "@/lib/auth";
import { incidentComments, incidentGet, incidentStateHistory, verdictGet } from "@/lib/argus-queries-export";
import { incidentMarkdown } from "@/lib/shared/incident-wiki";
import { hideVerdicts } from "@/lib/blind";

export async function GET(req: Request, ctx: { params: Promise<{ id: string }> }): Promise<Response> {
  const guard = await apiGuard(req);
  if (guard.response) return guard.response;
  const { id } = await ctx.params;
  if (!/^INC-\d{1,9}$/.test(id)) return Response.json({ error: "некорректный id" }, { status: 400 });
  try {
    const [incident, verdict, history, comments] = await Promise.all([
      incidentGet(id), verdictGet(id), incidentStateHistory(id, 10_000), incidentComments(id, 10_000),
    ]);
    if (!incident) return Response.json({ error: "не найден" }, { status: 404 });
    const blind = hideVerdicts(incident);
    return new Response(incidentMarkdown(incident, blind ? null : verdict, history, comments, { blind }), {
      headers: {
        "Content-Type": "text/markdown; charset=utf-8",
        "Content-Disposition": `attachment; filename="${id}.md"`,
        "Cache-Control": "private, no-store",
      },
    });
  } catch (err) {
    console.error("api/incidents/[id]/markdown:", err instanceof Error ? err.message : err);
    return Response.json({ error: "досье временно недоступно" }, { status: 503 });
  }
}
