import { apiGuard, outOfScope } from "@/lib/auth";
import { chQuery, incidentComments, incidentFirstResponse, incidentGet, incidentStateHistory, verdictGet } from "@/lib/argus-queries-export";
import { incidentAccess } from "@/lib/shared/triage";
import { relatedSummaries } from "@/lib/triage-queries";

// GET /api/incidents/INC-12 — полная карточка для отчёта: инцидент (последняя
// версия), история статусов, вердикт аналитика, действия оператора. Доступ —
// по той же сессии, что и консоль. История — из журнала console_audit
// (append-only), а не из версий ReplacingMergeTree: те исчезают после merge.
// Токен triage-session: свой инцидент — полностью, связанный — минимальной
// сводкой, любой другой — 403 out_of_scope.
export async function GET(req: Request, ctx: { params: Promise<{ id: string }> }): Promise<Response> {
  const guard = await apiGuard(req, "default", { triage: true });
  if (guard.response) return guard.response;
  const { id } = await ctx.params;
  if (!/^INC-\d{1,9}$/.test(id)) return Response.json({ error: "некорректный id" }, { status: 400 });
  const scope = guard.session.triage;
  const access = scope ? incidentAccess(scope, id) : "own";
  if (access === "out_of_scope") return outOfScope("инцидент не входит в сессию разбора");
  try {
    if (scope && access === "related") {
      const summary = (await relatedSummaries(scope)).find((r) => r.incident_id === id);
      if (!summary) return Response.json({ error: "не найден" }, { status: 404 });
      return Response.json({ incident: summary, scope: "related" });
    }
    const [incident, verdict, history, actions, comments, firstResponseAt] = await Promise.all([
      incidentGet(id),
      verdictGet(id),
      incidentStateHistory(id, 10_000),
      // Действия по инциденту: target = id либо detail начинается с «INC-12 ·» /
      // содержит «(из INC-12)». LIKE '%INC-1%' цеплял бы INC-10…INC-19.
      chQuery<Record<string, unknown>>(
        `SELECT ts, user, action, target, detail FROM console_audit
         WHERE target = {id:String} OR startsWith(detail, {prefix:String}) OR detail = {id:String} OR endsWith(detail, {from:String})
         ORDER BY ts`,
        { id, prefix: `${id} `, from: `(из ${id})` },
      ),
      incidentComments(id, 10_000),
      incidentFirstResponse(id),
    ]);
    if (!incident) return Response.json({ error: "не найден" }, { status: 404 });
    return Response.json(
      { incident, first_response_at: firstResponseAt, history, history_truncated: history.length === 10_000,
        verdict, actions, comments, comments_truncated: comments.length === 10_000,
        exported_at: new Date().toISOString() },
      { headers: { "Content-Disposition": `attachment; filename="${id}-${new Date().toISOString().slice(0, 10)}.json"` } },
    );
  } catch (err) {
    console.error("api/incidents/[id]:", err instanceof Error ? err.message : err);
    return Response.json({ error: "хранилище недоступно" }, { status: 503 });
  }
}
