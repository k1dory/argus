import { apiGuard, triageRequestsLeft } from "@/lib/auth";
import { incidentComments, incidentGet, incidentStateHistory, verdictGet } from "@/lib/argus-queries-export";
import { relatedSummaries, ruleHistory } from "@/lib/triage-queries";
import { blindComments, hideVerdicts } from "@/lib/blind";

// GET /api/triage/context — карточка инцидента сессии разбора одним запросом:
// инцидент, история статусов, комментарии, вердикт движка, связанные
// (минимальная сводка с типом связи) и счётчики правила за 90 дней. Только
// токен triage-session: id инцидента в запросе нет, он зашит в токен.
// Редакцию (псевдонимы, вырезание секретов) делает клиент-агент.
// session.anchors — сущности области с видом (как их проверяет поиск): агент
// берёт якоря только отсюда, найденные строки область не расширяют.
export async function GET(req: Request): Promise<Response> {
  const guard = await apiGuard(req, "default", { triage: true });
  if (guard.response) return guard.response;
  const scope = guard.session.triage;
  if (!scope) return Response.json({ error: "нужен токен triage-session" }, { status: 403 });
  try {
    const incident = await incidentGet(scope.incidentId);
    if (!incident) return Response.json({ error: "не найден" }, { status: 404 });
    const [history, comments, verdict, related, rule_history] = await Promise.all([
      incidentStateHistory(scope.incidentId, 200),
      incidentComments(scope.incidentId, 200),
      verdictGet(scope.incidentId),
      relatedSummaries(scope),
      ruleHistory(incident.rule_id, scope.incidentId),
    ]);
    // Слепая выборка — как /api/incidents/{id}: до завершения ни анализа модели,
    // ни копий вердикта агента в комментариях agent:*.
    const blind = hideVerdicts(incident);
    return Response.json({
      incident, history, comments: blind ? blindComments(comments) : comments, verdict: blind ? null : verdict,
      ...(blind ? { verdict_hidden: true } : {}), related, rule_history,
      session: { session_id: scope.sessionId, incident_id: scope.incidentId, expires_at: scope.expiresAt, search_from: scope.searchFrom, requests_left: triageRequestsLeft(scope),
        anchors: scope.entities.map((e) => ({ kind: e.kind, value: e.value, ...(e.weak && { weak: true }) })) },
    }, { headers: { "Cache-Control": "no-store" } });
  } catch (err) {
    console.error("api/triage/context:", err instanceof Error ? err.message : err);
    return Response.json({ error: "хранилище недоступно" }, { status: 503 });
  }
}
