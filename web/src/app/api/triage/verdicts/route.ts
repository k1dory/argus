import { apiGuard } from "@/lib/auth";
import { addIncidentComment, agentVerdictBySession, audit, claimTriageVerdict, incidentCommentExists, incidentGet, saveAgentVerdict } from "@/lib/argus-queries";
import {
  AGENT_NAME_RE, CONFIDENCE_NUM, DEFAULT_AGENT, VERDICT_MAX_BYTES, agentCommentId, checkVerdict, renderVerdictMarkdown, validateVerdictSchema,
  type Rejection, type VerdictDoc,
} from "@/lib/shared/triage-verdict";

// POST /api/triage/verdicts — агент разбора записывает вердикт в ARGUS.
// Bearer — сам токен triage-session: инцидент берётся из токена (sub), в теле
// он только сверяется. Тело — документ argus-triage/v3 (triage-verdict.schema.json)
// плюс необязательное поле agent (имя агента для автора комментария agent:<имя>).
//
// Проверки сервера: размер ≤ 64 КБ; JSON Schema; incident_id, level и rule_id —
// инцидента сессии; INC-ссылки доводов и related — из области токена;
// свободный текст — без ссылок, разметки, управляющих символов, псевдонимов
// и чужих номеров инцидентов (unsafe_text). Невалидный документ — 422 с путями.
//
// Запись, по порядку: журнал действий ДО любой записи (strict: нет журнала —
// нет вердикта и нет отметки, 503) → атомарная отметка claimTriageVerdict (одна
// сессия на поколение инцидента; проигравшая получает 409 verdict_published) →
// строка agent_verdicts как claim по session_id (токен дедупликации, при
// чтении — самая ранняя строка сессии: из двух разных документов одной сессии
// побеждает один, второй получает 409 verdict_exists) → комментарий
// incident_comments от победившего документа с детерминированным comment_id
// (agentCommentId). Повтор той же сессии с тем же документом — 201 с тем же id
// (незаписанный комментарий дописывается); с другим документом — 409
// verdict_exists. Провал записи после журнала — вторая запись
// triage.verdict.failed. Бюджет запросов сессии не тратится: вердикт — цель
// сессии, его нельзя потерять из-за исчерпанного лимита чтения.
export async function POST(req: Request): Promise<Response> {
  const guard = await apiGuard(req, "default", { triage: true, uncharged: true });
  if (guard.response) return guard.response;
  const scope = guard.session.triage;
  if (!scope) return Response.json({ error: "нужен токен triage-session" }, { status: 403 });

  const declared = Number(req.headers.get("content-length") ?? 0);
  if (declared > VERDICT_MAX_BYTES) return tooLarge();
  let text: string;
  try {
    text = await req.text();
  } catch {
    return Response.json({ error: "ожидается JSON" }, { status: 400 });
  }
  if (Buffer.byteLength(text, "utf8") > VERDICT_MAX_BYTES) return tooLarge();
  let body: unknown;
  try {
    body = JSON.parse(text);
  } catch {
    return Response.json({ error: "ожидается JSON" }, { status: 400 });
  }
  if (body === null || typeof body !== "object" || Array.isArray(body)) return Response.json({ error: "ожидается объект вердикта" }, { status: 400 });
  const { agent: agentRaw, ...doc } = body as Record<string, unknown>;
  const agent = agentRaw === undefined ? DEFAULT_AGENT : agentRaw;
  if (typeof agent !== "string" || !AGENT_NAME_RE.test(agent)) return Response.json({ error: "agent: латиница, цифры, . _ - (до 64)" }, { status: 400 });

  const schemaErrors = validateVerdictSchema(doc);
  if (schemaErrors.length) return rejected(schemaErrors);

  try {
    const verdict = doc as unknown as VerdictDoc;
    const incident = await incidentGet(scope.incidentId);
    if (!incident) return Response.json({ error: "инцидент не найден" }, { status: 404 });
    const errors = checkVerdict(verdict, { scope, incident: { level: incident.level, rule_id: incident.rule_id } });
    if (errors.length) return rejected(errors);

    const verdictJson = JSON.stringify(verdict);
    const commentId = agentCommentId(scope.sessionId);
    const existing = await agentVerdictBySession(scope.incidentId, scope.sessionId);
    if (existing) {
      if (existing.verdict_json !== verdictJson || existing.agent !== agent) {
        return Response.json({ error: "verdict_exists", detail: "эта сессия уже записала другой вердикт", id: existing.session_id }, { status: 409 });
      }
      // Повтор того же документа: дописать комментарий, если первая попытка оборвалась до него.
      if (!(await incidentCommentExists(scope.incidentId, commentId))) {
        await audit(guard.session.user, "triage.verdict", scope.incidentId, `повтор записи сессии ${scope.sessionId}: комментарий дописан`, { strict: true });
        await addIncidentComment(scope.incidentId, `agent:${agent}`, existing.markdown, { commentId });
      }
      return Response.json({ id: existing.session_id, incident_id: scope.incidentId, markdown: existing.markdown }, { status: 201, headers: { "Cache-Control": "no-store" } });
    }

    // Журнал — до любой записи: при отказе журнала не остаётся ни отметки, ни вердикта.
    await audit(guard.session.user, "triage.verdict", scope.incidentId,
      `вердикт ${verdict.verdict} (${verdict.confidence}, человек: ${verdict.human_needed ? "да" : "нет"}) от ${agent}, сессия ${scope.sessionId}`, { strict: true });

    const winner = await claimTriageVerdict({ incidentId: scope.incidentId, sessionId: scope.sessionId, actor: guard.session.user });
    if (winner !== scope.sessionId) {
      await audit(guard.session.user, "triage.verdict_conflict", scope.incidentId, `сессия ${scope.sessionId} опоздала, отметка у ${winner}`);
      return Response.json({ error: "verdict_published", detail: "вердикт по инциденту уже принят от другой сессии" }, { status: 409 });
    }

    const markdown = renderVerdictMarkdown(verdict, agent, scope.sessionId);
    try {
      // Строка вердикта — это и claim по session_id: записать, затем прочитать
      // победителя сессии (самая ранняя строка, при равном времени — по документу).
      // Два разных документа одной сессии одновременно: побеждает один, второй — 409.
      await saveAgentVerdict({
        incident_id: scope.incidentId, session_id: scope.sessionId, agent, verdict: verdict.verdict,
        confidence: CONFIDENCE_NUM[verdict.confidence] ?? 0, human_needed: verdict.human_needed ? 1 : 0,
        verdict_json: verdictJson, markdown,
      });
      const stored = await agentVerdictBySession(scope.incidentId, scope.sessionId);
      if (!stored) throw new Error("вердикт записан, но не читается");
      if (stored.verdict_json !== verdictJson || stored.agent !== agent) {
        return Response.json({ error: "verdict_exists", detail: "эта сессия одновременно записала другой вердикт", id: stored.session_id }, { status: 409 });
      }
      // Комментарий — от победившего документа под детерминированным comment_id.
      await addIncidentComment(scope.incidentId, `agent:${stored.agent}`, stored.markdown, { commentId });
      return Response.json({ id: stored.session_id, incident_id: scope.incidentId, markdown: stored.markdown }, { status: 201, headers: { "Cache-Control": "no-store" } });
    } catch (err) {
      await audit(guard.session.user, "triage.verdict.failed", scope.incidentId, `сессия ${scope.sessionId}: ${err instanceof Error ? err.message : "ошибка записи"}`);
      throw err;
    }
  } catch (err) {
    console.error("api/triage/verdicts:", err instanceof Error ? err.message : err);
    const msg = err instanceof Error && err.message.startsWith("журнал действий") ? err.message : "хранилище недоступно — вердикт не записан";
    return Response.json({ error: msg }, { status: 503 });
  }
}

const tooLarge = () => Response.json({ error: "payload_too_large", detail: `вердикт больше ${VERDICT_MAX_BYTES} байт` }, { status: 413 });
const rejected = (rejections: Rejection[]) => Response.json({ error: "invalid_verdict", rejections }, { status: 422 });
