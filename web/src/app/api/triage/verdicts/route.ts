import { apiGuard } from "@/lib/auth";
import { addIncidentComment, agentVerdictBySession, audit, claimTriageVerdict, incidentGet, saveAgentVerdict } from "@/lib/argus-queries";
import {
  AGENT_NAME_RE, CONFIDENCE_NUM, DEFAULT_AGENT, VERDICT_MAX_BYTES, checkVerdict, renderVerdictMarkdown, validateVerdictSchema,
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
// Запись: атомарная отметка claimTriageVerdict (одна сессия на поколение
// инцидента; проигравшая получает 409 verdict_published), строка в
// agent_verdicts, комментарий incident_comments с Markdown от агента, отметка
// в журнале действий. Одна сессия — один вердикт: повтор — 409 verdict_exists
// с id уже записанного. Бюджет запросов сессии не тратится: вердикт — цель
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

    const existing = await agentVerdictBySession(scope.incidentId, scope.sessionId);
    if (existing) return Response.json({ error: "verdict_exists", detail: "эта сессия уже записала вердикт", id: existing.session_id }, { status: 409 });

    const winner = await claimTriageVerdict({ incidentId: scope.incidentId, sessionId: scope.sessionId, actor: guard.session.user });
    if (winner !== scope.sessionId) {
      await audit(guard.session.user, "triage.verdict_conflict", scope.incidentId, `сессия ${scope.sessionId} опоздала, отметка у ${winner}`);
      return Response.json({ error: "verdict_published", detail: "вердикт по инциденту уже принят от другой сессии" }, { status: 409 });
    }

    const markdown = renderVerdictMarkdown(verdict, agent, scope.sessionId);
    await saveAgentVerdict({
      incident_id: scope.incidentId, session_id: scope.sessionId, agent, verdict: verdict.verdict,
      confidence: CONFIDENCE_NUM[verdict.confidence] ?? 0, human_needed: verdict.human_needed ? 1 : 0,
      verdict_json: JSON.stringify(verdict), markdown,
    });
    await addIncidentComment(scope.incidentId, `agent:${agent}`, markdown);
    await audit(guard.session.user, "triage.verdict", scope.incidentId,
      `вердикт ${verdict.verdict} (${verdict.confidence}, человек: ${verdict.human_needed ? "да" : "нет"}) от ${agent}, сессия ${scope.sessionId}`);
    return Response.json({ id: scope.sessionId, incident_id: scope.incidentId, markdown }, { status: 201, headers: { "Cache-Control": "no-store" } });
  } catch (err) {
    console.error("api/triage/verdicts:", err instanceof Error ? err.message : err);
    return Response.json({ error: "хранилище недоступно — вердикт не записан" }, { status: 503 });
  }
}

const tooLarge = () => Response.json({ error: "payload_too_large", detail: `вердикт больше ${VERDICT_MAX_BYTES} байт` }, { status: 413 });
const rejected = (rejections: Rejection[]) => Response.json({ error: "invalid_verdict", rejections }, { status: 422 });
