import { apiGuard, revokeTriageSession, signTriageToken } from "@/lib/auth";
import { audit, triageVerdictClaim } from "@/lib/argus-queries";
import { incidentGet, triageScopeFor } from "@/lib/triage-queries";
import { TRIAGE_TTL_MAX_SEC } from "@/lib/shared/triage";

const INCIDENT_ID_RE = /^INC-\d{1,9}$/;

// POST /api/triage/sessions {"incident_id": "INC-7", "ttl_sec": 3600} — выпуск
// токена triage-session для агента разбора. Только учётка triage-issuer
// (bearer ARGUS_TRIAGE_ISSUER_TOKEN). Область (связанные, сущности, привязка
// строк, начало окна поиска) считается здесь и зашивается в токен. По
// инциденту, вердикт которого уже принят (POST /api/triage/verdicts), сессия
// не выдаётся — 409 verdict_published, пока человек не разрешит повторный
// разбор в консоли.
export async function POST(req: Request): Promise<Response> {
  const guard = await apiGuard(req, "default", { issuer: true });
  if (guard.response) return guard.response;
  let body: { incident_id?: unknown; ttl_sec?: unknown };
  try {
    body = await req.json();
  } catch {
    return Response.json({ error: "ожидается JSON" }, { status: 400 });
  }
  const incidentId = body.incident_id;
  if (typeof incidentId !== "string" || !INCIDENT_ID_RE.test(incidentId)) return Response.json({ error: "incident_id: ожидается INC-<номер>" }, { status: 400 });
  const ttl = body.ttl_sec === undefined ? TRIAGE_TTL_MAX_SEC : Number(body.ttl_sec);
  if (!Number.isInteger(ttl) || ttl < 60 || ttl > TRIAGE_TTL_MAX_SEC) return Response.json({ error: `ttl_sec: от 60 до ${TRIAGE_TTL_MAX_SEC}` }, { status: 400 });
  try {
    const inc = await incidentGet(incidentId);
    if (!inc) return Response.json({ error: "инцидент не найден" }, { status: 404 });
    if (await triageVerdictClaim(incidentId)) {
      return Response.json({ error: "verdict_published", detail: "вердикт по инциденту уже записан; повторный разбор разрешает человек в консоли" }, { status: 409 });
    }
    const scope = await triageScopeFor(inc);
    const { token, scope: s } = await signTriageToken({ incidentId: inc.incident_id, ...scope, ttlSec: ttl });
    // Журнал обязателен: без записи о выпуске токен клиенту не отдаётся (strict → 503).
    await audit(guard.session.user, "triage.session", inc.incident_id,
      `сессия ${s.sessionId}, до ${s.expiresAt}, связанных ${Object.keys(s.related).length}`, { strict: true });
    return Response.json({
      token, token_type: "triage-session", session_id: s.sessionId, incident_id: s.incidentId,
      expires_at: s.expiresAt, related_ids: Object.keys(s.related),
    }, { status: 201, headers: { "Cache-Control": "no-store" } });
  } catch (err) {
    console.error("api/triage/sessions:", err instanceof Error ? err.message : err);
    return Response.json({ error: err instanceof Error && err.message.startsWith("журнал действий") ? err.message : "хранилище недоступно" }, { status: 503 });
  }
}

// DELETE /api/triage/sessions — агент закрывает свою сессию (bearer — сам
// токен triage-session): после записи вердикта чтение больше не нужно.
// Бюджет запросов не тратит: иначе после 100 запросов сессию не закрыть.
// В журнале — triage.session.revoke; отказ журнала отзыв не блокирует.
export async function DELETE(req: Request): Promise<Response> {
  const guard = await apiGuard(req, "default", { triage: true, uncharged: true });
  if (guard.response) return guard.response;
  if (!guard.session.triage) return Response.json({ error: "нужен токен triage-session" }, { status: 403 });
  // Исключение из правила «аудит strict до мутации»: отзыв важнее журнала —
  // при отказе журнала отзыв всё равно выполняется, ошибка — в лог сервера.
  try {
    await audit(guard.session.user, "triage.session.revoke", guard.session.triage.incidentId, `сессия ${guard.session.triage.sessionId} отозвана агентом`);
  } catch (err) {
    console.error("api/triage/sessions DELETE audit:", err instanceof Error ? err.message : err);
  }
  try {
    await revokeTriageSession(guard.session.triage);
  } catch (err) {
    console.error("api/triage/sessions DELETE:", err instanceof Error ? err.message : err);
    return Response.json({ error: "хранилище недоступно — сессия не отозвана" }, { status: 503 });
  }
  return new Response(null, { status: 204 });
}
