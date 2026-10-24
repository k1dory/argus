import { apiGuard, outOfScope } from "@/lib/auth";
import { audit } from "@/lib/argus-queries";
import { resolveAlias } from "@/lib/actors";
import { actorApiForbidden } from "@/lib/actors-access";
import { ALIAS_VALUE_MAX } from "@/lib/shared/actors";

// GET /api/v1/actors?alias=<значение>&at=<RFC 3339, по умолчанию сейчас> —
// резолв сырого значения (actor_name, IP, хост) в персону на момент at.
// Ответ: {"alias","at","status":"resolved|unbound|ambiguous","matches":[{person_id,
// display, kind, alias_kind, valid_from, valid_to}]}. Неоднозначность отдаётся
// явно — первый кандидат не выбирается. 400 — плохие параметры.
// Доступ: сессия консоли analyst+, bearer ARGUS_API_TOKEN; токен сессии
// разбора — только если alias ∈ субъектов своего инцидента, иначе 403 out_of_scope.
// Каждый успешный вызов — запись actor.view в журнал действий (без записи — 503).
const AT_RE = /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}(:\d{2}(\.\d{1,3})?)?(Z|[+-]\d{2}:\d{2})$/;

export async function GET(req: Request): Promise<Response> {
  const guard = await apiGuard(req, "default", { triage: true });
  if (guard.response) return guard.response;
  const forbidden = actorApiForbidden(guard.session);
  if (forbidden) return forbidden;
  const sp = new URL(req.url).searchParams;
  const alias = (sp.get("alias") ?? "").trim();
  if (!alias || alias.length > ALIAS_VALUE_MAX || /[\u0000-\u001f\u007f]/.test(alias)) {
    return Response.json({ error: "invalid_value", detail: `alias: непустое значение до ${ALIAS_VALUE_MAX} символов без управляющих` }, { status: 400 });
  }
  let atMs = Date.now();
  const at = sp.get("at");
  if (at) {
    const ms = Date.parse(at);
    if (!AT_RE.test(at) || !Number.isFinite(ms)) return Response.json({ error: "invalid_value", detail: "at: ожидается RFC 3339, например 2026-10-24T12:00:00Z" }, { status: 400 });
    atMs = ms;
  }
  const scope = guard.session.triage;
  if (scope && !scope.entities.some((e) => e.kind === "actor" && (e.value === alias || e.value.toLowerCase() === alias.toLowerCase()))) return outOfScope("alias: значение не из субъектов инцидента");
  try {
    const r = await resolveAlias(alias, atMs);
    await audit(guard.session.user, "actor.view", alias, `resolve · at ${new Date(atMs).toISOString()} · ${r.status}`, { strict: true });
    return Response.json({ alias, at: new Date(atMs).toISOString(), status: r.status, matches: r.matches }, { headers: { "Cache-Control": "no-store" } });
  } catch (err) {
    console.error("api/v1/actors:", err instanceof Error ? err.message : err);
    return Response.json({ error: "хранилище недоступно или запрос отклонён" }, { status: 503 });
  }
}
