import "server-only";

// Общая часть GET /api/v1/actors/{id} и /report: проверка доступа, разбор
// параметров, область сессии разбора, сборка отчёта и запись в журнал.
//
// Область сессии разбора: персона — субъект инцидента, только если её
// субъектный алиас совпадает с субъектом из области и действовал в момент
// инцидента (first_ts…last_ts); в ответ попадают лишь алиасы, совпавшие с
// сущностями области (чужие виды и значения не отдаются), team/note скрыты;
// окно — не раньше first_ts − 30 дней; привязка строк scope.bind действует на
// все части отчёта; инциденты — только свой и связанные.
import { apiGuard, outOfScope, type Session } from "./auth";
import { audit, incidentGet } from "./argus-queries";
import { actorReport, getPerson, personAliases } from "./actors";
import { actorApiForbidden } from "./actors-access";
import { ACTOR_KINDS, aliasInterval, aliasMatches, parseActorsParams, PERSON_ID_RE, rangeWindow, tsMs, type ActorReport, type Alias } from "./shared/actors";
import type { TriageEntityKind, TriageScope } from "./shared/triage";

export type ActorApiResult = { ok: true; report: ActorReport; session: Session } | { ok: false; response: Response };

/** Вид сущности области, с которой сопоставляется алиас данного вида. */
const entityKindOf = (a: Alias): TriageEntityKind => (a.kind === "ip" ? "ip" : a.kind === "host" ? "node" : "actor");

/** Алиас совпадает с сущностью области (сравнение по правилу вида: регистр, канон IP). */
export function scopedAlias(scope: TriageScope, a: Alias): boolean {
  const kind = entityKindOf(a);
  return scope.entities.some((e) => e.kind === kind && aliasMatches(a, e.value));
}

export async function actorApi(req: Request, id: string, action: "actor.view" | "actor.export"): Promise<ActorApiResult> {
  // Экспорт — выгрузка ПДн: лимит kind "export", токену сессии разбора закрыт (apiGuard → out_of_scope).
  const guard = await apiGuard(req, action === "actor.export" ? "export" : "default", { triage: true });
  if (guard.response) return { ok: false, response: guard.response };
  const forbidden = actorApiForbidden(guard.session);
  if (forbidden) return { ok: false, response: forbidden };
  if (!PERSON_ID_RE.test(id)) return { ok: false, response: Response.json({ error: "invalid_value", detail: "некорректный person_id" }, { status: 400 }) };
  const parsed = parseActorsParams(new URL(req.url).searchParams);
  if (!parsed.ok) return { ok: false, response: Response.json({ error: "invalid_value", detail: parsed.error }, { status: 400 }) };
  const { range, limit } = parsed.params;
  try {
    const [person, allAliases] = await Promise.all([getPerson(id), personAliases(id)]);
    if (!person) return { ok: false, response: Response.json({ error: "не найден" }, { status: 404 }) };
    const scope = guard.session.triage;
    let aliases = allAliases;
    let subject = person;
    let opts: Parameters<typeof actorReport>[4] = {};
    if (scope) {
      const inc = await incidentGet(scope.incidentId);
      if (!inc) return { ok: false, response: outOfScope("инцидент сессии разбора не найден") };
      const incWindow = { fromMs: tsMs(inc.first_ts) ?? 0, toMs: (tsMs(inc.last_ts) ?? tsMs(inc.first_ts) ?? 0) + 1 };
      // Субъект инцидента — субъектный алиас из области, действовавший в момент инцидента.
      const own = allAliases.some((a) => ACTOR_KINDS.includes(a.kind) && scopedAlias(scope, a) && aliasInterval(a, incWindow) !== null);
      if (!own) return { ok: false, response: outOfScope("персона не является субъектом инцидента сессии разбора") };
      aliases = allAliases.filter((a) => scopedAlias(scope, a));
      subject = { ...person, team: "", note: "" };
      const w = rangeWindow(range);
      opts = {
        window: { fromMs: Math.max(w.fromMs, Date.parse(scope.searchFrom)), toMs: w.toMs },
        bind: scope.bind,
        incidentIds: [scope.incidentId, ...Object.keys(scope.related)],
      };
    }
    // Сначала журнал действий: без записи о просмотре данные не читаются.
    await audit(guard.session.user, action, id, `${range}${scope ? ` · сессия разбора ${scope.incidentId}` : ""}`, { strict: true });
    const report = await actorReport(subject, aliases, range, limit, opts);
    return { ok: true, report, session: guard.session };
  } catch (err) {
    console.error(`api/v1/actors/[id] ${action}:`, err instanceof Error ? err.message : err);
    const msg = err instanceof Error && err.message.startsWith("журнал действий") ? err.message : "хранилище недоступно или запрос отклонён";
    return { ok: false, response: Response.json({ error: msg }, { status: 503 }) };
  }
}
