import { actorApi } from "@/lib/actors-api";
import { aliasKey, holdPolicy, isHeld } from "@/lib/shared/actors";

// GET /api/v1/actors/{id}?range=24h|7d|30d&limit=1…500 — паспорт субъекта в JSON
// для агентов: {"person":{person_id,display,kind,team,note},"aliases":[{kind,value,
// valid_from,valid_to,source,confidence,hold,policy?}] (hold — алиас на удержании по
// политике идентичности: показан, но в сшивке не участвует),"range":{from,to},"summary":{events,
// by_source_class,nodes,src_ips,incidents},"logins":[…],"hosts":[…],"network":[…],
// "apps":[…],"changes":[…],"incidents":[{id,level,status,rule_id,rule_title,
// created_at}],"timeline":[элементы в форме /api/v1/log]}. 404 — персоны нет.
// Доступ — как у /api/v1/actors; токен сессии разбора получает только субъект
// своего инцидента, окно не раньше first_ts − 30 дней, строки привязаны к
// субъекту и узлам инцидента. Каждый вызов — actor.view в журнале действий.
export async function GET(req: Request, ctx: { params: Promise<{ id: string }> }): Promise<Response> {
  const { id } = await ctx.params;
  const r = await actorApi(req, id, "actor.view");
  if (!r.ok) return r.response;
  const rep = r.report;
  return Response.json({
    person: rep.person,
    aliases: rep.aliases.map((a) => ({
      kind: a.kind, value: a.value, valid_from: a.valid_from, valid_to: a.valid_to, source: a.source, confidence: a.confidence,
      hold: isHeld(a), ...(isHeld(a) && { policy: holdPolicy(a) ?? "" }),
    })),
    // Алиасы персоны, которые в окне делятся с другой персоной (ключ неоднозначности — колонка + значение).
    ambiguous: rep.aliases.filter((a) => rep.ambiguous.includes(aliasKey(a))).map(({ kind, value }) => ({ kind, value })),
    range: { key: rep.range.key, from: rep.range.from, to: rep.range.to },
    summary: rep.summary,
    sources: rep.sources,
    logins: rep.sections.login,
    hosts: rep.sections.host,
    network: rep.sections.network,
    apps: rep.sections.app,
    changes: rep.sections.change,
    incidents: rep.incidents,
    timeline: rep.timeline,
    limit: rep.limit,
    missing: rep.missing,
    generated_at: rep.generated_at,
  }, { headers: { "Cache-Control": "no-store" } });
}
