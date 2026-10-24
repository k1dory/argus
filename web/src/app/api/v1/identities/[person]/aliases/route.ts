import { apiGuard } from "@/lib/auth";
import { audit } from "@/lib/argus-queries";
import { closeAlias } from "@/lib/actors";
import { identitiesWriteForbidden } from "@/lib/actors-access";
import { ALIAS_VALUE_MAX, isAliasKind, PERSON_ID_RE } from "@/lib/shared/actors";

// DELETE /api/v1/identities/{person}/aliases?kind=&value= — закрыть алиас:
// действующая версия получает valid_to = сейчас (новая строка, история
// остаётся). 204 — закрыт; 404 — действующего алиаса нет; 400 — параметры.
// Доступ — как у PUT /api/v1/identities. Журнал обязателен: identity.alias.close
// пишется ДО изменения (strict), провал — identity.alias.close.failed.
export async function DELETE(req: Request, ctx: { params: Promise<{ person: string }> }): Promise<Response> {
  const guard = await apiGuard(req, "default");
  if (guard.response) return guard.response;
  const forbidden = identitiesWriteForbidden(guard.session);
  if (forbidden) return forbidden;
  const { person } = await ctx.params;
  if (!PERSON_ID_RE.test(person)) return Response.json({ error: "invalid_value", detail: "некорректный person_id" }, { status: 400 });
  const sp = new URL(req.url).searchParams;
  const kind = sp.get("kind") ?? "";
  const value = (sp.get("value") ?? "").trim();
  if (!isAliasKind(kind)) return Response.json({ error: "invalid_value", detail: "kind: email|login|uid|ip|host|sid|peer" }, { status: 400 });
  if (!value || value.length > ALIAS_VALUE_MAX) return Response.json({ error: "invalid_value", detail: `value: непустое значение до ${ALIAS_VALUE_MAX} символов` }, { status: 400 });
  // Журнал — до изменения (strict): без записи алиас не закрывается.
  try {
    await audit(guard.session.user, "identity.alias.close", person, `${kind} = ${value}`, { strict: true });
  } catch (err) {
    return Response.json({ error: err instanceof Error ? err.message : "журнал действий недоступен" }, { status: 503 });
  }
  try {
    const n = await closeAlias(person, kind, value);
    if (n === 0) {
      await audit(guard.session.user, "identity.alias.close.failed", person, `${kind} = ${value}: действующего алиаса нет`);
      return Response.json({ error: "не найден", detail: "действующего алиаса с таким значением нет" }, { status: 404 });
    }
    return new Response(null, { status: 204 });
  } catch (err) {
    console.error("api/v1/identities/[person]/aliases:", err instanceof Error ? err.message : err);
    await audit(guard.session.user, "identity.alias.close.failed", person, `${kind} = ${value}: ${err instanceof Error ? err.message : "ошибка"}`);
    return Response.json({ error: "хранилище недоступно или запрос отклонён" }, { status: 503 });
  }
}
