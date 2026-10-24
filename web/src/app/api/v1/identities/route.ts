import { apiGuard } from "@/lib/auth";
import { audit } from "@/lib/argus-queries";
import { upsertIdentities } from "@/lib/actors";
import { identitiesWriteForbidden } from "@/lib/actors-access";
import { parseIdentitiesDoc } from "@/lib/shared/actors";

// PUT /api/v1/identities — upsert персон и алиасов в форме identities.yml (JSON):
// {"persons":{"<id>":{"display","kind","team","note","aliases":[{"kind","value",
// "from","to","confidence","note"}]}}}. Проверка как у файла: person_id по
// ^[a-z0-9][a-z0-9._-]{0,63}$, kind ∈ email|login|uid|ip|host|sid|peer, адрес
// разбирается, email/login/host — в нижний регистр, даты YYYY-MM-DD или RFC 3339.
// 200 {"persons":n,"aliases":n}; 422 {"error":"invalid_value","path","detail"}.
// Доступ: bearer ARGUS_API_TOKEN или администратор консоли. Запись — source=api.
// Журнал действий обязателен: identity.import пишется ДО изменения (нет журнала
// → 503, изменения нет); провал записи — вторая запись identity.import.failed.
const BODY_MAX = 4_000_000;

export async function PUT(req: Request): Promise<Response> {
  const guard = await apiGuard(req, "default");
  if (guard.response) return guard.response;
  const forbidden = identitiesWriteForbidden(guard.session);
  if (forbidden) return forbidden;
  let body: unknown;
  try {
    const text = await req.text();
    if (text.length > BODY_MAX) return Response.json({ error: "invalid_value", detail: "тело больше 4 МБ" }, { status: 413 });
    body = JSON.parse(text);
  } catch {
    return Response.json({ error: "invalid_value", detail: "тело — JSON" }, { status: 400 });
  }
  const parsed = parseIdentitiesDoc(body);
  if (!parsed.ok) return Response.json({ error: "invalid_value", path: parsed.path, detail: parsed.error }, { status: 422 });
  const total = parsed.persons.reduce((n, p) => n + p.aliases.length, 0);
  // Журнал — до изменения: без записи импорта не будет (strict → 503).
  try {
    await audit(guard.session.user, "identity.import", "api", `персон ${parsed.persons.length} · алиасов ${total} · ${parsed.persons.map((p) => p.person_id).slice(0, 20).join(", ")}`, { strict: true });
  } catch (err) {
    return Response.json({ error: err instanceof Error ? err.message : "журнал действий недоступен" }, { status: 503 });
  }
  try {
    const n = await upsertIdentities(parsed.persons, "api");
    return Response.json(n, { headers: { "Cache-Control": "no-store" } });
  } catch (err) {
    console.error("api/v1/identities:", err instanceof Error ? err.message : err);
    await audit(guard.session.user, "identity.import.failed", "api", `импорт не записан: ${err instanceof Error ? err.message : "ошибка"}`);
    return Response.json({ error: "хранилище недоступно или запрос отклонён" }, { status: 503 });
  }
}
