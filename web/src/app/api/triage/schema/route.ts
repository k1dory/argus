import { createHash } from "crypto";
import { apiGuard } from "@/lib/auth";
import { VERDICT_SCHEMA, VERDICT_SCHEMA_VERSION } from "@/lib/shared/triage-verdict";

// GET /api/triage/schema — JSON Schema вердикта (argus-triage/v3), по которой консоль
// проверяет POST /api/triage/verdicts. Только токену triage-session: агент разбора
// получает схему с того же сервера, которому отдаст вердикт, и не держит копию в своих
// инструкциях. Схема статична — ETag по содержимому, 304 на If-None-Match.
const body = JSON.stringify(VERDICT_SCHEMA);
const etag = `"${createHash("sha256").update(body).digest("hex").slice(0, 32)}"`;

export async function GET(req: Request): Promise<Response> {
  const guard = await apiGuard(req, "default", { triage: true, uncharged: true }); // схема статична — бюджет сессии не тратим
  if (guard.response) return guard.response;
  if (!guard.session.triage) return Response.json({ error: "нужен токен triage-session" }, { status: 403 });
  const headers = { "Content-Type": "application/schema+json; charset=utf-8", ETag: etag, "Cache-Control": "private, max-age=3600", "X-Argus-Schema-Version": VERDICT_SCHEMA_VERSION };
  if (req.headers.get("if-none-match") === etag) return new Response(null, { status: 304, headers });
  return new Response(body, { status: 200, headers });
}
