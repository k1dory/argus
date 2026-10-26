import { apiSession } from "@/lib/auth";
import { APP_VERSION, OPENAPI_PATH } from "@/lib/version";

// Живость сервиса для healthcheck compose — без деталей. Номер версии
// раскрывается только сессии/токену: анониму он помогает подбирать эксплойты.
// openapi — путь к спецификации API (копия api/openapi.yaml в public/, см.
// scripts/sync-openapi.mjs): агенту с токеном — точка входа для discovery.
export async function GET(req: Request): Promise<Response> {
  const session = await apiSession(req);
  if (!session) return Response.json({ status: "ok" });
  return Response.json({ status: "ok", name: "argus-console", version: APP_VERSION, openapi: OPENAPI_PATH });
}
