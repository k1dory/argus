import "server-only";

// Доступ к паспортам субъектов: страницы — аналитику и администратору
// (наблюдателю — ForbiddenError → error.tsx «Доступ запрещён»); API — то же
// для сессии консоли, bearer ARGUS_API_TOKEN — разрешён, токен сессии
// разбора — только субъект своего инцидента (проверяет маршрут).
import { ForbiddenError, requirePageSession, type Session } from "./auth";
import { ROLE_RANK } from "./shared/incidents";

export async function requireActorAccess(): Promise<Session> {
  const session = await requirePageSession();
  if (ROLE_RANK[session.role] < ROLE_RANK.analyst) throw new ForbiddenError("Паспорта субъектов доступны аналитику и администратору");
  return session;
}

/** Сессия консоли ниже аналитика не читает паспорта; служебный bearer и
 *  токен сессии разбора — да (область последнего проверяет маршрут); issuer — нет.
 *  Решает kind сессии, не имя пользователя. */
export function actorApiForbidden(s: Session): Response | null {
  if (s.kind === "triage-session" || s.kind === "api-token") return null;
  if (s.kind === "console" && ROLE_RANK[s.role] >= ROLE_RANK.analyst) return null;
  return Response.json({ error: "forbidden", detail: "паспорта субъектов доступны аналитику и администратору" }, { status: 403 });
}

/** Запись в identities: bearer ARGUS_API_TOKEN или администратор консоли. */
export function identitiesWriteForbidden(s: Session): Response | null {
  if (s.kind === "api-token" || (s.kind === "console" && s.role === "admin")) return null;
  return Response.json({ error: "forbidden", detail: "запись identities — токен API или администратор" }, { status: 403 });
}
