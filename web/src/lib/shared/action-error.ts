// Текст ошибки server action для форм консоли. Чистая функция без зависимостей
// от Next: то же правило на клиенте (ActionForm) и в тестах.

export const ACTION_FAILED_LOGGED = "Действие не выполнено — подробности в журнале консоли";
export const ACTION_FAILED = "Действие не выполнено";
export const ACTION_FORBIDDEN = "Недостаточно прав для этого действия";

/** Навигационное исключение Next (redirect / notFound / forbidden) — его надо пробросить дальше. */
export function isNavigationDigest(digest: string): boolean {
  return digest.startsWith("NEXT_REDIRECT") || digest === "NEXT_NOT_FOUND" || digest.startsWith("NEXT_HTTP_ERROR");
}

/**
 * Ошибка → текст для тоста и строки под формой; "" — навигационное
 * исключение, которое форма пробрасывает. Сообщение показываем только у
 * ошибок без digest: у серверных исключений Next вырезает текст и оставляет
 * хеш, а сам стек лежит в журнале консоли.
 */
export function actionErrorText(e: unknown): string {
  if (e && typeof e === "object" && "digest" in e) {
    const d = String((e as { digest?: unknown }).digest ?? "");
    if (d === "FORBIDDEN") return ACTION_FORBIDDEN;
    if (isNavigationDigest(d)) return "";
    if (d) return ACTION_FAILED_LOGGED;
  }
  return e instanceof Error && e.message ? e.message : ACTION_FAILED;
}
