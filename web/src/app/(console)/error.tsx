"use client";

import { useEffect } from "react";
import Link from "next/link";
import { Button } from "@/components/ui/button";
import { Led, Panel } from "@/components/console/panel";

/**
 * Ошибка сегмента консоли: окно вместо сырой страницы Next. Текст ошибки
 * пользователю не показываем (в проде Next его и так вырезает) — только
 * общий текст на русском и digest для поиска в журнале контейнера web.
 * digest === "FORBIDDEN" — ForbiddenError из lib/auth: отказ по роли.
 */
export default function ConsoleError({ error, reset }: { error: Error & { digest?: string }; reset: () => void }) {
  useEffect(() => {
    console.error(error);
  }, [error]);
  const denied = error.digest === "FORBIDDEN";
  return (
    <Panel label={denied ? "Доступ запрещён" : "Ошибка"} meta={!denied && error.digest ? `digest ${error.digest}` : undefined}>
      <p className="flex items-center gap-2 text-sm text-foreground">
        <Led color={denied ? "var(--status-warn)" : "var(--status-err)"} />
        {denied ? "Недостаточно прав для этого раздела или действия." : "Страница не отрисовалась: что-то пошло не так на сервере консоли."}
      </p>
      <p className="mt-2 text-sm text-muted-foreground">
        {denied
          ? "Действие доступно аналитику или администратору. Обратитесь к администратору консоли за ролью."
          : "Повторите попытку; если ошибка повторяется — смотрите журнал контейнера web (по digest выше)."}
      </p>
      <div className="mt-4 flex flex-wrap gap-2">
        {!denied && (
          <Button type="button" variant="secondary" size="sm" onClick={reset}>
            Повторить
          </Button>
        )}
        <Button asChild variant="ghost" size="sm">
          <Link href="/">На обзор</Link>
        </Button>
      </div>
    </Panel>
  );
}
