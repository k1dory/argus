import Link from "next/link";
import type { Metadata } from "next";
import { Button } from "@/components/ui/button";
import { Led, Panel } from "@/components/console/panel";

export const metadata: Metadata = { title: "Не найдено" };

/** 404 внутри консоли: окно в стиле лендинга, шапка и навигация остаются. */
export default function ConsoleNotFound() {
  return (
    <Panel label="Не найдено" meta="404">
      <p className="flex items-center gap-2 text-sm text-foreground">
        <Led color="var(--status-warn)" />
        Такой страницы, инцидента или дашборда нет.
      </p>
      <p className="mt-2 text-sm text-muted-foreground">Запись могла быть удалена или адрес набран с ошибкой.</p>
      <div className="mt-4 flex flex-wrap gap-2">
        <Button asChild variant="secondary" size="sm"><Link href="/">На обзор</Link></Button>
        <Button asChild variant="ghost" size="sm"><Link href="/incidents">К инцидентам</Link></Button>
        <Button asChild variant="ghost" size="sm"><Link href="/dashboards">К дашбордам</Link></Button>
      </div>
    </Panel>
  );
}
