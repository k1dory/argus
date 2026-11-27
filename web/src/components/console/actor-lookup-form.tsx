import { Search } from "lucide-react";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { ALIAS_VALUE_MAX, type ActorRange } from "@/lib/shared/actors";

/**
 * Поиск владельца: одно поле на любой идентификатор (почта, логин, телефон,
 * IP, хост, id персоны). Период «где встречалось» берётся из переключателя
 * страницы (скрытое поле), отдельного выбора периода у формы нет. Обычная
 * GET-форма — работает без JS, адрес результата можно переслать коллеге.
 */
export function ActorLookupForm({ value = "", range = "7d", autoFocus = false }: { value?: string; range?: ActorRange; autoFocus?: boolean }) {
  return (
    <form method="get" action="/actors/lookup" className="flex flex-wrap items-center gap-2" role="search" aria-label="Кому принадлежит">
      <input type="hidden" name="range" value={range} />
      <Input
        name="v" defaultValue={value} maxLength={ALIAS_VALUE_MAX} required autoComplete="off" spellCheck={false} autoFocus={autoFocus}
        placeholder="почта, логин, телефон, IP, хост или id персоны"
        aria-label="Значение" className="h-10 min-w-0 flex-1 basis-72 px-3 font-mono placeholder:font-sans"
      />
      <Button type="submit" variant="secondary" className="min-h-10"><Search strokeWidth={1.5} />Найти</Button>
    </form>
  );
}
