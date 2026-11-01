import { Search } from "lucide-react";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { ALIAS_VALUE_MAX, type ActorRange } from "@/lib/shared/actors";

/**
 * Поиск владельца: одно поле на любой идентификатор (почта, логин, телефон,
 * IP, хост, id персоны) и период для «где встречалось». Обычная GET-форма —
 * работает без JS, адрес результата можно переслать коллеге.
 */
export function ActorLookupForm({ value = "", range = "7d" }: { value?: string; range?: ActorRange }) {
  return (
    <form method="get" action="/actors/lookup" className="flex flex-wrap items-center gap-2" role="search" aria-label="Кому принадлежит">
      <Input
        name="v" defaultValue={value} maxLength={ALIAS_VALUE_MAX} required autoComplete="off" spellCheck={false}
        placeholder="почта, логин, телефон, IP, хост или id персоны"
        aria-label="Значение" className="min-w-0 flex-1 basis-72 font-mono"
      />
      <select name="range" defaultValue={range} aria-label="Период журнала" className="h-9 rounded-md border border-input bg-transparent px-2 text-sm">
        <option value="24h">24 часа</option>
        <option value="7d">7 дней</option>
        <option value="30d">30 дней</option>
      </select>
      <Button type="submit" size="sm"><Search strokeWidth={1.5} />Найти</Button>
    </form>
  );
}
