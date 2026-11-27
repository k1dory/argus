"use client";

import { useSearchParams } from "next/navigation";
import { Search } from "lucide-react";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from "@/components/ui/select";

const ANY_AGENT = "__all";

/**
 * Поля журнала алертов (описание правила, агент) внутри общей формы
 * RangeFilters: одна форма и одна кнопка «Применить» — уровень, интервал,
 * текст и агент уходят вместе. Значения — из URL; форма пересоздаётся при
 * навигации (ключ RangeFilters — строка запроса), поэтому поля неуправляемые.
 * Имена полей (q, agent) страница передаёт в extraKeys RangeFilters.
 */
export function AlertsExtraFields({ agents }: { agents: string[] }) {
  const params = useSearchParams();
  const urlAgent = params.get("agent") ?? "";
  // Агент из URL может отсутствовать в списке за диапазон — показываем как есть.
  const agentOptions = urlAgent && !agents.includes(urlAgent) ? [urlAgent, ...agents] : agents;

  return (
    <>
      <div className="w-full space-y-1.5 sm:w-64">
        <Label htmlFor="alerts-q" className="c-label">Описание правила</Label>
        <div className="relative">
          <Search strokeWidth={1.5} className="pointer-events-none absolute top-1/2 left-3 h-4 w-4 -translate-y-1/2 text-muted-foreground" aria-hidden />
          <Input id="alerts-q" name="q" defaultValue={params.get("q") ?? ""} placeholder="например, sshd" className="h-9 pl-9" />
        </div>
      </div>
      <div className="space-y-1.5">
        <Label htmlFor="alerts-agent" className="c-label">Агент</Label>
        <Select name="agent" defaultValue={urlAgent || ANY_AGENT}>
          <SelectTrigger id="alerts-agent" className="h-9 w-48"><SelectValue placeholder="Все агенты" /></SelectTrigger>
          <SelectContent>
            <SelectItem value={ANY_AGENT}>Все агенты</SelectItem>
            {agentOptions.map((a) => (
              <SelectItem key={a} value={a}>{a}</SelectItem>
            ))}
          </SelectContent>
        </Select>
      </div>
    </>
  );
}
