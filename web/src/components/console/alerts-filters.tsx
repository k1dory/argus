"use client";

import { useState, useTransition } from "react";
import { usePathname, useRouter, useSearchParams } from "next/navigation";
import { Search } from "lucide-react";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from "@/components/ui/select";
import { ALERT_LEVEL_FILTERS } from "@/lib/shared/labels";

const ANY_AGENT = "__all";

/**
 * Фильтры журнала алертов: controlled-значения из URL (страница передаёт
 * key={params}, чтобы состояние сбрасывалось при навигации), применяются
 * кнопкой «Найти» или Enter; на время перехода — aria-busy и спиннер, без
 * disabled на нажатом контроле (иначе фокус уходит на body).
 */
export function AlertsFilters({ agents }: { agents: string[] }) {
  const router = useRouter();
  const pathname = usePathname();
  const params = useSearchParams();
  const [pending, start] = useTransition();
  const [q, setQ] = useState(params.get("q") ?? "");
  const [level, setLevel] = useState(params.get("level") ?? "0");
  const urlAgent = params.get("agent") ?? "";
  const [agent, setAgent] = useState(urlAgent || ANY_AGENT);
  // Агент из URL может отсутствовать в списке за диапазон — показываем как есть.
  const agentOptions = urlAgent && !agents.includes(urlAgent) ? [urlAgent, ...agents] : agents;

  const apply = () => {
    const next = new URLSearchParams(params);
    const set = (k: string, v: string, empty: string[]) => (v && !empty.includes(v) ? next.set(k, v) : next.delete(k));
    set("q", q.trim(), [""]);
    set("level", level, ["0"]);
    set("agent", agent, [ANY_AGENT]);
    next.delete("page");
    start(() => router.push(`${pathname}?${next.toString()}`));
  };

  return (
    <form
      className="flex flex-wrap items-end gap-3"
      aria-busy={pending}
      onSubmit={(e) => {
        e.preventDefault();
        if (!pending) apply(); // повторный Enter/клик во время перехода игнорируется, фокус остаётся на месте
      }}
    >
      <div className="w-full space-y-1 sm:w-64">
        <Label htmlFor="alerts-q" className="c-label">Описание правила</Label>
        <div className="relative">
          <Search strokeWidth={1.5} className="pointer-events-none absolute top-1/2 left-3 h-4 w-4 -translate-y-1/2 text-muted-foreground" aria-hidden />
          <Input id="alerts-q" name="q" value={q} onChange={(e) => setQ(e.target.value)} placeholder="brute force…" className="h-10 pl-9" aria-busy={pending || undefined} readOnly={pending} />
        </div>
      </div>
      <div className="space-y-1">
        <Label htmlFor="alerts-level" className="c-label">Уровень</Label>
        <Select value={level} onValueChange={setLevel} disabled={pending}>
          <SelectTrigger id="alerts-level" className="h-10 w-48"><SelectValue /></SelectTrigger>
          <SelectContent>
            {ALERT_LEVEL_FILTERS.map((l) => (
              <SelectItem key={l.value} value={l.value}>{l.label}</SelectItem>
            ))}
          </SelectContent>
        </Select>
      </div>
      <div className="space-y-1">
        <Label htmlFor="alerts-agent" className="c-label">Агент</Label>
        <Select value={agent} onValueChange={setAgent} disabled={pending}>
          <SelectTrigger id="alerts-agent" className="h-10 w-48"><SelectValue placeholder="Все агенты" /></SelectTrigger>
          <SelectContent>
            <SelectItem value={ANY_AGENT}>Все агенты</SelectItem>
            {agentOptions.map((a) => (
              <SelectItem key={a} value={a}>{a}</SelectItem>
            ))}
          </SelectContent>
        </Select>
      </div>
      <Button type="submit" variant="secondary" className="min-h-10" aria-busy={pending || undefined} aria-disabled={pending || undefined} title="Enter в поле — тоже применяет фильтры">
        {pending ? <span className="ascii-spin" aria-hidden /> : null}
        {pending ? "Ищу…" : "Найти"}
      </Button>
      <span className="pb-2 font-mono text-[11px] text-muted-foreground">Enter — применить</span>
    </form>
  );
}
