"use client";

import { useState, useTransition } from "react";
import { useRouter } from "next/navigation";
import { Search as SearchIcon } from "lucide-react";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { Select, SelectContent, SelectGroup, SelectItem, SelectTrigger, SelectValue } from "@/components/ui/select";
import { QuerySyntaxHelp } from "@/components/console/query-syntax";
import { addQueryTerm } from "@/lib/shared/query-fields";

const ANY = "__any"; // Radix Select не принимает пустое значение пункта

export type SearchFormProps = {
  index: "events" | "alerts";
  q: string;
  range: string;
  from?: string;
  to?: string;
  levelMin?: number;
  levelMax?: number;
  showMuted: boolean;
  /** Верх шкалы уровня индекса: 10 у событий, 15 у алертов Wazuh. */
  levelTop: number;
  levelLabel: string;
  maxLength: number;
  placeholder: string;
};

/**
 * Одна форма поиска: запрос, точный интервал и уровень отправляются вместе
 * кнопкой «Искать» или Enter в любом поле — введённый запрос не теряется
 * (раньше интервал и уровень жили в отдельной форме с «Применить»).
 * Без JS форма уходит обычным GET; с JS — router.push без пустых параметров.
 */
export function SearchForm(p: SearchFormProps) {
  const router = useRouter();
  const [pending, start] = useTransition();
  const [q, setQ] = useState(p.q);
  const [from, setFrom] = useState(p.from ?? "");
  const [to, setTo] = useState(p.to ?? "");
  const [min, setMin] = useState(p.levelMin !== undefined ? String(p.levelMin) : ANY);
  const [max, setMax] = useState(p.levelMax !== undefined ? String(p.levelMax) : ANY);
  const levels = Array.from({ length: p.levelTop + 1 }, (_, i) => String(i));

  const submit = (e: React.FormEvent) => {
    e.preventDefault();
    if (pending) return;
    const next = new URLSearchParams();
    next.set("index", p.index);
    if (q.trim()) next.set("q", q.trim());
    // Точный интервал главнее пресета: пресет снимается, чтобы ссылка читалась однозначно.
    if (from || to) {
      if (from) next.set("from", from);
      if (to) next.set("to", to);
    } else next.set("range", p.range);
    if (min !== ANY) next.set("level_min", min);
    if (max !== ANY) next.set("level_max", max);
    if (p.showMuted) next.set("muted", "1");
    start(() => router.push(`/search?${next.toString()}`));
  };

  const dt = "h-9 min-w-0 rounded-lg border border-[var(--border-strong)] bg-background px-2 font-mono text-[12px] text-foreground [color-scheme:dark]";
  return (
    <form method="get" action="/search" onSubmit={submit} className="flex flex-col gap-3" role="search" aria-label="Поиск" aria-busy={pending}>
      <input type="hidden" name="index" value={p.index} />
      {!from && !to && <input type="hidden" name="range" value={p.range} />}
      {p.showMuted && <input type="hidden" name="muted" value="1" />}
      {min !== ANY && <input type="hidden" name="level_min" value={min} />}
      {max !== ANY && <input type="hidden" name="level_max" value={max} />}
      <div className="flex flex-wrap gap-2">
        <Label htmlFor="search-q" className="sr-only">Строка запроса</Label>
        <div className="flex min-w-0 flex-1 items-center gap-2 rounded-lg border border-[var(--border-strong)] bg-background pr-1.5 pl-3 focus-within:border-[color-mix(in_oklab,var(--ring)_60%,transparent)] sm:min-w-[24rem]">
          <Input
            id="search-q"
            name="q"
            value={q}
            onChange={(e) => setQ(e.target.value)}
            maxLength={p.maxLength}
            placeholder={p.placeholder}
            spellCheck={false}
            autoComplete="off"
            autoFocus
            className="h-10 border-0 bg-transparent px-0 font-mono shadow-none focus-visible:border-0 focus-visible:shadow-none focus-visible:ring-0"
          />
          <QuerySyntaxHelp index={p.index} onPick={(t) => setQ((cur) => addQueryTerm(cur, t))} />
        </div>
        <Button type="submit" size="lg" className="h-10 px-4">
          {pending ? <span className="ascii-spin" aria-hidden /> : <SearchIcon strokeWidth={1.5} aria-hidden />}
          Искать
        </Button>
      </div>
      <div className="flex flex-wrap items-end gap-3">
        <fieldset className="flex min-w-0 flex-col gap-1.5">
          <legend className="c-label mb-1.5">Точный интервал, UTC</legend>
          <div className="flex items-center gap-1.5">
            <input id="search-from" name="from" type="datetime-local" value={from} onChange={(e) => setFrom(e.target.value)} aria-label="Точный интервал: начало" className={dt} />
            <span className="text-[var(--text-tertiary)]" aria-hidden>—</span>
            <input id="search-to" name="to" type="datetime-local" value={to} onChange={(e) => setTo(e.target.value)} aria-label="Точный интервал: конец" className={dt} />
          </div>
        </fieldset>
        <fieldset className="flex min-w-0 flex-col gap-1.5">
          <legend className="c-label mb-1.5">{p.levelLabel}, 0–{p.levelTop}</legend>
          <div className="flex items-center gap-1.5">
            <Bound id="search-level-min" label={`${p.levelLabel}: не ниже`} any="не ниже…" prefix="≥" value={min} onChange={setMin} levels={levels} />
            <Bound id="search-level-max" label={`${p.levelLabel}: не выше`} any="не выше…" prefix="≤" value={max} onChange={setMax} levels={levels} />
          </div>
        </fieldset>
      </div>
    </form>
  );
}

function Bound({ id, label, any, prefix, value, onChange, levels }: { id: string; label: string; any: string; prefix: string; value: string; onChange: (v: string) => void; levels: string[] }) {
  return (
    <>
      <Label htmlFor={id} className="sr-only">{label}</Label>
      <Select value={value} onValueChange={onChange}>
        <SelectTrigger id={id} aria-label={label} className="h-9 w-32 text-[13px]">
          <SelectValue>{value === ANY ? any : `${prefix} ${value}`}</SelectValue>
        </SelectTrigger>
        <SelectContent>
          <SelectGroup>
            <SelectItem value={ANY}>{any.replace("…", "")} — любой</SelectItem>
            {levels.map((l) => <SelectItem key={l} value={l}>{prefix} {l}</SelectItem>)}
          </SelectGroup>
        </SelectContent>
      </Select>
    </>
  );
}
