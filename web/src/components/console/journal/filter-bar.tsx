"use client";

import { useState, useTransition } from "react";
import { useRouter } from "next/navigation";
import { Search as SearchIcon } from "lucide-react";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { Select, SelectContent, SelectGroup, SelectItem, SelectTrigger, SelectValue } from "@/components/ui/select";
import { journalHref, MAX_Q_LEN, SEV_MAX_OPTIONS, SEV_OPTIONS, type JournalFilters } from "@/lib/shared/journal";

const ANY = "__any"; // Radix Select не принимает пустое значение пункта

const HINT = 'sshd · actor:i.petrov · src:10.20.* · -outcome:allow · attr.rule_groups:sshd · object:"/etc/passwd"';

/** Панель фильтров журнала: свободный запрос + источник, хост, серьёзность, правило, точный интервал UTC. */
export function JournalFilterBar({ filters, sources, hosts }: { filters: JournalFilters; sources: string[]; hosts: string[] }) {
  const router = useRouter();
  const [pending, start] = useTransition();
  const [q, setQ] = useState(filters.q);
  const [source, setSource] = useState(filters.source ?? ANY);
  const [host, setHost] = useState(filters.host ?? ANY);
  const [sev, setSev] = useState(filters.sev ? String(filters.sev) : ANY);
  const [sevMax, setSevMax] = useState(filters.sevMax !== undefined ? String(filters.sevMax) : ANY);
  // Выбранный в URL порог, которого нет среди пресетов (level_max=6), показываем как есть.
  const sevMaxOpts = filters.sevMax !== undefined && !SEV_MAX_OPTIONS.some((o) => o.value === String(filters.sevMax))
    ? [...SEV_MAX_OPTIONS, { value: String(filters.sevMax), label: `≤ ${filters.sevMax}` }]
    : SEV_MAX_OPTIONS;
  const sevOpts = filters.sev !== undefined && !SEV_OPTIONS.some((o) => o.value === String(filters.sev))
    ? [...SEV_OPTIONS, { value: String(filters.sev), label: `≥ ${filters.sev}` }]
    : SEV_OPTIONS;
  const [rule, setRule] = useState(filters.rule ?? "");
  const [from, setFrom] = useState(filters.from ?? "");
  const [to, setTo] = useState(filters.to ?? "");
  // Выбранное значение показываем, даже если в окне его больше нет.
  const sourceOpts = filters.source && !sources.includes(filters.source) ? [filters.source, ...sources] : sources;
  const hostOpts = filters.host && !hosts.includes(filters.host) ? [filters.host, ...hosts] : hosts;

  const submit = (e: React.FormEvent) => {
    e.preventDefault();
    const v = (s: string) => (s === ANY || s.trim() === "" ? undefined : s.trim());
    start(() =>
      router.push(
        journalHref(filters, { q: q.trim() || undefined, source: v(source), host: v(host), sev: v(sev), sevMax: v(sevMax), rule: v(rule), from: v(from), to: v(to) }),
      ),
    );
  };

  return (
    <form onSubmit={submit} className="flex flex-col gap-3" role="search" aria-label="Фильтры журнала" aria-busy={pending}>
      <div className="flex flex-wrap gap-2">
        <Label htmlFor="journal-q" className="sr-only">Свободный поиск</Label>
        <div className="flex min-w-0 flex-1 items-center gap-2 rounded-lg border border-[var(--border-strong)] bg-background pl-3 focus-within:border-[color-mix(in_oklab,var(--ring)_60%,transparent)] sm:min-w-[28rem]">
          <span className="select-none font-mono text-[13px] text-[var(--text-tertiary)]" aria-hidden>$</span>
          <Input
            id="journal-q"
            value={q}
            onChange={(e) => setQ(e.target.value)}
            maxLength={MAX_Q_LEN}
            placeholder={HINT}
            spellCheck={false}
            autoComplete="off"
            className="h-10 border-0 bg-transparent px-0 shadow-none focus-visible:shadow-none"
          />
        </div>
        <Button type="submit" size="lg" className="h-10 px-4">
          {pending ? <span className="ascii-spin" aria-hidden /> : <SearchIcon strokeWidth={1.5} aria-hidden />}
          Показать
        </Button>
      </div>

      <div className="grid gap-3 sm:grid-cols-2 lg:grid-cols-[repeat(5,minmax(0,1fr))_auto]">
        <Field label="Источник" id="journal-source">
          <Select value={source} onValueChange={setSource}>
            <SelectTrigger id="journal-source" className="h-9 w-full font-mono text-[13px]"><SelectValue>{source === ANY ? "Все источники" : source}</SelectValue></SelectTrigger>
            <SelectContent>
              <SelectGroup>
                <SelectItem value={ANY}>Все источники</SelectItem>
                {sourceOpts.map((s) => <SelectItem key={s} value={s} className="font-mono text-[13px]">{s}</SelectItem>)}
              </SelectGroup>
            </SelectContent>
          </Select>
        </Field>
        <Field label="Хост" id="journal-host">
          <Select value={host} onValueChange={setHost}>
            <SelectTrigger id="journal-host" className="h-9 w-full font-mono text-[13px]"><SelectValue>{host === ANY ? "Все хосты" : host}</SelectValue></SelectTrigger>
            <SelectContent>
              <SelectGroup>
                <SelectItem value={ANY}>Все хосты</SelectItem>
                {hostOpts.map((h) => <SelectItem key={h} value={h} className="font-mono text-[13px]">{h}</SelectItem>)}
              </SelectGroup>
            </SelectContent>
          </Select>
        </Field>
        <Field label="Серьёзность от" id="journal-sev">
          <Select value={sev} onValueChange={setSev}>
            <SelectTrigger id="journal-sev" className="h-9 w-full"><SelectValue>{sevOpts.find((o) => (o.value || ANY) === sev)?.label ?? "Любая"}</SelectValue></SelectTrigger>
            <SelectContent>
              <SelectGroup>
                {sevOpts.map((o) => <SelectItem key={o.value || ANY} value={o.value || ANY}>{o.label}</SelectItem>)}
              </SelectGroup>
            </SelectContent>
          </Select>
        </Field>
        <Field label="Серьёзность до" id="journal-sev-max">
          <Select value={sevMax} onValueChange={setSevMax}>
            <SelectTrigger id="journal-sev-max" className="h-9 w-full"><SelectValue>{sevMaxOpts.find((o) => (o.value || ANY) === sevMax)?.label ?? "Любая"}</SelectValue></SelectTrigger>
            <SelectContent>
              <SelectGroup>
                {sevMaxOpts.map((o) => <SelectItem key={o.value || ANY} value={o.value || ANY}>{o.label}</SelectItem>)}
              </SelectGroup>
            </SelectContent>
          </Select>
        </Field>
        <Field label="Правило" id="journal-rule" hint="5763 — правило Wazuh; a41c-… — события его инцидентов: источник, узел и окно инцидента. Берутся 5000 последних инцидентов правила — у шумного правила старые окна не попадут">
          <Input id="journal-rule" aria-describedby="journal-rule-hint" value={rule} onChange={(e) => setRule(e.target.value)} placeholder="5763 · a41c-*" spellCheck={false} autoComplete="off" className="h-9" />
        </Field>
        <fieldset className="flex min-w-0 flex-col gap-1.5">
          <legend className="c-label mb-1.5">Точный интервал, UTC</legend>
          <div className="flex items-center gap-1.5">
            <input type="datetime-local" value={from} onChange={(e) => setFrom(e.target.value)} aria-label="Начало интервала, UTC" className="h-9 min-w-0 rounded-lg border border-[var(--border-strong)] bg-background px-2 font-mono text-[12px] text-foreground [color-scheme:dark]" />
            <span className="text-[var(--text-tertiary)]" aria-hidden>—</span>
            <input type="datetime-local" value={to} onChange={(e) => setTo(e.target.value)} aria-label="Конец интервала, UTC" className="h-9 min-w-0 rounded-lg border border-[var(--border-strong)] bg-background px-2 font-mono text-[12px] text-foreground [color-scheme:dark]" />
          </div>
        </fieldset>
      </div>
    </form>
  );
}

function Field({ label, id, hint, children }: { label: string; id: string; hint?: string; children: React.ReactNode }) {
  return (
    <div className="flex min-w-0 flex-col gap-1.5">
      <Label htmlFor={id} className="c-label">{label}</Label>
      {children}
      {hint && <p id={`${id}-hint`} className="text-[11px] leading-[1.4] text-[var(--text-tertiary)]">{hint}</p>}
    </div>
  );
}
