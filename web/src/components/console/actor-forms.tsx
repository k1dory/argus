"use client";

import { useActionState, useEffect, useState } from "react";
import Link from "next/link";
import { useRouter } from "next/navigation";
import { BadgeCheck, Link2, TriangleAlert, Unlink } from "lucide-react";
import { toast } from "sonner";
import { bindAliasAction, closeAliasAction, confirmAliasAction, type BindAliasState } from "@/lib/actor-actions";
import { ALIAS_KIND_LABELS, ALIAS_KINDS, type AliasKind } from "@/lib/shared/actors";
import { ALL_HISTORY_FIELD, bindRisk, todayUtc } from "@/lib/shared/actors-ui";
import { cn } from "@/lib/utils";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from "@/components/ui/select";
import { ConfirmActionForm } from "@/components/console/action-form";

const initial: BindAliasState = { error: null };

export type PersonOption = { person_id: string; display: string };

/**
 * Привязка алиаса (admin): к существующей персоне (поиск по имени и id) или к
 * новой. Если персона задана (страница паспорта) — выбор скрыт. Начало
 * действия по умолчанию — сегодня (UTC): привязка «на всю историю» отдаёт
 * персоне все прошлые события значения, поэтому включается отдельным флажком
 * с предупреждением. После успеха — переход в паспорт персоны.
 */
export function BindAliasForm({
  persons, value = "", kind = "login", personId, today, kindGuessed = false,
}: {
  persons: PersonOption[];
  value?: string;
  kind?: AliasKind;
  personId?: string;
  /** Дата по умолчанию (YYYY-MM-DD, UTC); без неё — сегодня. */
  today?: string;
  /** Вид подобран по значению автоматически — показать «проверьте». */
  kindGuessed?: boolean;
}) {
  const router = useRouter();
  const [mode, setMode] = useState<"existing" | "new">(personId || persons.length ? "existing" : "new");
  const [query, setQuery] = useState(personId ?? "");
  const [aliasKind, setAliasKind] = useState<AliasKind>(kind);
  const [aliasValue, setAliasValue] = useState(value);
  const [allHistory, setAllHistory] = useState(false);
  const [state, action, pending] = useActionState(bindAliasAction, initial);
  useEffect(() => {
    if (state.error) toast.error(state.error);
    else if (state.ok && state.person_id) {
      toast.success("Алиас привязан");
      router.push(`/actors/${encodeURIComponent(state.person_id)}`);
    }
  }, [state, router]);
  const q = query.trim().toLowerCase();
  // Совпадение по id или точному имени: в форму уходит id выбранной персоны.
  const picked = personId || !q ? null : persons.find((p) => p.person_id === q) ?? persons.find((p) => p.display.trim().toLowerCase() === q) ?? null;
  const risk = bindRisk(aliasKind, aliasValue);
  return (
    <form action={action} className="space-y-4" aria-busy={pending || undefined}>
      <input type="hidden" name="kind" value={aliasKind} />
      {personId && <input type="hidden" name="person_id" value={personId} />}
      {!personId && mode === "existing" && <input type="hidden" name="person_id" value={picked?.person_id ?? query.trim()} />}
      {allHistory && <input type="hidden" name={ALL_HISTORY_FIELD} value="1" />}
      {!personId && (
        <div role="radiogroup" aria-label="К кому привязать" className="inline-flex items-center gap-0.5 rounded-lg border border-border bg-[var(--surface-deep)] p-0.5">
          {([["existing", "Существующая персона"], ["new", "Новая персона"]] as const).map(([m, label]) => (
            <button
              key={m} type="button" role="radio" aria-checked={mode === m}
              disabled={m === "existing" && !persons.length}
              onClick={() => setMode(m)}
              className={cn(
                "min-h-8 rounded-md px-3 text-[13px] transition-colors disabled:cursor-default disabled:text-[var(--text-disabled)]",
                mode === m ? "bg-[var(--surface-elevated)] font-medium text-foreground shadow-[inset_0_0_0_1px_var(--border-strong)]" : "text-muted-foreground hover:text-foreground",
              )}
            >{label}</button>
          ))}
        </div>
      )}
      <div className="flex flex-wrap items-start gap-3">
        {!personId && mode === "existing" && (
          <div className="space-y-2">
            <Label htmlFor="bind-person" className="c-label">Персона</Label>
            <Input
              id="bind-person" list="bind-person-list" value={query} onChange={(e) => setQuery(e.target.value)}
              placeholder="начните вводить имя или id" autoComplete="off" spellCheck={false} required
              className="h-10 w-64 px-3 font-mono placeholder:font-sans" aria-describedby="bind-person-hint"
            />
            <datalist id="bind-person-list">
              {persons.map((p) => <option key={p.person_id} value={p.person_id}>{p.display && p.display !== p.person_id ? p.display : undefined}</option>)}
            </datalist>
            <p id="bind-person-hint" className="min-h-4 text-xs text-muted-foreground">
              {picked ? <span className="text-foreground">{picked.display || picked.person_id} <span className="font-mono text-[var(--text-tertiary)]">{picked.person_id}</span></span> : q ? <span className="text-[var(--status-warn)]">нет такой персоны — выберите из подсказок</span> : `${persons.length} в справочнике`}
            </p>
          </div>
        )}
        {!personId && mode === "new" && (
          <>
            <div className="space-y-2">
              <Label htmlFor="bind-new-id" className="c-label">Идентификатор</Label>
              <Input id="bind-new-id" name="new_person_id" placeholder="i.petrov" className="h-10 w-44 px-3 font-mono" required pattern="[a-z0-9][a-z0-9._-]{0,63}" />
            </div>
            <div className="space-y-2">
              <Label htmlFor="bind-display" className="c-label">Имя</Label>
              <Input id="bind-display" name="display" placeholder="Иван Петров" className="h-10 w-52 px-3" />
            </div>
            <div className="space-y-2">
              <Label htmlFor="bind-team" className="c-label">Отдел</Label>
              <Input id="bind-team" name="team" placeholder="platform" className="h-10 w-36 px-3" />
            </div>
          </>
        )}
        <div className="space-y-2">
          <Label htmlFor="bind-kind" className="c-label">Вид</Label>
          <Select value={aliasKind} onValueChange={(v) => setAliasKind(v as AliasKind)}>
            <SelectTrigger id="bind-kind" className="h-10 w-36" aria-describedby={kindGuessed ? "bind-kind-hint" : undefined}><SelectValue /></SelectTrigger>
            <SelectContent>
              {ALIAS_KINDS.map((k) => <SelectItem key={k} value={k}>{ALIAS_KIND_LABELS[k]}</SelectItem>)}
            </SelectContent>
          </Select>
          {kindGuessed && <p id="bind-kind-hint" className="text-xs text-muted-foreground">подобран по значению — проверьте</p>}
        </div>
        <div className="space-y-2">
          <Label htmlFor="bind-value" className="c-label">Значение</Label>
          <Input id="bind-value" name="value" value={aliasValue} onChange={(e) => setAliasValue(e.target.value)} className="h-10 w-56 px-3 font-mono" required />
        </div>
        <div className="space-y-2">
          <Label htmlFor="bind-from" className="c-label">Действует с (UTC)</Label>
          <Input
            id="bind-from" name="from" type="date" defaultValue={today ?? todayUtc()} disabled={allHistory} required={!allHistory}
            className="h-10 w-44 px-3 [color-scheme:dark] disabled:opacity-40"
          />
          <label className="flex items-center gap-2 text-[13px] text-muted-foreground">
            <input
              type="checkbox" checked={allHistory} onChange={(e) => setAllHistory(e.target.checked)}
              className="size-4 accent-[var(--status-warn)] [color-scheme:dark]" aria-describedby={allHistory ? "bind-all-warning" : undefined}
            />
            на всю историю
          </label>
        </div>
      </div>
      {allHistory && (
        <p id="bind-all-warning" role="alert" className="flex items-start gap-2 border-l-2 border-[var(--status-warn)] pl-3 text-[13px] text-[var(--status-warn)]">
          <TriangleAlert className="mt-0.5 size-4 shrink-0" strokeWidth={1.5} aria-hidden />
          Все прошлые события и инциденты с этим значением будут отнесены к персоне — в том числе те, что были до того, как значение стало её.
        </p>
      )}
      {risk && (
        <p className="flex items-start gap-2 border-l-2 border-[var(--status-warn)] pl-3 text-[13px] text-foreground">
          <TriangleAlert className="mt-0.5 size-4 shrink-0 text-[var(--status-warn)]" strokeWidth={1.5} aria-hidden />
          {risk}
        </p>
      )}
      <div className="flex flex-wrap items-center gap-3">
        <Button type="submit" variant="secondary" disabled={pending} className="min-h-10">
          <Link2 strokeWidth={1.5} />
          {pending ? "Привязка…" : "Привязать"}
        </Button>
        <p className="text-xs text-muted-foreground">Запись попадёт в журнал действий от вашего имени.</p>
      </div>
      {state.error && <p role="alert" className="text-sm text-destructive">{state.error}</p>}
    </form>
  );
}

/** Закрыть алиас (admin): valid_to = сейчас, события после него субъекту не приписываются. */
export function CloseAliasButton({ personId, kind, value }: { personId: string; kind: AliasKind; value: string }) {
  return (
    <ConfirmActionForm
      action={closeAliasAction}
      title={`Закрыть алиас ${ALIAS_KIND_LABELS[kind]} ${value}?`}
      description="С этого момента события с этим значением перестанут относиться к персоне. История сохраняется: прошлые события остаются в паспорте."
      confirmLabel="Да, закрыть"
      successText="Алиас закрыт"
    >
      <input type="hidden" name="person_id" value={personId} />
      <input type="hidden" name="kind" value={kind} />
      <input type="hidden" name="value" value={value} />
      <Button type="submit" variant="ghost" size="xs" aria-label={`Закрыть алиас ${value}`}>
        <Unlink strokeWidth={1.5} />
        закрыть
      </Button>
    </ConfirmActionForm>
  );
}

/** Подтвердить удержанный алиас (admin): confidence = 1 — алиас начинает сшивать события. */
export function ConfirmAliasButton({ personId, kind, value, policy }: { personId: string; kind: AliasKind; value: string; policy: string | null }) {
  return (
    <ConfirmActionForm
      action={confirmAliasAction}
      title={`Подтвердить алиас ${ALIAS_KIND_LABELS[kind]} ${value}?`}
      description={`Движок удержал алиас по политике идентичности${policy ? ` «${policy}»` : ""}. После подтверждения его события и инциденты будут относиться к персоне, в том числе за прошлые периоды внутри интервала действия.`}
      confirmLabel="Да, подтвердить"
      successText="Алиас подтверждён"
    >
      <input type="hidden" name="person_id" value={personId} />
      <input type="hidden" name="kind" value={kind} />
      <input type="hidden" name="value" value={value} />
      <Button type="submit" variant="ghost" size="xs" aria-label={`Подтвердить алиас ${value}`}>
        <BadgeCheck strokeWidth={1.5} />
        подтвердить
      </Button>
    </ConfirmActionForm>
  );
}

/** Переключатель периода паспорта: ссылки, без клиентского состояния. */
export function ActorRangeLinks({ current, base }: { current: string; base: string }) {
  const items: [string, string][] = [["24h", "24 часа"], ["7d", "7 дней"], ["30d", "30 дней"]];
  return (
    <div className="flex gap-2" role="group" aria-label="Период паспорта">
      {items.map(([key, label]) => (
        <Button key={key} asChild variant="secondary" size="sm" aria-pressed={current === key}>
          <Link href={`${base}${base.includes("?") ? "&" : "?"}range=${key}`}>{label}</Link>
        </Button>
      ))}
    </div>
  );
}
