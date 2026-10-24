"use client";

import { useActionState, useEffect, useState } from "react";
import Link from "next/link";
import { useRouter } from "next/navigation";
import { Link2, Unlink } from "lucide-react";
import { toast } from "sonner";
import { bindAliasAction, closeAliasAction, type BindAliasState } from "@/lib/actor-actions";
import { ALIAS_KINDS, type AliasKind } from "@/lib/shared/actors";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from "@/components/ui/select";
import { ConfirmActionForm } from "@/components/console/action-form";

const initial: BindAliasState = { error: null };

export const ALIAS_KIND_LABELS: Record<AliasKind, string> = {
  email: "email", login: "логин", uid: "uid", ip: "IP-адрес", host: "хост", sid: "SID", peer: "узел VPN",
};

export type PersonOption = { person_id: string; display: string };

/**
 * Привязка алиаса (admin): к существующей персоне из списка или к новой.
 * Если персона задана (страница паспорта) — выбор скрыт. После успеха —
 * переход в паспорт персоны.
 */
export function BindAliasForm({ persons, value = "", kind = "login", personId }: { persons: PersonOption[]; value?: string; kind?: AliasKind; personId?: string }) {
  const router = useRouter();
  const [mode, setMode] = useState<"existing" | "new">(personId || persons.length ? "existing" : "new");
  const [selected, setSelected] = useState(personId ?? persons[0]?.person_id ?? "");
  const [aliasKind, setAliasKind] = useState<AliasKind>(kind);
  const [state, action, pending] = useActionState(bindAliasAction, initial);
  useEffect(() => {
    if (state.error) toast.error(state.error);
    else if (state.ok && state.person_id) {
      toast.success("Алиас привязан");
      router.push(`/actors/${encodeURIComponent(state.person_id)}`);
    }
  }, [state, router]);
  return (
    <form action={action} className="space-y-3" aria-busy={pending || undefined}>
      <input type="hidden" name="kind" value={aliasKind} />
      {mode === "existing" && <input type="hidden" name="person_id" value={selected} />}
      {!personId && (
        <div className="flex flex-wrap items-center gap-3 text-[13px]">
          <label className="flex items-center gap-1.5"><input type="radio" name="_mode" checked={mode === "existing"} onChange={() => setMode("existing")} disabled={!persons.length} /> существующая персона</label>
          <label className="flex items-center gap-1.5"><input type="radio" name="_mode" checked={mode === "new"} onChange={() => setMode("new")} /> новая персона</label>
        </div>
      )}
      <div className="flex flex-wrap items-end gap-3">
        {!personId && mode === "existing" && (
          <div className="space-y-2">
            <Label htmlFor="bind-person" className="c-label">Персона</Label>
            <Select value={selected} onValueChange={setSelected}>
              <SelectTrigger id="bind-person" className="h-10 w-64"><SelectValue placeholder="выберите" /></SelectTrigger>
              <SelectContent>
                {persons.map((p) => <SelectItem key={p.person_id} value={p.person_id}>{p.display || p.person_id} <span className="font-mono text-muted-foreground">{p.person_id}</span></SelectItem>)}
              </SelectContent>
            </Select>
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
              <Label htmlFor="bind-team" className="c-label">Команда</Label>
              <Input id="bind-team" name="team" placeholder="platform" className="h-10 w-36 px-3" />
            </div>
          </>
        )}
        <div className="space-y-2">
          <Label htmlFor="bind-kind" className="c-label">Вид</Label>
          <Select value={aliasKind} onValueChange={(v) => setAliasKind(v as AliasKind)}>
            <SelectTrigger id="bind-kind" className="h-10 w-36"><SelectValue /></SelectTrigger>
            <SelectContent>
              {ALIAS_KINDS.map((k) => <SelectItem key={k} value={k}>{ALIAS_KIND_LABELS[k]}</SelectItem>)}
            </SelectContent>
          </Select>
        </div>
        <div className="space-y-2">
          <Label htmlFor="bind-value" className="c-label">Значение</Label>
          <Input id="bind-value" name="value" defaultValue={value} className="h-10 w-56 px-3 font-mono" required />
        </div>
        <div className="space-y-2">
          <Label htmlFor="bind-from" className="c-label">Действует с (UTC)</Label>
          <Input id="bind-from" name="from" type="date" className="h-10 w-44 px-3" />
        </div>
        <Button type="submit" variant="secondary" disabled={pending} className="min-h-10">
          <Link2 strokeWidth={1.5} />
          {pending ? "Привязка…" : "Привязать"}
        </Button>
      </div>
      <p className="text-xs text-muted-foreground">Пустая дата — алиас действует на всю историю журнала; укажите дату, чтобы ограничить начало. Источник записи — api, запись попадает в журнал действий.</p>
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
