"use client";

import { useActionState, useEffect, useState } from "react";
import { toast } from "sonner";
import type { FormState } from "@/lib/actions";
import {
  addIncidentCommentAction,
  assignIncidentAction,
  setIncidentStatusAction,
  takeIncidentAction,
} from "@/lib/incident-actions";
import { INCIDENT_STATUSES } from "@/lib/shared/incidents";
import { Button } from "@/components/ui/button";
import { Field, FieldDescription, FieldError, FieldGroup, FieldLabel, FieldLegend, FieldSet } from "@/components/ui/field";

const initial: FormState = { error: null };
const isFinal = (status: string) => status === "closed" || status === "false_positive";

function Result({ state }: { state: FormState }) {
  return state.error ? <FieldError>{state.error}</FieldError>
    : state.ok ? <p role="status" className="text-xs text-[var(--status-ok)]">Сохранено</p> : null;
}

function TakeForm({ incidentId }: { incidentId: string }) {
  const [state, action, pending] = useActionState(takeIncidentAction, initial);
  return <form action={action} aria-busy={pending} className="flex flex-wrap items-center gap-3">
    <input type="hidden" name="incident_id" value={incidentId} />
    <Button type="submit" disabled={pending}>{pending ? "Сохраняю…" : "Взять в работу"}</Button>
    <Result state={state} />
  </form>;
}

function AssignForm({ incidentId, users }: { incidentId: string; users: { name: string; role: string }[] }) {
  const [state, action, pending] = useActionState(assignIncidentAction, initial);
  const analysts = users.filter((u) => u.role === "analyst");
  return <form action={action} aria-busy={pending} className="flex flex-col gap-2">
    <input type="hidden" name="incident_id" value={incidentId} />
    <FieldGroup><Field data-disabled={pending || analysts.length === 0}>
    <FieldLabel htmlFor="assign-owner">Назначить или передать аналитику</FieldLabel>
    <div className="flex flex-wrap items-center gap-2">
      <select id="assign-owner" name="owner" required defaultValue="" className="h-10 min-w-44 border border-border bg-[var(--surface-deep)] px-2 text-sm" disabled={pending || analysts.length === 0}>
        <option value="" disabled>Выберите сотрудника</option>
        {analysts.map((u) => <option key={u.name} value={u.name}>{u.name}</option>)}
      </select>
      <Button type="submit" variant="secondary" disabled={pending || analysts.length === 0}>{pending ? "Назначаю…" : "Назначить"}</Button>
    </div>
    {analysts.length === 0 && <FieldDescription>Нет доступных аналитиков. Добавьте сотрудника с ролью аналитика в настройках.</FieldDescription>}
    </Field></FieldGroup>
    <Result state={state} />
  </form>;
}

function StatusForm({ incidentId, status, exceptions }: { incidentId: string; status: string; exceptions: { field: string; value: string; label: string }[] }) {
  const [next, setNext] = useState(status);
  const [reason, setReason] = useState("");
  const [selectedExceptions, setSelectedExceptions] = useState<string[]>([]);
  const [state, action, pending] = useActionState(setIncidentStatusAction, initial);
  return <form action={action} aria-busy={pending} className="flex flex-col gap-3">
    <input type="hidden" name="incident_id" value={incidentId} />
    <FieldGroup><Field data-disabled={pending}>
    <FieldLabel htmlFor="inc-status">Статус расследования</FieldLabel>
    <div className="flex flex-wrap items-center gap-2">
      <select id="inc-status" name="status" value={next} onChange={(e) => setNext(e.target.value)} disabled={pending} className="h-10 min-w-44 border border-border bg-[var(--surface-deep)] px-2 text-sm">
        {Object.entries(INCIDENT_STATUSES).filter(([key]) => key !== "new" && key !== "waiting_owner").map(([key, label]) => <option key={key} value={key}>{label}</option>)}
      </select>
      <Button type="submit" disabled={pending || next === status}>{pending ? "Сохраняю…" : "Изменить статус"}</Button>
    </div>
    </Field>
    {isFinal(next) && <Field data-disabled={pending}>
      <FieldLabel htmlFor="inc-close-reason">Причина завершения</FieldLabel>
      <textarea id="inc-close-reason" name="reason" value={reason} onChange={(e) => setReason(e.target.value)} aria-describedby="inc-close-help" required minLength={10} maxLength={2000} rows={3} disabled={pending}
        placeholder="Что проверено, какой результат, ссылка на заявку или доказательство…"
        className="w-full resize-y border border-border bg-[var(--surface-deep)] p-3 text-sm focus-visible:outline-2 focus-visible:outline-[var(--ring)]" />
      <FieldDescription id="inc-close-help">От 10 до 2000 символов. Причина, автор и время сохраняются в истории инцидента.</FieldDescription>
    </Field>}
    {next === "false_positive" && exceptions.length > 0 && <FieldSet className="border border-border p-3" disabled={pending}>
      <FieldLegend variant="label">Добавить исключение в правило</FieldLegend>
      {exceptions.map((x) => <label key={x.field} className="flex items-center gap-2 font-mono text-xs">
        <input type="checkbox" name={`exc_${x.field}`} value="1" checked={selectedExceptions.includes(x.field)} onChange={(e) => setSelectedExceptions((current) => e.target.checked ? [...current, x.field] : current.filter((field) => field !== x.field))} className="accent-[var(--ring)]" />
        <input type="hidden" name={`excv_${x.field}`} value={x.value} />
        {x.label}: <span className="text-foreground">{x.value}</span>
      </label>)}
    </FieldSet>}
    </FieldGroup>
    <Result state={state} />
  </form>;
}

export function CommentForm({ incidentId }: { incidentId: string }) {
  const [body, setBody] = useState("");
  const submit = async (previous: FormState, data: FormData) => {
    const result = await addIncidentCommentAction(previous, data);
    if (result.ok) setBody("");
    return result;
  };
  const [state, action, pending] = useActionState(submit, initial);
  useEffect(() => {
    if (state.ok) {
      toast.success("Комментарий добавлен");
    }
  }, [state]);
  return <form action={action} aria-busy={pending} className="flex flex-col gap-3">
    <input type="hidden" name="incident_id" value={incidentId} />
    <FieldGroup><Field data-disabled={pending}>
    <FieldLabel htmlFor="inc-comment">Запись в досье (Markdown)</FieldLabel>
    <textarea id="inc-comment" name="body" value={body} onChange={(e) => setBody(e.target.value)} required maxLength={8000} rows={5} disabled={pending}
      placeholder={"### Проверено\n- Источник и время\n- Действия\n\nВывод и ссылка на заявку…"}
      className="w-full resize-y border border-border bg-[var(--surface-deep)] p-3 text-sm focus-visible:border-[var(--border-strong)] focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-[var(--ring)]/40" />
    </Field></FieldGroup>
    <div className="flex flex-wrap items-center gap-3">
      <Button type="submit" variant="secondary" disabled={pending || !body.trim()}>{pending ? "Сохраняю…" : "Добавить запись"}</Button>
      <Result state={state} />
    </div>
  </form>;
}

export function IncidentStatusForm({ incidentId, status, owner, currentUser, isAdmin, users, exceptions }: {
  incidentId: string;
  status: string;
  owner: string;
  currentUser: string;
  isAdmin: boolean;
  users: { name: string; role: string }[];
  exceptions: { field: string; value: string; label: string }[];
}) {
  const open = !isFinal(status);
  const mine = owner === currentUser;
  return <div className="flex flex-col gap-5">
    {!open && <p className="text-sm text-muted-foreground">Инцидент завершён. Дополнительные сведения можно добавить в досье.</p>}
    {open && (!owner || mine && status !== "in_progress") && <TakeForm incidentId={incidentId} />}
    {open && isAdmin && <AssignForm incidentId={incidentId} users={users} />}
    {open && mine && status !== "new" && status !== "waiting_owner" && <StatusForm key={status} incidentId={incidentId} status={status} exceptions={exceptions} />}
    {open && !mine && owner && !isAdmin && <p className="text-xs text-muted-foreground">Статус меняет ответственный: {owner}.</p>}
  </div>;
}
