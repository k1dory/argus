"use client";

import { useActionState, useId } from "react";
import type { FormState } from "@/lib/actions";
import { scanGroupAction } from "@/lib/incident-actions";
import { DISPOSITIONS } from "@/lib/shared/closure-label";
import { Button } from "@/components/ui/button";
import { FieldError } from "@/components/ui/field";

const initial: FormState = { error: null };
const selectClass = "h-9 border border-border bg-[var(--surface-deep)] px-2 text-sm";

function Result({ state }: { state: FormState }) {
  return state.error ? <FieldError>{state.error}</FieldError>
    : state.ok ? <p role="status" className="text-xs text-[var(--status-ok)]">Готово: {state.message}</p> : null;
}

/** Подтверждение действия над всей группой: без отметки сервер откажет. */
function Confirm({ count }: { count: number }) {
  const id = useId();
  return <label htmlFor={id} className="flex items-center gap-2 text-xs">
    <input id={id} type="checkbox" name="confirm" value="yes" required />
    подтверждаю: {count} {count === 1 ? "инцидент" : "инцидентов"} этой подсети
  </label>;
}

export type GroupFilter = { status?: string; level?: string; q?: string; queue?: string };

/**
 * Показанный состав (incident_id) и условия очереди, при которых он показан:
 * сервер пересчитает группу при тех же условиях и сверит состав.
 */
function Hidden({ op, subnet, ids, filter }: { op: string; subnet: string; ids: string[]; filter: GroupFilter }) {
  return <>
    <input type="hidden" name="op" value={op} />
    <input type="hidden" name="subnet" value={subnet} />
    <input type="hidden" name="ids" value={ids.join(",")} />
    <input type="hidden" name="f_status" value={filter.status ?? ""} />
    <input type="hidden" name="f_level" value={filter.level ?? ""} />
    <input type="hidden" name="f_q" value={filter.q ?? ""} />
    <input type="hidden" name="f_queue" value={filter.queue ?? ""} />
  </>;
}

/** Групповые действия над открытыми инцидентами одной подсети сканов — по выбору аналитика. */
export function ScanGroupActions({ subnet, ids, filter, isAdmin, users }: {
  subnet: string; ids: string[]; filter: GroupFilter; isAdmin: boolean; users: { name: string; role: string }[];
}) {
  const count = ids.length;
  const [takeState, takeAction, taking] = useActionState(scanGroupAction, initial);
  const [assignState, assignAction, assigning] = useActionState(scanGroupAction, initial);
  const [closeState, closeAction, closing] = useActionState(scanGroupAction, initial);
  const analysts = users.filter((u) => u.role === "analyst" || u.role === "admin");
  return <div className="mt-3 grid gap-4 md:grid-cols-3">
    <form action={takeAction} aria-busy={taking} className="space-y-2 border border-border p-3">
      <div className="c-label">Взять все в работу</div>
      <Hidden op="take" subnet={subnet} ids={ids} filter={filter} />
      <Confirm count={count} />
      <Button type="submit" size="sm" variant="secondary" disabled={taking}>{taking ? "Беру…" : "Взять"}</Button>
      <Result state={takeState} />
    </form>
    {isAdmin && <form action={assignAction} aria-busy={assigning} className="space-y-2 border border-border p-3">
      <div className="c-label">Назначить все</div>
      <Hidden op="assign" subnet={subnet} ids={ids} filter={filter} />
      <select name="owner" required defaultValue="" aria-label="Ответственный" className={selectClass}>
        <option value="" disabled>Выберите сотрудника</option>
        {analysts.map((u) => <option key={u.name} value={u.name}>{u.name}</option>)}
      </select>
      <Confirm count={count} />
      <Button type="submit" size="sm" variant="secondary" disabled={assigning || analysts.length === 0}>{assigning ? "Назначаю…" : "Назначить"}</Button>
      <Result state={assignState} />
    </form>}
    <form action={closeAction} aria-busy={closing} className="space-y-2 border border-border p-3">
      <div className="c-label">Завершить все</div>
      <Hidden op="close" subnet={subnet} ids={ids} filter={filter} />
      <select name="status" required defaultValue="" aria-label="Статус завершения" className={selectClass}>
        <option value="" disabled>Статус</option>
        <option value="closed">закрыт</option>
        <option value="false_positive">ложное срабатывание</option>
      </select>
      <select name="disposition" required defaultValue="" aria-label="Характер срабатывания" className={selectClass}>
        <option value="" disabled>Характер срабатывания</option>
        {Object.entries(DISPOSITIONS).map(([k, v]) => <option key={k} value={k}>{v}</option>)}
      </select>
      <select name="escalate" required defaultValue="" aria-label="Нужна ли эскалация" className={selectClass}>
        <option value="" disabled>Эскалация</option>
        <option value="no">не нужна</option>
        <option value="yes">нужна</option>
      </select>
      <select name="severity_correct" required defaultValue="" aria-label="Верен ли уровень" className={selectClass}>
        <option value="" disabled>Уровень</option>
        <option value="yes">верен</option>
        <option value="no">неверен</option>
      </select>
      <textarea name="reason" required minLength={10} maxLength={2000} rows={2} placeholder="Причина (от 10 символов)" aria-label="Причина" className="w-full border border-border bg-[var(--surface-deep)] p-2 text-sm" />
      <Confirm count={count} />
      <Button type="submit" size="sm" variant="secondary" disabled={closing}>{closing ? "Завершаю…" : "Завершить"}</Button>
      <Result state={closeState} />
    </form>
  </div>;
}
