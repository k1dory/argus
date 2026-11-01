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
import { DISPOSITIONS, OPS_ACTIONS, OPS_CAUSES, OPS_URGENCY, SEVERITY_LABELS } from "@/lib/shared/closure-label";
import { ATTACK_OTHER, ATTACK_TACTICS, type AttackFormOptions } from "@/lib/shared/attack";
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

function AssignForm({ incidentId, owner, users }: { incidentId: string; owner: string; users: { name: string; role: string }[] }) {
  const [state, action, pending] = useActionState(assignIncidentAction, initial);
  // Аналитики и администраторы, кроме текущего ответственного; наблюдателям не назначают.
  const analysts = users.filter((u) => (u.role === "analyst" || u.role === "admin") && u.name !== owner);
  return <form action={action} aria-busy={pending} className="flex flex-col gap-2">
    <input type="hidden" name="incident_id" value={incidentId} />
    <FieldGroup><Field data-disabled={pending || analysts.length === 0}>
    <FieldLabel htmlFor="assign-owner">Назначить или передать аналитику</FieldLabel>
    <div className="flex flex-wrap items-center gap-2">
      <select id="assign-owner" name="owner" required defaultValue="" className="h-10 min-w-44 border border-border bg-[var(--surface-deep)] px-2 text-sm" disabled={pending || analysts.length === 0}>
        <option value="" disabled>Выберите сотрудника</option>
        {analysts.map((u) => <option key={u.name} value={u.name}>{u.name}{u.role === "admin" ? " (администратор)" : ""}</option>)}
      </select>
      <Button type="submit" variant="secondary" disabled={pending || analysts.length === 0}>{pending ? "Назначаю…" : "Назначить"}</Button>
    </div>
    {analysts.length === 0 && <FieldDescription>Некому назначить: добавьте сотрудника с ролью аналитика в настройках или дождитесь его входа через SSO.</FieldDescription>}
    </Field></FieldGroup>
    <Result state={state} />
  </form>;
}

const selectClass = "h-10 w-full border border-border bg-[var(--surface-deep)] px-2 text-sm";

/** Выбор из словаря; пустое значение по умолчанию — ответ нельзя «проскочить». */
function LabelSelect({ id, name, label, options, value, onChange, disabled, required = true, help }: {
  id: string; name: string; label: string; options: Record<string, string>; value: string; onChange: (v: string) => void; disabled: boolean;
  required?: boolean; help?: string;
}) {
  return <Field data-disabled={disabled}>
    <FieldLabel htmlFor={id}>{label}</FieldLabel>
    <select id={id} name={name} required={required} value={value} onChange={(e) => onChange(e.target.value)} disabled={disabled} className={selectClass}
      aria-describedby={help ? `${id}-help` : undefined}>
      <option value="" disabled={required}>{required ? "Выберите…" : "не указано"}</option>
      {Object.entries(options).map(([key, text]) => <option key={key} value={key}>{text}</option>)}
    </select>
    {help && <FieldDescription id={`${id}-help`}>{help}</FieldDescription>}
  </Field>;
}

const YES_NO = { yes: "да", no: "нет" };
const OTHER_LABEL = "другое";

/** Метка ответа при завершении — вопросы плана разметки: вердикт ИБ, правильный уровень,
 *  тактика и техника ATT&CK; для DevOps — причина, действовать ли сейчас, срочность. */
export function ClosureLabelFields({ ops, status, attack, disabled }: { ops: boolean; status: string; attack: AttackFormOptions; disabled: boolean }) {
  const [disposition, setDisposition] = useState("");
  const [escalate, setEscalate] = useState("");
  const [severity, setSeverity] = useState("");
  const [tactic, setTactic] = useState(attack.defaultTactic);
  const [technique, setTechnique] = useState("");
  const [cause, setCause] = useState("");
  const [actNow, setActNow] = useState("");
  const [urgency, setUrgency] = useState("");
  const [action, setAction] = useState("");
  const falsePositive = status === "false_positive";
  if (ops) {
    // «Ложное срабатывание» в статусе и в причине — одно и то же решение.
    const causeValue = falsePositive ? "false_positive" : cause === "false_positive" ? "" : cause;
    const causeOptions: Record<string, string> = falsePositive ? { false_positive: OPS_CAUSES.false_positive }
      : Object.fromEntries(Object.entries(OPS_CAUSES).filter(([k]) => k !== "false_positive"));
    return <FieldSet className="grid gap-3 border border-border p-3 sm:grid-cols-2" disabled={disabled}>
      <FieldLegend variant="label">Ответ DevOps</FieldLegend>
      <LabelSelect id="inc-ops-cause" name="ops_cause" label="Причина" options={causeOptions} value={causeValue} onChange={setCause} disabled={disabled} />
      <LabelSelect id="inc-ops-act-now" name="ops_act_now" label="Действовать сейчас" options={YES_NO} value={actNow} onChange={setActNow} disabled={disabled} />
      <LabelSelect id="inc-ops-urgency" name="ops_urgency" label="Срочность" options={OPS_URGENCY} value={urgency} onChange={setUrgency} disabled={disabled} />
      <LabelSelect id="inc-ops-action" name="ops_action" label="Что сделали" options={OPS_ACTIONS} value={action} onChange={setAction} disabled={disabled} required={false} />
    </FieldSet>;
  }
  const dispositionValue = falsePositive ? "false_positive" : disposition === "false_positive" ? "" : disposition;
  const dispositionOptions: Record<string, string> = falsePositive
    ? { false_positive: DISPOSITIONS.false_positive }
    : { malicious: DISPOSITIONS.malicious, benign_authorized: DISPOSITIONS.benign_authorized };
  const tacticOptions: Record<string, string> = { ...ATTACK_TACTICS, [ATTACK_OTHER]: OTHER_LABEL };
  const candidates = attack.candidates[tactic] ?? [];
  const techniqueOptions: Record<string, string> = {
    ...Object.fromEntries(candidates.map((t) => [t.id, `${t.id} ${t.name}`])), [ATTACK_OTHER]: OTHER_LABEL,
  };
  // Смена тактики меняет кандидатов: выбранная техника вне нового списка сбрасывается.
  const techniqueValue = Object.hasOwn(techniqueOptions, technique) ? technique : "";
  return <FieldSet className="grid gap-3 border border-border p-3 sm:grid-cols-3" disabled={disabled}>
    <FieldLegend variant="label">Ответ аналитика</FieldLegend>
    <LabelSelect id="inc-disposition" name="disposition" label="Характер срабатывания" options={dispositionOptions} value={dispositionValue} onChange={setDisposition} disabled={disabled} />
    <LabelSelect id="inc-escalate" name="escalate" label="Нужна эскалация" options={YES_NO} value={escalate} onChange={setEscalate} disabled={disabled} />
    <LabelSelect id="inc-severity" name="severity_level" label="Какой уровень правильный" options={SEVERITY_LABELS} value={severity} onChange={setSeverity} disabled={disabled} />
    <LabelSelect id="inc-attack-tactic" name="attack_tactic" label="Тактика ATT&CK" options={tacticOptions} value={tactic} onChange={setTactic} disabled={disabled}
      required={!falsePositive} help={attack.defaultTactic ? "по умолчанию — из тегов правила" : undefined} />
    <LabelSelect id="inc-attack-technique" name="attack_technique" label="Техника ATT&CK" options={techniqueOptions} value={techniqueValue} onChange={setTechnique} disabled={disabled}
      required={!falsePositive} help={`ATT&CK Enterprise ${attack.version}: техники из тегов правила и соседние по тактике`} />
  </FieldSet>;
}

function StatusForm({ incidentId, status, ops, attack, exceptions }: { incidentId: string; status: string; ops: boolean; attack: AttackFormOptions; exceptions: { field: string; value: string; label: string }[] }) {
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
    {isFinal(next) && <ClosureLabelFields ops={ops} status={next} attack={attack} disabled={pending} />}
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

export function IncidentStatusForm({ incidentId, status, ops, attack, owner, currentUser, isAdmin, users, exceptions }: {
  incidentId: string;
  status: string;
  /** Эксплуатационное правило (теги ops.*): при завершении — форма DevOps. */
  ops: boolean;
  /** Тактика по умолчанию и кандидаты техники ATT&CK (attackFormOptions по тегам правила). */
  attack: AttackFormOptions;
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
    {open && isAdmin && <AssignForm incidentId={incidentId} owner={owner} users={users} />}
    {open && mine && status !== "new" && status !== "waiting_owner" && <StatusForm key={status} incidentId={incidentId} status={status} ops={ops} attack={attack} exceptions={exceptions} />}
    {open && !mine && owner && !isAdmin && <p className="text-xs text-muted-foreground">Статус меняет ответственный: {owner}.</p>}
  </div>;
}
