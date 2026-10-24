"use client";

import { useActionState, useEffect, useState } from "react";
import { KeyRound, Trash2, UserPlus } from "lucide-react";
import { toast } from "sonner";
import { createUserAction, deleteUserAction, resetUserPasswordAction, type CreateUserState } from "@/lib/user-actions";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from "@/components/ui/select";
import { ConfirmActionForm } from "@/components/console/action-form";

const initial: CreateUserState = { error: null };

/** Одноразовый показ пароля — как у installation assistant Wazuh. */
function OneTimePassword({ name, password }: { name: string; password: string }) {
  return (
    <div className="border border-[var(--status-warn)]/40 bg-[var(--surface-deep)] p-3 font-mono text-xs">
      <div className="c-label mb-1">Пароль показывается один раз</div>
      <div>User: {name}</div>
      <div>Password: <span className="text-foreground select-all">{password}</span></div>
    </div>
  );
}

export function CreateUserForm() {
  const [role, setRole] = useState("analyst");
  const [state, action, pending] = useActionState(createUserAction, initial);
  // «Затронуто» считается относительно конкретного результата: новый ввод
  // после ответа прячет ok/ошибку, новый ответ показывает их снова.
  const [touchedFor, setTouchedFor] = useState<CreateUserState | null>(null);
  const touched = touchedFor === state;
  useEffect(() => {
    if (state.error) toast.error(state.error);
    else if (state.ok) toast.success(`Пользователь ${state.name} создан`);
  }, [state]);
  return (
    <form action={action} className="space-y-4" aria-busy={pending || undefined}>
      <input type="hidden" name="role" value={role} />
      <div className="flex flex-wrap items-end gap-3">
        <div className="space-y-2">
          <Label htmlFor="new-user" className="c-label">Имя</Label>
          <Input id="new-user" name="name" placeholder="i.petrov" className="h-10 w-48 px-3" required onChange={() => setTouchedFor(state)} />
        </div>
        <div className="space-y-2">
          <Label htmlFor="new-user-role" className="c-label">Роль</Label>
          <Select value={role} onValueChange={setRole}>
            <SelectTrigger id="new-user-role" className="h-10 w-44"><SelectValue /></SelectTrigger>
            <SelectContent>
              <SelectItem value="viewer">наблюдатель</SelectItem>
              <SelectItem value="analyst">аналитик</SelectItem>
              <SelectItem value="admin">администратор</SelectItem>
            </SelectContent>
          </Select>
        </div>
        <Button type="submit" variant="secondary" disabled={pending} className="min-h-10">
          <UserPlus strokeWidth={1.5} />
          {pending ? "Создание…" : "Создать"}
        </Button>
      </div>
      {state.error && !touched && <p role="alert" className="text-sm text-destructive">{state.error}</p>}
      {state.ok && state.password && state.name && !touched && <OneTimePassword name={state.name} password={state.password} />}
    </form>
  );
}

/** Сброс пароля другому пользователю: подтверждение в диалоге, новый пароль — один раз. */
export function ResetPasswordButton({ name }: { name: string }) {
  const [shown, setShown] = useState<{ name: string; password: string } | null>(null);
  if (shown) return <OneTimePassword name={shown.name} password={shown.password} />;
  return (
    <ConfirmActionForm
      action={(fd) => resetUserPasswordAction(initial, fd)}
      title={`Сбросить пароль ${name}?`}
      description="Сессии пользователя будут отозваны. Новый пароль будет показан один раз — сразу передайте его владельцу."
      confirmLabel="Да, сбросить"
      successText={`Пароль ${name} сброшен`}
      onDone={(r) => {
        if (r?.ok && r.password && r.name) setShown({ name: r.name, password: r.password });
      }}
    >
      <input type="hidden" name="name" value={name} />
      <Button type="submit" variant="ghost" size="icon" title={`Сбросить пароль ${name}`}>
        <KeyRound strokeWidth={1.5} />
        <span className="sr-only">Сбросить пароль</span>
      </Button>
    </ConfirmActionForm>
  );
}

export function DeleteUserButton({ name }: { name: string }) {
  return (
    <ConfirmActionForm
      action={deleteUserAction}
      title={`Удалить пользователя ${name}?`}
      description="Его сессии перестанут действовать сразу."
      confirmLabel="Удалить"
      successText={`Пользователь ${name} удалён`}
    >
      <input type="hidden" name="name" value={name} />
      <Button type="submit" variant="ghost" size="icon" title={`Удалить ${name}`}>
        <Trash2 strokeWidth={1.5} />
        <span className="sr-only">Удалить</span>
      </Button>
    </ConfirmActionForm>
  );
}
