"use client";

import { useActionState, useEffect, useState } from "react";
import { KeyRound } from "lucide-react";
import { toast } from "sonner";
import { changePasswordAction, type FormState } from "@/lib/actions";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";

const initial: FormState = { error: null };

/** Смена пароля текущего локального пользователя. force — стартовый пароль
 *  admin ещё не сменён: остальные разделы заблокированы до смены. */
export function PasswordForm({ force = false }: { force?: boolean }) {
  const [state, action, pending] = useActionState(changePasswordAction, initial);
  const [touchedFor, setTouchedFor] = useState<FormState | null>(null);
  const touched = touchedFor === state; // новый ввод после ответа прячет ok/ошибку
  useEffect(() => {
    if (state.error) toast.error(state.error);
    else if (state.ok) toast.success("Пароль изменён");
  }, [state]);
  const onChange = () => setTouchedFor(state);
  return (
    <form action={action} className="space-y-5" aria-busy={pending || undefined}>
      {force && !state.ok && (
        <p role="alert" className="border border-[var(--status-warn)]/50 bg-[var(--surface-deep)] px-3 py-2 text-xs">
          Стартовый пароль администратора нужно сменить — до этого остальные действия консоли заблокированы.
        </p>
      )}
      <div className="space-y-2">
        <Label htmlFor="current" className="c-label">
          Текущий пароль
        </Label>
        <Input id="current" name="current" type="password" autoComplete="current-password" required className="h-12 px-4" onChange={onChange} />
      </div>
      <div className="space-y-2">
        <Label htmlFor="next" className="c-label">
          Новый пароль
        </Label>
        <Input id="next" name="next" type="password" autoComplete="new-password" required className="h-12 px-4" onChange={onChange} />
      </div>
      <div className="space-y-2">
        <Label htmlFor="confirm" className="c-label">
          Подтверждение
        </Label>
        <Input id="confirm" name="confirm" type="password" autoComplete="new-password" required className="h-12 px-4" onChange={onChange} />
      </div>
      {state.error && !touched && (
        <p role="alert" className="text-sm text-destructive">
          {state.error}
        </p>
      )}
      {state.ok && !touched && (
        <p role="status" className="text-sm text-[var(--status-ok)]">
          Пароль изменён{force ? " — консоль разблокирована" : ""}
        </p>
      )}
      <Button type="submit" size="lg" disabled={pending} className="min-h-12 w-full sm:w-auto">
        <KeyRound strokeWidth={2} />
        {pending ? "Сохранение…" : "Сменить пароль"}
      </Button>
    </form>
  );
}
