"use client";

import { useActionState } from "react";
import { LogIn } from "lucide-react";
import { loginAction, type FormState } from "@/lib/actions";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";

const initial: FormState = { error: null };

/** next — уже проверенный относительный путь (safeNextPath на странице). */
export function LoginForm({ next = "/" }: { next?: string }) {
  const [state, action, pending] = useActionState(loginAction, initial);
  const totpStep = Boolean(state.requiresTotp);
  const loginError = Boolean(state.error);
  return (
    <form action={action} className="space-y-5" aria-busy={pending}>
      <input type="hidden" name="next" value={next} />
      {totpStep ? <input type="hidden" name="step" value="totp" /> : null}
      {totpStep ? (
        <>
          <p className="text-sm text-muted-foreground">
            Пароль принят для {state.totpUser}. Введите код из приложения аутентификации.
          </p>
          <div className="space-y-2">
            <Label htmlFor="totp" className="c-label">Код 2FA</Label>
            <Input
              id="totp"
              name="totp"
              inputMode="numeric"
              autoComplete="one-time-code"
              placeholder="000000"
              maxLength={6}
              pattern="[0-9]{6}"
              required
              autoFocus
              aria-invalid={loginError || undefined}
              aria-describedby={loginError ? "login-error" : undefined}
              className="h-12 px-4"
              disabled={pending}
            />
          </div>
        </>
      ) : (
        <>
          <div className="space-y-2">
            <Label htmlFor="user" className="c-label">Пользователь</Label>
            <Input
              id="user"
              name="user"
              autoComplete="username"
              autoFocus
              required
              maxLength={64}
              spellCheck={false}
              autoCapitalize="none"
              aria-invalid={loginError || undefined}
              aria-describedby={loginError ? "login-error" : undefined}
              className="h-12 px-4"
              disabled={pending}
            />
          </div>
          <div className="space-y-2">
            <Label htmlFor="password" className="c-label">Пароль</Label>
            <Input
              id="password"
              name="password"
              type="password"
              autoComplete="current-password"
              required
              aria-invalid={loginError || undefined}
              aria-describedby={loginError ? "login-error" : undefined}
              className="h-12 px-4"
              disabled={pending}
            />
          </div>
        </>
      )}
      {loginError && (
        <p id="login-error" role="alert" className="text-sm text-destructive">
          {state.error}
        </p>
      )}
      <Button type="submit" size="lg" disabled={pending} className="min-h-12 w-full">
        {pending ? <span className="ascii-spin" aria-hidden /> : <LogIn strokeWidth={2} />}
        {pending ? "Проверка…" : totpStep ? "Подтвердить" : "Войти"}
      </Button>
      {totpStep && <a href={next === "/" ? "/login" : `/login?next=${encodeURIComponent(next)}`} className="block text-center font-mono text-xs text-muted-foreground underline underline-offset-4">Другой пользователь</a>}
    </form>
  );
}
