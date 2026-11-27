"use client";

import { useActionState, useState } from "react";
import { Eye, EyeOff, LogIn } from "lucide-react";
import { loginAction, type FormState } from "@/lib/actions";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";

const initial: FormState = { error: null };
const LABEL = "text-sm font-medium text-foreground";

/** next — уже проверенный относительный путь (safeNextPath на странице). */
export function LoginForm({ next = "/" }: { next?: string }) {
  const [state, action, pending] = useActionState(loginAction, initial);
  return (
    <form action={action} className="space-y-5" aria-busy={pending}>
      <LoginFields state={state} pending={pending} next={next} />
    </form>
  );
}

/**
 * Поля формы входа по состоянию action. Вынесены отдельно, чтобы рендер
 * после ошибки проверялся тестом: React 19 сбрасывает поля формы после
 * action, поэтому логин возвращается в state.user и ставится defaultValue —
 * иначе после неверного пароля его приходится набирать заново.
 */
export function LoginFields({ state, pending = false, next = "/" }: { state: FormState; pending?: boolean; next?: string }) {
  const totpStep = Boolean(state.requiresTotp);
  const loginError = Boolean(state.error);
  const [showPassword, setShowPassword] = useState(false);
  const [capsLock, setCapsLock] = useState(false);
  const onKey = (e: React.KeyboardEvent<HTMLInputElement>) => setCapsLock(e.getModifierState?.("CapsLock") ?? false);
  const describedBy = [loginError ? "login-error" : "", capsLock ? "login-caps" : ""].filter(Boolean).join(" ") || undefined;
  return (
    <>
      <input type="hidden" name="next" value={next} />
      {totpStep ? <input type="hidden" name="step" value="totp" /> : null}
      {totpStep ? (
        <>
          <p className="text-sm text-muted-foreground">
            Пароль принят для <span className="font-mono text-foreground">{state.totpUser}</span>. Введите код из приложения аутентификации.
          </p>
          <div className="space-y-2">
            <Label htmlFor="totp" className={LABEL}>Код 2FA</Label>
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
              className="h-12 px-4 font-mono"
              disabled={pending}
            />
          </div>
        </>
      ) : (
        <>
          <div className="space-y-2">
            <Label htmlFor="user" className={LABEL}>Пользователь</Label>
            <Input
              // key: при новом логине из state поле пересоздаётся с ним, даже если React уже сбросил форму.
              key={state.user ?? ""}
              id="user"
              name="user"
              defaultValue={state.user ?? ""}
              autoComplete="username"
              autoFocus={!state.user}
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
            <Label htmlFor="password" className={LABEL}>Пароль</Label>
            <div className="relative">
              <Input
                id="password"
                name="password"
                type={showPassword ? "text" : "password"}
                autoComplete="current-password"
                autoFocus={Boolean(state.user)}
                required
                onKeyUp={onKey}
                onKeyDown={onKey}
                aria-invalid={loginError || undefined}
                aria-describedby={describedBy}
                className="h-12 pr-12 pl-4"
                disabled={pending}
              />
              <button
                type="button"
                onClick={() => setShowPassword((v) => !v)}
                aria-pressed={showPassword}
                aria-label="Показать пароль"
                title={showPassword ? "Скрыть пароль" : "Показать пароль"}
                className="absolute inset-y-0 right-0 flex w-12 items-center justify-center text-muted-foreground hover:text-foreground"
              >
                {showPassword ? <EyeOff className="size-4" strokeWidth={1.5} aria-hidden /> : <Eye className="size-4" strokeWidth={1.5} aria-hidden />}
              </button>
            </div>
            {capsLock && <p id="login-caps" className="text-[12px] text-[var(--status-warn)]">Включён Caps Lock</p>}
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
      {totpStep && <a href={next === "/" ? "/login" : `/login?next=${encodeURIComponent(next)}`} className="block text-center text-[13px] text-muted-foreground underline underline-offset-4 hover:text-foreground">Другой пользователь</a>}
    </>
  );
}
