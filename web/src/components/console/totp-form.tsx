"use client";

import { useActionState, useEffect, useState } from "react";
import { QrCode, ShieldCheck, ShieldOff } from "lucide-react";
import { toast } from "sonner";
import {
  beginTotpAction,
  confirmTotpAction,
  disableTotpAction,
  type FormState,
  type TotpEnrollState,
} from "@/lib/actions";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";

const initialEnroll: TotpEnrollState = { error: null };
const initial: FormState = { error: null };

function CodeInput({ id, onChange }: { id: string; onChange?: () => void }) {
  return (
    <Input
      id={id}
      name="code"
      inputMode="numeric"
      autoComplete="one-time-code"
      placeholder="000000"
      maxLength={6}
      required
      className="h-12 w-40 px-4"
      onChange={onChange}
    />
  );
}

/** Включение TOTP: сгенерировать секрет → отсканировать QR → подтвердить кодом. */
function EnrollFlow({ user }: { user: string }) {
  const [enroll, generate, generating] = useActionState(beginTotpAction, initialEnroll);
  const [confirm, confirmAction, confirming] = useActionState(confirmTotpAction, initial);
  const [touchedFor, setTouchedFor] = useState<FormState | null>(null);
  const touched = touchedFor === confirm;
  useEffect(() => {
    if (confirm.error) toast.error(confirm.error);
    else if (confirm.ok) toast.success("TOTP включён");
  }, [confirm]);

  if (confirm.ok) {
    return (
      <p role="status" className="text-sm text-[var(--status-ok)]">
        TOTP включён для {user} — при входе понадобится код из приложения
      </p>
    );
  }

  return (
    <div className="space-y-5">
      {!enroll.secret && (
        <form action={generate} aria-busy={generating || undefined}>
          <Button type="submit" variant="secondary" disabled={generating}>
            <QrCode strokeWidth={1.5} />
            {generating ? "Генерация…" : "Сгенерировать секрет"}
          </Button>
        </form>
      )}
      {enroll.secret && (
        <>
          <div className="flex flex-wrap items-start gap-5">
            {enroll.qrDataUrl && (
              // eslint-disable-next-line @next/next/no-img-element
              <img
                src={enroll.qrDataUrl}
                alt="QR-код для приложения-аутентификатора"
                width={160}
                height={160}
                className="border border-border bg-white p-2"
              />
            )}
            <div className="space-y-2">
              <p className="max-w-md text-sm text-muted-foreground">
                Отсканируйте QR в приложении (Google Authenticator, FreeOTP, Aegis)
                или введите секрет вручную. Учётная запись: <span className="font-mono">{user}</span>.
              </p>
              <code className="block max-w-md border border-border bg-[var(--surface-deep)] px-3 py-2 font-mono text-xs break-all">
                {enroll.secret}
              </code>
            </div>
          </div>
          <form action={confirmAction} className="flex flex-wrap items-end gap-3" aria-busy={confirming || undefined}>
            <div className="space-y-2">
              <Label htmlFor="totp-confirm" className="c-label">
                Код из приложения
              </Label>
              <CodeInput id="totp-confirm" onChange={() => setTouchedFor(confirm)} />
            </div>
            <Button type="submit" disabled={confirming} className="min-h-12">
              <ShieldCheck strokeWidth={1.5} />
              {confirming ? "Проверка…" : "Подтвердить и включить"}
            </Button>
          </form>
        </>
      )}
      {(enroll.error || (confirm.error && !touched)) && (
        <p role="alert" className="text-sm text-destructive">
          {enroll.error ?? confirm.error}
        </p>
      )}
    </div>
  );
}

/** Отключение требует текущий пароль и код — украденной сессии недостаточно. */
function DisableForm() {
  const [state, action, pending] = useActionState(disableTotpAction, initial);
  const [touchedFor, setTouchedFor] = useState<FormState | null>(null);
  const touched = touchedFor === state;
  useEffect(() => {
    if (state.error) toast.error(state.error);
    else if (state.ok) toast.success("TOTP отключён");
  }, [state]);

  if (state.ok) {
    return (
      <p role="status" className="text-sm text-muted-foreground">
        TOTP отключён
      </p>
    );
  }

  return (
    <form action={action} className="flex flex-wrap items-end gap-3" aria-busy={pending || undefined}>
      <div className="space-y-2">
        <Label htmlFor="totp-password" className="c-label">
          Текущий пароль
        </Label>
        <Input id="totp-password" name="password" type="password" autoComplete="current-password" required className="h-12 w-56 px-4" onChange={() => setTouchedFor(state)} />
      </div>
      <div className="space-y-2">
        <Label htmlFor="totp-disable" className="c-label">
          Код из приложения
        </Label>
        <CodeInput id="totp-disable" onChange={() => setTouchedFor(state)} />
      </div>
      <Button type="submit" variant="secondary" disabled={pending} className="min-h-12">
        <ShieldOff strokeWidth={1.5} />
        {pending ? "Проверка…" : "Отключить 2FA"}
      </Button>
      {state.error && !touched && (
        <p role="alert" className="w-full text-sm text-destructive">
          {state.error}
        </p>
      )}
    </form>
  );
}

export function TotpControls({ enabled, user }: { enabled: boolean; user: string }) {
  return enabled ? <DisableForm /> : <EnrollFlow user={user} />;
}
