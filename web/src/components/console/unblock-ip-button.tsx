"use client";

import { useActionState, useEffect, useId, useState } from "react";
import { ShieldOff } from "lucide-react";
import { toast } from "sonner";
import type { FormState } from "@/lib/actions";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import {
  AlertDialog,
  AlertDialogCancel,
  AlertDialogContent,
  AlertDialogDescription,
  AlertDialogFooter,
  AlertDialogHeader,
  AlertDialogTitle,
  AlertDialogTrigger,
} from "@/components/ui/alert-dialog";

const initial: FormState = { error: null };

export type UnblockAction = (prev: FormState, formData: FormData) => Promise<FormState>;

/**
 * Снятие активной блокировки. Server action (`unblockIpAction` из
 * incident-actions, поля ip и reason) передаётся страницей.
 */
export function UnblockIpButton({ ip, incidentId, action }: { ip: string; incidentId?: string; action: UnblockAction }) {
  const [state, run, pending] = useActionState(action, initial);
  const [open, setOpen] = useState(false);
  const [reason, setReason] = useState("");
  const reasonId = useId();

  // Тост — внешняя система; при успехе вместо диалога рендерится «снята».
  useEffect(() => {
    if (state.ok && state.warning) toast.warning(`Блокировка ${ip} снята с оговоркой`, { description: state.warning, duration: Infinity });
    else if (state.ok) toast.success(`Блокировка ${ip} снята`);
    else if (state.error) toast.error("Не удалось снять блокировку", { description: state.error });
  }, [state, ip]);

  if (state.ok && state.warning) return <span role="alert" className="font-mono text-xs text-[var(--status-warn)]">снята, но: {state.warning}</span>;
  if (state.ok) return <span className="font-mono text-xs text-[var(--status-ok)]">снята</span>;

  return (
    <AlertDialog open={open} onOpenChange={(o) => !pending && setOpen(o)}>
      <AlertDialogTrigger asChild>
        <Button type="button" variant="ghost" size="sm" disabled={pending}>
          <ShieldOff strokeWidth={1.5} />
          Снять блокировку
        </Button>
      </AlertDialogTrigger>
      <AlertDialogContent>
        <form action={run} className="space-y-4" aria-busy={pending}>
          <input type="hidden" name="ip" value={ip} />
          {incidentId && <input type="hidden" name="incident_id" value={incidentId} />}
          <AlertDialogHeader>
            <AlertDialogTitle>Снять блокировку</AlertDialogTitle>
            <AlertDialogDescription>
              Адрес <span className="font-mono text-foreground">{ip}</span> будет разблокирован на всех исполнителях. Причина попадёт в аудит.
            </AlertDialogDescription>
          </AlertDialogHeader>
          <div className="space-y-2">
            <Label htmlFor={reasonId} className="c-label">Причина (обязательно)</Label>
            <Input id={reasonId} name="reason" value={reason} onChange={(e) => setReason(e.target.value)} required minLength={3} maxLength={200} placeholder="ложное срабатывание, адрес партнёра…" className="h-10 px-3" disabled={pending} autoFocus />
          </div>
          {state.error && <p role="alert" className="text-xs text-destructive">{state.error}</p>}
          <AlertDialogFooter>
            <AlertDialogCancel type="button" disabled={pending}>Отмена</AlertDialogCancel>
            <Button type="submit" disabled={pending || reason.trim().length < 3} aria-busy={pending}>
              {pending ? <span className="ascii-spin" aria-hidden /> : <ShieldOff strokeWidth={1.5} />}
              {pending ? "Снимаю…" : "Снять"}
            </Button>
          </AlertDialogFooter>
        </form>
      </AlertDialogContent>
    </AlertDialog>
  );
}
