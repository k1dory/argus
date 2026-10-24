"use client";

import { useActionState, useEffect, useId, useState } from "react";
import { ShieldBan } from "lucide-react";
import { toast } from "sonner";
import type { FormState } from "@/lib/actions";
import { blockIpAction } from "@/lib/incident-actions";
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

/**
 * Обратный канал: заблокировать адрес (active-response Wazuh / NGFW).
 * Подтверждение в AlertDialog с показом адреса и обязательной причиной —
 * она уходит в журнал реагирования и аудит (поля формы: incident_id, ip, reason).
 */
export function BlockIpButton({ incidentId, ip }: { incidentId: string; ip: string }) {
  const [state, action, pending] = useActionState(blockIpAction, initial);
  const [open, setOpen] = useState(false);
  const [reason, setReason] = useState("");
  const reasonId = useId();

  // Тост — внешняя система; диалог при успехе исчезает сам (ниже рендерится строка вместо него).
  useEffect(() => {
    if (state.ok) toast.success(`Адрес ${ip} заблокирован`, { description: "детали — в журнале реагирования" });
    else if (state.error) toast.error("Блокировка не выполнена", { description: state.error });
  }, [state, ip]);

  if (state.ok) {
    return <span className="font-mono text-xs text-[var(--status-ok)]">{ip} заблокирован — детали в журнале реагирования</span>;
  }

  return (
    <div className="flex flex-wrap items-center gap-3">
      <AlertDialog open={open} onOpenChange={(o) => !pending && setOpen(o)}>
        <AlertDialogTrigger asChild>
          <Button type="button" variant="secondary" size="sm" disabled={pending}>
            <ShieldBan strokeWidth={1.5} />
            Заблокировать {ip}
          </Button>
        </AlertDialogTrigger>
        <AlertDialogContent>
          <form action={action} className="space-y-4" aria-busy={pending}>
            <input type="hidden" name="incident_id" value={incidentId} />
            <input type="hidden" name="ip" value={ip} />
            <AlertDialogHeader>
              <AlertDialogTitle>Блокировка адреса</AlertDialogTitle>
              <AlertDialogDescription>
                Адрес <span className="font-mono text-foreground">{ip}</span> будет заблокирован через active-response Wazuh и API NGFW на TTL движка. Действие попадёт в аудит от вашего имени.
              </AlertDialogDescription>
            </AlertDialogHeader>
            <div className="space-y-2">
              <Label htmlFor={reasonId} className="c-label">Причина (обязательно)</Label>
              <Input
                id={reasonId}
                name="reason"
                value={reason}
                onChange={(e) => setReason(e.target.value)}
                required
                minLength={3}
                maxLength={500}
                placeholder="перебор паролей с этого адреса, INC-…"
                className="h-10 px-3"
                disabled={pending}
                autoFocus
              />
            </div>
            {state.error && (
              <p role="alert" className="text-xs text-destructive">
                {state.error}
              </p>
            )}
            <AlertDialogFooter>
              <AlertDialogCancel type="button" disabled={pending}>Отмена</AlertDialogCancel>
              <Button type="submit" variant="destructive" disabled={pending || reason.trim().length < 3} aria-busy={pending}>
                {pending ? <span className="ascii-spin" aria-hidden /> : <ShieldBan strokeWidth={1.5} />}
                {pending ? "Блокировка…" : `Да, заблокировать ${ip}`}
              </Button>
            </AlertDialogFooter>
          </form>
        </AlertDialogContent>
      </AlertDialog>
      {state.error && <span role="alert" className="font-mono text-xs text-destructive">{state.error}</span>}
    </div>
  );
}
