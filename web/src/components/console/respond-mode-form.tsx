"use client";

import { useActionState, useRef, useState } from "react";
import { ShieldAlert } from "lucide-react";
import { Button } from "@/components/ui/button";
import { Label } from "@/components/ui/label";
import { RadioGroup, RadioGroupItem } from "@/components/ui/radio-group";
import {
  AlertDialog,
  AlertDialogAction,
  AlertDialogCancel,
  AlertDialogContent,
  AlertDialogDescription,
  AlertDialogFooter,
  AlertDialogHeader,
  AlertDialogTitle,
} from "@/components/ui/alert-dialog";
import type { FormState } from "@/lib/actions";
import { RESPOND_MODES, type RespondMode, type RespondModeFrom } from "@/lib/shared/respond";
import { setRespondModeAction } from "@/lib/respond-actions";
import { cn } from "@/lib/utils";

/**
 * Переключатель режима реагирования. requested — что уже записано из консоли,
 * но движок ещё не подтвердил. disabled — движок не отвечает: менять режим
 * нельзя, потому что движок не подтвердит его и не покажет, что действует сейчас.
 * Переход в IPS (автоблокировка) — только после подтверждения.
 */
export function RespondModeForm({
  current,
  from,
  requested,
  disabled = false,
  disabledReason,
}: {
  current: RespondMode;
  from: RespondModeFrom;
  requested?: RespondMode | "" | null;
  disabled?: boolean;
  disabledReason?: string;
}) {
  const [state, action, pending] = useActionState(setRespondModeAction, { error: null } as FormState);
  const [selected, setSelected] = useState<RespondMode>((requested || current) as RespondMode);
  const [confirmOpen, setConfirmOpen] = useState(false);
  const confirmed = useRef(false);
  const formRef = useRef<HTMLFormElement>(null);
  const waiting = requested !== undefined && requested !== null && requested !== current && (requested !== "" || from === "console");
  const locked = disabled || pending;

  const onSubmit = (e: React.FormEvent<HTMLFormElement>) => {
    const submitter = (e.nativeEvent as SubmitEvent).submitter as HTMLButtonElement | null;
    const isReset = submitter?.name === "reset";
    if (disabled) {
      e.preventDefault();
      return;
    }
    if (!isReset && selected === "ips" && current !== "ips" && !confirmed.current) {
      e.preventDefault();
      setConfirmOpen(true);
      return;
    }
    confirmed.current = false;
  };

  return (
    <form ref={formRef} action={action} onSubmit={onSubmit} className="space-y-4" aria-describedby={disabled && disabledReason ? "respond-mode-locked" : undefined}>
      <fieldset className="space-y-2" disabled={locked}>
        <legend className="sr-only">Режим реагирования</legend>
        <RadioGroup name="mode" value={selected} onValueChange={(v) => setSelected(v as RespondMode)} className="gap-2" disabled={locked}>
          {(Object.keys(RESPOND_MODES) as RespondMode[]).map((m) => {
            const ips = m === "ips";
            const active = m === current && !disabled; // движок не ответил — какой режим действует, неизвестно
            return (
              <Label
                key={m}
                htmlFor={`mode-${m}`}
                className={cn(
                  "flex cursor-pointer items-start gap-3 rounded-md border bg-[var(--surface-deep)] px-3 py-2.5 font-normal transition-colors",
                  ips ? "border-[var(--status-err)]/30" : "border-border",
                  selected === m && "border-[var(--ring)]/60 bg-[var(--surface-elevated)]",
                  locked && "cursor-not-allowed opacity-70",
                )}
              >
                <RadioGroupItem id={`mode-${m}`} value={m} className="mt-1" />
                <span className="min-w-0">
                  <span className="flex flex-wrap items-center gap-2 text-sm font-medium text-foreground">
                    {ips && <ShieldAlert className="size-4 text-[var(--status-err)]" strokeWidth={1.5} aria-hidden />}
                    {RESPOND_MODES[m].label}
                    {active && <span className="text-[12px] font-normal text-muted-foreground">· действует сейчас</span>}
                  </span>
                  <span className="mt-0.5 block text-[13px] leading-snug text-muted-foreground">{RESPOND_MODES[m].hint}</span>
                </span>
              </Label>
            );
          })}
        </RadioGroup>
      </fieldset>
      <div className="flex flex-wrap items-center gap-3">
        <Button type="submit" disabled={locked}>{pending ? "Сохранение…" : "Применить"}</Button>
        {from === "console" && (
          <Button type="submit" name="reset" value="1" variant="secondary" disabled={locked}>Вернуть режим из конфига</Button>
        )}
      </div>
      {disabled && disabledReason && (
        <p id="respond-mode-locked" className="text-[13px] text-[var(--status-warn)]">{disabledReason}</p>
      )}
      <p className="text-[13px] text-muted-foreground">
        Источник режима: {from === "console" ? "консоль (сохраняется после перезапуска движка)" : <>файл конфигурации <span className="font-mono">argus.analyst.yml</span></>}
        {waiting && ` · запрошено «${requested ? RESPOND_MODES[requested as RespondMode].label : "из конфига"}», движок применит в течение цикла`}
      </p>
      {state.error && <p role="alert" className="text-sm text-destructive">{state.error}</p>}
      {state.ok && <p role="status" className="text-sm text-[var(--status-ok)]">Сохранено — движок подхватит режим на следующем цикле</p>}

      <AlertDialog open={confirmOpen} onOpenChange={setConfirmOpen}>
        <AlertDialogContent>
          <AlertDialogHeader>
            <AlertDialogTitle>Включить автоблокировку (IPS)?</AlertDialogTitle>
            <AlertDialogDescription>
              Движок начнёт сам блокировать адреса на NGFW и агентах по правилам с блоком реагирования — без участия оператора.
              Адреса из списка «Никогда не блокируются» и частные сети не затрагиваются.
            </AlertDialogDescription>
          </AlertDialogHeader>
          <AlertDialogFooter>
            <AlertDialogCancel>Отмена</AlertDialogCancel>
            <AlertDialogAction
              onClick={() => {
                confirmed.current = true;
                setConfirmOpen(false);
                formRef.current?.requestSubmit();
              }}
            >
              Включить IPS
            </AlertDialogAction>
          </AlertDialogFooter>
        </AlertDialogContent>
      </AlertDialog>
    </form>
  );
}
