"use client";

import { useState, useTransition } from "react";
import { toast } from "sonner";
import { actionErrorText } from "@/lib/shared/action-error";
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

export type ActionResult = void | { error: string | null; ok?: boolean } | undefined;
/** Plain action (`(fd) => void`) или action, возвращающий FormState — оба контракта поддерживаются. */
export type PlainAction<R extends ActionResult = ActionResult> = (formData: FormData) => R | Promise<R>;

function resultError(r: ActionResult): string | null {
  return r && typeof r === "object" && "error" in r && r.error ? r.error : null;
}

/** Общий прогон действия: ошибка результата или исключения → toast + inline; навигационные исключения — наружу. */
async function runAction<R extends ActionResult>(
  action: PlainAction<R>,
  fd: FormData,
  setError: (e: string | null) => void,
  successText: string | undefined,
  onDone: ((r: R) => void) | undefined,
): Promise<void> {
  setError(null);
  try {
    const r = await action(fd);
    const err = resultError(r);
    if (err) {
      setError(err);
      toast.error(err);
      return;
    }
    if (successText) toast.success(successText);
    onDone?.(r);
  } catch (e) {
    const msg = actionErrorText(e);
    if (!msg) throw e; // redirect / notFound
    setError(msg);
    toast.error(msg);
  }
}

/**
 * Форма для plain server action (`(formData) => void | FormState`): обратная
 * связь тостом и inline, кнопки недоступны на время выполнения. redirect()
 * внутри action пробрасывается Next как исключение — его не считаем ошибкой.
 */
export function ActionForm<R extends ActionResult = ActionResult>({
  action,
  successText,
  className,
  children,
  onDone,
}: {
  action: PlainAction<R>;
  successText?: string;
  className?: string;
  children: React.ReactNode;
  onDone?: (result: R) => void;
}) {
  const [pending, start] = useTransition();
  const [error, setError] = useState<string | null>(null);
  const submit = (fd: FormData) => start(() => runAction(action, fd, setError, successText, onDone));
  return (
    <form action={submit} className={className} aria-busy={pending}>
      <fieldset disabled={pending} className="contents">
        {children}
      </fieldset>
      {error && (
        <p role="alert" className="mt-2 text-xs text-destructive">
          {error}
        </p>
      )}
    </form>
  );
}

/**
 * Разрушительное действие с подтверждением в AlertDialog (не window.confirm):
 * фокус внутри, Esc — отмена. children — hidden-поля и кнопка-триггер.
 * Данные формы снимаются при submit, действие уходит только по кнопке диалога.
 */
export function ConfirmActionForm<R extends ActionResult = ActionResult>({
  action,
  title,
  description,
  confirmLabel = "Да, выполнить",
  successText,
  className,
  children,
  onDone,
}: {
  action: PlainAction<R>;
  title: string;
  description?: React.ReactNode;
  confirmLabel?: string;
  successText?: string;
  className?: string;
  children: React.ReactNode;
  onDone?: (result: R) => void;
}) {
  const [open, setOpen] = useState(false);
  const [pending, start] = useTransition();
  const [error, setError] = useState<string | null>(null);
  const [fd, setFd] = useState<FormData | null>(null);

  const confirm = () => {
    if (!fd) return;
    start(() =>
      runAction(action, fd, setError, successText, (r) => {
        setOpen(false);
        onDone?.(r);
      }),
    );
  };

  return (
    <>
      <form
        className={className}
        aria-busy={pending}
        onSubmit={(e) => {
          e.preventDefault();
          setFd(new FormData(e.currentTarget));
          setError(null);
          setOpen(true);
        }}
      >
        <fieldset disabled={pending} className="contents">
          {children}
        </fieldset>
      </form>
      <AlertDialog open={open} onOpenChange={(o) => !pending && setOpen(o)}>
        <AlertDialogContent>
          <AlertDialogHeader>
            <AlertDialogTitle>{title}</AlertDialogTitle>
            {description && <AlertDialogDescription>{description}</AlertDialogDescription>}
          </AlertDialogHeader>
          {error && (
            <p role="alert" className="text-xs text-destructive">
              {error}
            </p>
          )}
          <AlertDialogFooter>
            <AlertDialogCancel disabled={pending}>Отмена</AlertDialogCancel>
            <AlertDialogAction disabled={pending} aria-busy={pending} onClick={(e) => { e.preventDefault(); confirm(); }}>
              {pending ? <span className="ascii-spin" aria-hidden /> : null}
              {pending ? "Выполняю…" : confirmLabel}
            </AlertDialogAction>
          </AlertDialogFooter>
        </AlertDialogContent>
      </AlertDialog>
    </>
  );
}
