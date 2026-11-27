"use client";

import { useEffect, useId, useRef, useState } from "react";
import { CircleHelp, X } from "lucide-react";
import { QUERY_FIELDS, QUERY_OPERATORS } from "@/lib/shared/query-fields";

/**
 * Шпаргалка языка запросов: кнопка «?» в поле запроса открывает панель с
 * полями (что это, пример) и операторами. Пример кликабелен — onPick
 * дописывает его в запрос. Список полей — lib/shared/query-fields: один для
 * журнала и поиска. Закрывается Esc, кликом мимо и повторным нажатием.
 */
export function QuerySyntaxHelp({ index, onPick }: { index: "events" | "alerts"; onPick: (term: string) => void }) {
  const [open, setOpen] = useState(false);
  const id = useId();
  const root = useRef<HTMLDivElement>(null);
  const button = useRef<HTMLButtonElement>(null);

  useEffect(() => {
    if (!open) return;
    const onKey = (e: KeyboardEvent) => {
      if (e.key === "Escape") {
        setOpen(false);
        button.current?.focus();
      }
    };
    const onDown = (e: MouseEvent) => {
      if (root.current && !root.current.contains(e.target as Node)) setOpen(false);
    };
    document.addEventListener("keydown", onKey);
    document.addEventListener("mousedown", onDown);
    return () => {
      document.removeEventListener("keydown", onKey);
      document.removeEventListener("mousedown", onDown);
    };
  }, [open]);

  const pick = (t: string) => onPick(t);
  const ex = "rounded-[4px] px-1 text-left font-mono text-[12px] text-[var(--ring)] hover:bg-[var(--surface-elevated)] hover:underline focus-visible:outline-2 focus-visible:outline-[var(--ring)]";

  return (
    <div ref={root} className="relative shrink-0">
      <button
        ref={button}
        type="button"
        aria-label="Синтаксис запроса"
        aria-expanded={open}
        aria-controls={id}
        title="Синтаксис запроса"
        onClick={() => setOpen(!open)}
        className="inline-flex size-7 items-center justify-center rounded-md text-[var(--text-tertiary)] transition-colors hover:bg-[var(--surface-elevated)] hover:text-foreground aria-expanded:text-[var(--ring)]"
      >
        <CircleHelp strokeWidth={1.5} className="size-4" aria-hidden />
      </button>
      {open && (
        <div
          id={id}
          role="dialog"
          aria-label="Синтаксис запроса"
          className="absolute top-full right-0 z-30 mt-2 max-h-[70vh] w-[min(40rem,calc(100vw-2rem))] overflow-y-auto rounded-[10px] border border-[var(--border-strong)] bg-[var(--surface-elevated)] p-4 shadow-[0_12px_32px_rgb(0_0_0/0.45)]"
        >
          <div className="mb-3 flex items-center justify-between gap-3">
            <p className="text-[13px] font-semibold text-foreground">Как писать запрос</p>
            <button type="button" aria-label="Закрыть" onClick={() => setOpen(false)} className="inline-flex size-6 items-center justify-center rounded-md text-[var(--text-tertiary)] hover:text-foreground">
              <X strokeWidth={1.5} className="size-3.5" aria-hidden />
            </button>
          </div>
          <p className="mb-3 text-[12px] leading-relaxed text-muted-foreground">
            Условия через пробел должны выполняться все сразу. Нажмите на пример — он добавится в запрос.
          </p>
          <div className="grid gap-5 sm:grid-cols-[minmax(0,3fr)_minmax(0,2fr)]">
            <section aria-label="Поля">
              <h3 className="mb-1.5 text-[12px] font-medium text-[var(--text-tertiary)]">Поля</h3>
              <table className="w-full text-[12px]">
                <tbody>
                  {QUERY_FIELDS[index].map((f) => (
                    <tr key={f.field} className="border-t border-[var(--border)] align-top">
                      <td className="py-1 pr-2 font-mono text-foreground">{f.field}</td>
                      <td className="py-1 pr-2 text-muted-foreground">{f.label}</td>
                      <td className="py-1"><button type="button" className={ex} onClick={() => pick(f.example)}>{f.example}</button></td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </section>
            <section aria-label="Операторы">
              <h3 className="mb-1.5 text-[12px] font-medium text-[var(--text-tertiary)]">Операторы</h3>
              <ul className="flex flex-col text-[12px]">
                {QUERY_OPERATORS.map((o) => (
                  <li key={o.op} className="border-t border-[var(--border)] py-1">
                    <div className="flex items-baseline gap-2">
                      <span className="w-12 shrink-0 font-mono text-foreground">{o.op}</span>
                      <span className="text-muted-foreground">{o.label}</span>
                    </div>
                    <button type="button" className={`${ex} ml-12`} onClick={() => pick(o.example)}>{o.example}</button>
                  </li>
                ))}
              </ul>
            </section>
          </div>
        </div>
      )}
    </div>
  );
}

