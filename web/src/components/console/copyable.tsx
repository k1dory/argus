"use client";

import Link from "next/link";
import { Copy } from "lucide-react";
import { toast } from "sonner";
import { cn } from "@/lib/utils";

/**
 * Значение-ссылка с копированием: клик по тексту — переход (href), клик по
 * иконке — в буфер + тост. Без href — копирование по клику на текст.
 */
export function Copyable({
  value,
  href,
  label,
  className,
  children,
}: {
  value: string;
  href?: string;
  /** Что сказать в тосте: «IP скопирован» */
  label?: string;
  className?: string;
  children?: React.ReactNode;
}) {
  const copy = async () => {
    try {
      await navigator.clipboard.writeText(value);
      toast.success(`${label ?? "Значение"} скопировано`, { description: value });
    } catch {
      toast.error("Буфер обмена недоступен", { description: "Скопируйте вручную: " + value });
    }
  };
  const text = children ?? value;
  return (
    <span className={cn("group/copy inline-flex max-w-full items-center gap-1 font-mono", className)}>
      {href ? (
        <Link href={href} className="truncate text-[var(--ring)] hover:underline" title={value}>
          {text}
        </Link>
      ) : (
        <button type="button" onClick={copy} className="truncate text-left hover:underline" title={`Скопировать ${value}`}>
          {text}
        </button>
      )}
      <button
        type="button"
        onClick={copy}
        aria-label={`Скопировать ${label ? label.toLowerCase() + " " : ""}${value}`}
        className="shrink-0 text-muted-foreground opacity-0 transition-opacity group-hover/copy:opacity-100 hover:text-foreground focus-visible:opacity-100"
      >
        <Copy strokeWidth={1.5} className="h-3 w-3" />
      </button>
    </span>
  );
}
