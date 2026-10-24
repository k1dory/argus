"use client";

import { useState } from "react";
import { Check, Copy } from "lucide-react";
import { prettyRaw, tokenizeJsonLine, type JsonToken } from "@/lib/shared/journal";

const TOKEN_CLASS: Record<JsonToken["t"], string> = {
  key: "text-fn",
  str: "text-str",
  num: "text-num",
  lit: "text-kw",
  punct: "text-[var(--text-tertiary)]",
  ws: "",
};

/** Кнопка копирования: иконка сменяется галочкой на 1.5 с, состояние объявляется скринридеру. */
export function CopyButton({ value, label }: { value: string; label: string }) {
  const [done, setDone] = useState<"ok" | "err" | null>(null);
  const copy = async () => {
    try {
      await navigator.clipboard.writeText(value);
      setDone("ok");
    } catch {
      setDone("err");
    }
    setTimeout(() => setDone(null), 1500);
  };
  return (
    <button
      type="button"
      onClick={copy}
      aria-label={label}
      className="inline-flex size-8 items-center justify-center rounded-md text-[var(--text-tertiary)] transition-colors duration-150 hover:bg-[var(--surface-elevated)] hover:text-muted-foreground"
    >
      {done === "ok" ? <Check strokeWidth={1.5} className="size-4 text-[var(--status-ok)]" aria-hidden /> : <Copy strokeWidth={1.5} className="size-4" aria-hidden />}
      <span className="sr-only" aria-live="polite">{done === "ok" ? "Скопировано" : done === "err" ? "Буфер обмена недоступен" : ""}</span>
    </button>
  );
}

/** Сырое событие в двойной рамке: вкладка-имя, язык, копирование, номера строк вне выделения. */
export function RawBlock({ raw, source }: { raw: string; source: string }) {
  if (raw.trim() === "") {
    return <p className="rounded-[10px] border border-dashed border-[var(--border-strong)] px-4 py-6 text-[13px] text-[var(--text-tertiary)]">Источник <span className="font-mono">{source}</span> не передал сырое событие — есть только нормализованные поля.</p>;
  }
  const pretty = prettyRaw(raw);
  const text = pretty ?? raw;
  const lines = text.split("\n");
  const gutter = String(lines.length).length;
  return (
    <div className="frame min-w-0">
      <figure className="frame__inner m-0">
        <figcaption className="flex h-10 items-center gap-2 border-b border-[var(--border)] pr-1 pl-4">
          <span className="font-mono text-[13px] text-muted-foreground">{pretty ? "raw.json" : "raw.log"}</span>
          <span className="truncate font-mono text-[12px] text-[var(--text-tertiary)]">{source}</span>
          <span className="ml-auto font-mono text-[12px] text-[var(--text-tertiary)]">{pretty ? "JSON" : "text"} · {lines.length} стр.</span>
          <CopyButton value={raw} label="Скопировать сырое событие" />
        </figcaption>
        <pre className="max-h-[420px] overflow-auto px-4 py-3 text-[12.5px] leading-[1.6]" tabIndex={0} aria-label="Сырое событие">
          <code className="font-mono" lang={pretty ? "json" : undefined}>
            {lines.map((line, i) => (
              <span key={i} className="block whitespace-pre">
                <span className="inline-block pr-4 text-right text-[var(--text-disabled)] select-none" style={{ width: `${gutter + 2}ch` }} aria-hidden>{i + 1}</span>
                {pretty
                  ? tokenizeJsonLine(line).map((t, j) => <span key={j} className={TOKEN_CLASS[t.t]}>{t.v}</span>)
                  : <span className="text-foreground">{line}</span>}
              </span>
            ))}
          </code>
        </pre>
      </figure>
    </div>
  );
}
