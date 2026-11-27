"use client";

import { useState } from "react";
import { ChevronRight } from "lucide-react";
import { cn } from "@/lib/utils";
import type { IndexKey } from "@/lib/search";
import { SEVERITY, severityTone } from "@/lib/shared/severity";
import { formatTs } from "@/lib/shared/time";
import { Copyable } from "./copyable";
import { searchHref } from "@/lib/shared/search-href";
import { TONE_CLASS } from "./tone";

function pretty(raw: unknown): string {
  if (typeof raw !== "string" || raw === "") return "";
  try {
    return JSON.stringify(JSON.parse(raw), null, 2);
  } catch {
    return raw;
  }
}

/** Значения-ссылки: IP → поиск по srcip, правило → поиск по rule, агент → карточка агентов. */
function linkFor(index: IndexKey, key: string, value: string): { href: string; label: string } | null {
  if (!value || value === "0") return null;
  if (index === "alerts") {
    if (key === "srcip") return { href: searchHref.srcip(value), label: "IP" };
    if (key === "rule_id") return { href: searchHref.rule(value), label: "Правило" };
    if (key === "agent_name") return { href: "/wazuh/agents", label: "Агент" };
  } else {
    if (key === "src_ip") return { href: searchHref.eventSrc(value), label: "IP" };
    if (key === "source") return { href: searchHref.source(value), label: "Источник" };
    if (key === "actor_name") return { href: searchHref.actor(value), label: "Субъект" };
    if (key === "node") return { href: searchHref.node(value), label: "Хост" };
  }
  return null;
}

/** Короткое время строки: «11-25 06:12:41» — «UTC» стоит в заголовке колонки. */
const shortTs = (s: string): string => {
  const full = formatTs(s);
  return /^\d{4}-/.test(full) ? full.slice(5, 19) : full;
};

/**
 * Строка выдачи: краткие колонки; раскрытие — кнопкой со стрелкой (24×24,
 * подпись с временем и действием) или кликом по любому месту строки, кроме
 * ссылок. В детали — все поля и исходное событие.
 */
export function SearchHit({ row, columns, index, rowKey }: { row: Record<string, unknown>; columns: { key: string; label: string }[]; index: IndexKey; rowKey: string }) {
  const [open, setOpen] = useState(false);
  const sevKey = index === "alerts" ? "rule_level" : "severity";
  const detailKeys = Object.keys(row).filter((k) => k !== "raw");
  const what = String(row[index === "alerts" ? "rule_description" : "action"] ?? "");
  const id = `hit-${rowKey}`;
  return (
    <>
      <tr
        className={cn("cursor-pointer border-b border-border/40 align-top transition-colors hover:bg-[var(--surface-elevated)]", open && "bg-[var(--surface-elevated)]")}
        onClick={(e) => {
          if ((e.target as HTMLElement).closest("a,button")) return;
          setOpen(!open);
        }}
      >
        <td className="py-0.5 pl-1">
          <button
            type="button"
            aria-expanded={open}
            aria-controls={id}
            aria-label={`${open ? "Свернуть" : "Раскрыть"} запись ${shortTs(String(row.time ?? ""))} ${what}`.trim()}
            onClick={() => setOpen(!open)}
            className="inline-flex size-6 items-center justify-center rounded-md text-[var(--text-tertiary)] hover:text-foreground"
          >
            <ChevronRight strokeWidth={1.5} className={cn("size-4 transition-transform duration-150", open && "rotate-90 text-[var(--ring)]")} aria-hidden />
          </button>
        </td>
        {columns.map((c) => {
          const v = row[c.key];
          const s = String(v ?? "");
          if (c.key === sevKey) {
            const n = Number(v);
            return (
              <td key={c.key} className="px-2 py-1">
                {n > 0 ? <span className={cn("inline-flex h-5 min-w-7 items-center justify-center rounded-[6px] border px-1.5 font-mono text-[11px] tabular-nums", TONE_CLASS[severityTone(SEVERITY[index], n)])}>{s}</span> : <span className="text-[var(--text-tertiary)]" aria-label="0">·</span>}
              </td>
            );
          }
          if (c.key === "time") {
            return <td key={c.key} className="px-2 py-1 font-mono text-xs whitespace-nowrap tabular-nums" title={formatTs(s)}>{shortTs(s)}</td>;
          }
          const link = linkFor(index, c.key, s);
          if (link) {
            return (
              <td key={c.key} className="max-w-md px-2 py-1 font-mono text-xs">
                <Copyable value={s} href={link.href} label={link.label} />
              </td>
            );
          }
          return <td key={c.key} className={cn("max-w-md truncate px-2 py-1", c.key === "rule_id" || c.key === "dst_ip" ? "font-mono text-xs whitespace-nowrap" : "")} title={s}>{s}</td>;
        })}
      </tr>
      {/* Деталь в разметке всегда (поиск по странице, без JS), скрыта до раскрытия. */}
      <tr id={id} hidden={!open} className="border-b border-border/40 bg-[var(--surface-elevated)]/40">
        <td />
        <td colSpan={columns.length} className="px-2 py-2">
          <dl className="grid gap-x-4 gap-y-1 font-mono text-xs sm:grid-cols-[10rem_1fr]">
            {detailKeys.map((k) => {
              const s = String(row[k] ?? "");
              return (
                <div key={k} className="contents">
                  <dt className="text-muted-foreground">{k}</dt>
                  <dd className="break-all">{k === "time" ? formatTs(s) : s ? <Copyable value={s} /> : "—"}</dd>
                </div>
              );
            })}
          </dl>
          {pretty(row.raw) && <pre className="mt-2 max-h-80 overflow-auto bg-[var(--surface-deep)] p-2 font-mono text-[11px] leading-[1.4]">{pretty(row.raw)}</pre>}
        </td>
      </tr>
    </>
  );
}
