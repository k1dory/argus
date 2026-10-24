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
    if (key === "node") return { href: searchHref.node(value), label: "Узел" };
  }
  return null;
}

/** Строка выдачи: краткие колонки, по клику — все поля и исходный JSON. */
export function SearchHit({ row, columns, index }: { row: Record<string, unknown>; columns: { key: string; label: string }[]; index: IndexKey }) {
  const sevKey = index === "alerts" ? "rule_level" : "severity";
  const detailKeys = Object.keys(row).filter((k) => k !== "raw");
  return (
    <>
      <tr className="border-b border-border/40 align-top">
        <td className="px-1 py-1">
          <details className="group">
            <summary className="cursor-pointer list-none font-mono text-muted-foreground group-open:text-foreground" aria-label="подробности">›</summary>
          </details>
        </td>
        {columns.map((c) => {
          const v = row[c.key];
          const s = String(v ?? "");
          if (c.key === sevKey) {
            return (
              <td key={c.key} className="px-2 py-1">
                <span className={cn("inline-block border px-1.5 font-mono text-[11px]", TONE_CLASS[severityTone(SEVERITY[index], Number(v))])}>{s}</span>
              </td>
            );
          }
          if (c.key === "time") {
            return <td key={c.key} className="px-2 py-1 font-mono text-xs whitespace-nowrap">{formatTs(s)}</td>;
          }
          const link = linkFor(index, c.key, s);
          if (link) {
            return (
              <td key={c.key} className="max-w-md px-2 py-1 font-mono text-xs">
                <Copyable value={s} href={link.href} label={link.label} />
              </td>
            );
          }
          return <td key={c.key} className={cn("max-w-md truncate px-2 py-1", c.key === "rule_id" ? "font-mono text-xs whitespace-nowrap" : "")} title={s}>{s}</td>;
        })}
      </tr>
      <tr className="hidden border-b border-border/40 [tr:has(details[open])+&]:table-row">
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
