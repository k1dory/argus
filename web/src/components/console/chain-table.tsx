import { parseChainLine } from "@/lib/shared/incident-lines";
import { Copyable } from "./copyable";
import { searchHref } from "@/lib/shared/search-href";

/**
 * Цепочка событий инцидента таблицей: время, источник, узел, действие,
 * деталь — каждое значение копируется и ведёт в поиск. Строки, которые не
 * разбираются (примечание движка «→ …»), показываются как есть.
 */
export function ChainTable({ chain, date }: { chain: string[]; date?: string }) {
  if (chain.length === 0) return <p className="text-xs text-muted-foreground">— цепочка пуста —</p>;
  const steps = chain.map((line, i) => ({ id: `${i}-${line}`, step: parseChainLine(line) }));
  return (
    <div className="c-well overflow-x-auto p-2">
      <table className="w-full font-mono text-[12px] leading-[1.6]">
        <thead>
          <tr className="border-b border-border/60 text-left">
            <th scope="col" className="c-label py-1 pr-3">время{date ? ` (${date})` : ""}</th>
            <th scope="col" className="c-label py-1 pr-3">источник</th>
            <th scope="col" className="c-label py-1 pr-3">узел</th>
            <th scope="col" className="c-label py-1 pr-3">действие</th>
            <th scope="col" className="c-label py-1">деталь</th>
          </tr>
        </thead>
        <tbody>
          {steps.map(({ id, step }) =>
            step.kind === "event" ? (
              <tr key={id} className="border-b border-border/40 align-top">
                <td className="whitespace-nowrap py-1 pr-3 text-muted-foreground">{step.ts}</td>
                <td className="py-1 pr-3">{step.source ? <Copyable value={step.source} href={searchHref.source(step.source)} label="Источник" /> : "—"}</td>
                <td className="py-1 pr-3">{step.node ? <Copyable value={step.node} href={searchHref.node(step.node)} label="Узел" /> : "—"}</td>
                <td className="py-1 pr-3 text-foreground">{step.action || "—"}</td>
                <td className="py-1 break-all">{step.detail ? <Copyable value={step.detail} label="Значение" /> : "—"}</td>
              </tr>
            ) : (
              <tr key={id} className="border-b border-border/40">
                <td colSpan={5} className={step.kind === "note" ? "py-1 text-[var(--ring)]" : "py-1 text-muted-foreground"}>
                  {step.kind === "note" ? `→ ${step.text}` : step.text}
                </td>
              </tr>
            ),
          )}
        </tbody>
      </table>
    </div>
  );
}
