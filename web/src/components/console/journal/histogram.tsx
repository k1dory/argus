import Link from "next/link";
import { formatAxisTs, fmtNum } from "@/lib/shared/time";
import type { Bar } from "@/lib/shared/journal";

const SEGMENTS = [
  { key: "critical", label: "критичная", color: "var(--chart-3)" },
  { key: "high", label: "высокая", color: "var(--chart-2)" },
  { key: "low", label: "ниже высокой", color: "var(--chart-1)" },
] as const;

/**
 * Гистограмма по времени: высоты считаются из чисел (v / max), сегменты по
 * серьёзности. Каждый столбик — ссылка: клик сужает журнал до этой корзины.
 */
export function JournalHistogram({ bars, longRange, hrefFor, bucketMinutes }: { bars: Bar[]; longRange: boolean; hrefFor: (b: Bar) => string; bucketMinutes: number }) {
  const max = Math.max(1, ...bars.map((b) => b.total));
  const sums = { critical: 0, high: 0, low: 0 };
  for (const b of bars) {
    sums.critical += b.critical;
    sums.high += b.high;
    sums.low += b.low;
  }
  const ticks = bars.length > 0 ? [0, Math.floor((bars.length - 1) / 2), bars.length - 1] : [];
  return (
    <figure className="m-0">
      <div className="flex gap-3">
        <div className="flex h-[132px] w-10 shrink-0 flex-col justify-between text-right font-mono text-[11px] text-[var(--text-tertiary)] tabular-nums" aria-hidden>
          <span>{fmtNum(max)}</span>
          <span>{fmtNum(Math.round(max / 2))}</span>
          <span>0</span>
        </div>
        <div className="min-w-0 flex-1">
          <div className="relative flex h-[132px] items-end gap-px border-b border-[var(--border-strong)]" role="list" aria-label="События по времени">
            <div className="pointer-events-none absolute inset-x-0 top-1/2 border-t border-dashed border-[var(--border)]" aria-hidden />
            {bars.map((b) => {
              const label = `${formatAxisTs(b.bucket, true)} UTC, ${bucketMinutes} мин: ${fmtNum(b.total)} событий (критичных ${fmtNum(b.critical)}, высоких ${fmtNum(b.high)})`;
              return (
                <div key={b.startMs} role="listitem" className="flex h-full min-w-0 flex-1">
                  <Link href={hrefFor(b)} title={label} aria-label={`${label}. Сузить журнал до этого интервала`} className="group flex h-full w-full flex-col justify-end rounded-t-[2px] hover:bg-[var(--surface-elevated)] focus-visible:bg-[var(--surface-elevated)]">
                    {b.total > 0 && (
                      <span className="flex w-full flex-col overflow-hidden rounded-t-[2px]" style={{ height: `${Math.max(2, (b.total / max) * 100)}%` }}>
                        {SEGMENTS.map((s) =>
                          b[s.key] > 0 ? <span key={s.key} className="block w-full group-hover:brightness-125" style={{ flexGrow: b[s.key], minHeight: 1, background: s.color }} /> : null,
                        )}
                      </span>
                    )}
                  </Link>
                </div>
              );
            })}
          </div>
          <div className="relative mt-1.5 h-4 font-mono text-[11px] text-[var(--text-tertiary)] tabular-nums" aria-hidden>
            {ticks.map((i, n) => (
              <span key={i} className="absolute top-0 whitespace-nowrap" style={n === 0 ? { left: 0 } : n === ticks.length - 1 ? { right: 0 } : { left: "50%", transform: "translateX(-50%)" }}>
                {formatAxisTs(bars[i].bucket, longRange)}
              </span>
            ))}
          </div>
        </div>
      </div>
      <figcaption className="mt-3 flex flex-wrap items-center gap-x-5 gap-y-1 text-[12px] text-muted-foreground">
        {SEGMENTS.map((s) => (
          <span key={s.key} className="inline-flex items-center gap-1.5">
            <span className="inline-block h-2 w-2 rounded-[2px]" style={{ background: s.color }} aria-hidden />
            {s.label} <span className="font-mono text-foreground tabular-nums">{fmtNum(sums[s.key])}</span>
          </span>
        ))}
        <span className="ml-auto text-[var(--text-tertiary)]">корзина {bucketMinutes} мин · клик по столбику — сузить интервал</span>
      </figcaption>
    </figure>
  );
}
