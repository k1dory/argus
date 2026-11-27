import Link from "next/link";
import { fmtNum, formatAxisTs } from "@/lib/shared/time";
import { bucketLabel, compactNum, niceCeil, timeTicks } from "@/lib/shared/histogram";
import { severityBands, type SeverityThresholds } from "@/lib/shared/severity";
import type { Bar } from "@/lib/shared/journal";

const COLOR = { critical: "var(--chart-3)", high: "var(--chart-2)", low: "var(--chart-1)" } as const;

/**
 * Гистограмма по времени (журнал, поиск): высоты считаются из чисел
 * (v / верх оси), сегменты по серьёзности, легенда — из порогов того индекса,
 * чьи данные на графике (scale + max). Столбик со критичными помечен точкой
 * над ним: 14 критичных на фоне 70 000 иначе превращаются в риску в 1 px.
 * Каждый столбик — ссылка: клик сужает выдачу до его интервала.
 */
export function TimeHistogram({
  bars,
  hrefFor,
  bucketMinutes,
  scale,
  scaleMax,
  noun = "событий",
  ariaLabel = "События по времени",
  height = 132,
}: {
  bars: Bar[];
  hrefFor: (b: Bar) => string;
  bucketMinutes: number;
  /** Пороги индекса (SEVERITY.events / SEVERITY.alerts) — те же, что у SQL-ряда. */
  scale: SeverityThresholds;
  /** Верх шкалы (SEVERITY_MAX[index]). */
  scaleMax: number;
  /** Что считаем — в подписях для скринридера: «событий», «алертов». */
  noun?: string;
  ariaLabel?: string;
  height?: number;
}) {
  const top = niceCeil(Math.max(1, ...bars.map((b) => b.total)));
  const bands = severityBands(scale, scaleMax);
  const sums = { critical: 0, high: 0, low: 0 };
  for (const b of bars) {
    sums.critical += b.critical;
    sums.high += b.high;
    sums.low += b.low;
  }
  const ticks = bars.length > 0 ? timeTicks(bars[0].startMs, bars[bars.length - 1].endMs, 8) : [];
  const step = bucketLabel(bucketMinutes);
  return (
    <figure className="m-0">
      <div className="flex gap-3">
        <div className="flex w-16 shrink-0 flex-col justify-between whitespace-nowrap text-right font-mono text-[11px] text-[var(--text-tertiary)] tabular-nums" style={{ height }} aria-hidden>
          <span>{compactNum(top)}</span>
          <span>{compactNum(top / 2)}</span>
          <span>0</span>
        </div>
        <div className="min-w-0 flex-1">
          <div className="relative flex items-end gap-px border-b border-[var(--border-strong)]" style={{ height }} role="list" aria-label={ariaLabel}>
            <div className="pointer-events-none absolute inset-x-0 top-1/2 border-t border-dashed border-[var(--border)]" aria-hidden />
            {bars.map((b) => {
              const label = `${formatAxisTs(b.bucket, true)} UTC, ${step}: ${fmtNum(b.total)} ${noun} (критичных ${fmtNum(b.critical)}, высоких ${fmtNum(b.high)})`;
              return (
                <div key={b.startMs} role="listitem" className="flex h-full min-w-0 flex-1">
                  <Link href={hrefFor(b)} title={label} aria-label={`${label}. Сузить до этого интервала`} className="group flex h-full w-full flex-col items-center justify-end rounded-t-[2px] hover:bg-[var(--surface-elevated)] focus-visible:bg-[var(--surface-elevated)]">
                    {b.critical > 0 && <span className="mb-0.5 size-1.5 shrink-0 rounded-full" style={{ background: COLOR.critical }} data-critical aria-hidden />}
                    {b.total > 0 && (
                      <span className="flex w-full flex-col overflow-hidden rounded-t-[2px]" style={{ height: `${Math.max(2, (b.total / top) * 100)}%` }}>
                        {(["critical", "high", "low"] as const).map((k) =>
                          b[k] > 0 ? <span key={k} className="block w-full group-hover:brightness-125" style={{ flexGrow: b[k], minHeight: k === "low" ? 1 : 2, background: COLOR[k] }} /> : null,
                        )}
                      </span>
                    )}
                  </Link>
                </div>
              );
            })}
          </div>
          <div className="relative mt-1.5 h-4 overflow-hidden font-mono text-[11px] text-[var(--text-tertiary)] tabular-nums" aria-hidden>
            {ticks.map((t, i) => (
              <span
                key={t.ms}
                className="absolute top-0 whitespace-nowrap"
                style={t.pos < 0.04 ? { left: 0 } : t.pos > 0.96 ? { right: 0 } : { left: `${t.pos * 100}%`, transform: "translateX(-50%)" }}
                data-tick={i}
              >
                {t.label}
              </span>
            ))}
          </div>
        </div>
      </div>
      <figcaption className="mt-3 flex flex-wrap items-center gap-x-5 gap-y-1 text-[12px] text-muted-foreground">
        {bands.map((s) => (
          <span key={s.key} className="inline-flex items-center gap-1.5">
            <span className="inline-block size-2 rounded-[2px]" style={{ background: COLOR[s.key] }} aria-hidden />
            {s.label} <span className="text-[var(--text-tertiary)]">({s.range})</span> <span className="font-mono text-foreground tabular-nums">{fmtNum(sums[s.key])}</span>
          </span>
        ))}
        <span className="ml-auto">столбик — {step} · нажмите на столбик, чтобы сузить интервал</span>
      </figcaption>
    </figure>
  );
}
