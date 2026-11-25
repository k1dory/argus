// Трассировка субъекта: сессии → откуда → куда → действия, полосы на шкале
// сессии (как в трейсинге). Серверный компонент: раскрытие — <details>, без JS.
import Link from "next/link";
import { ChevronRight } from "lucide-react";
import { LevelBadge } from "@/components/console/incident-badges";
import { Empty, Panel } from "@/components/console/panel";
import { Badge } from "@/components/ui/badge";
import { fmtDuration, spanEventsHref, spanLabel, TRACE_SECTION_LABELS, type ActorTrace, type TraceOrigin, type TraceSession, type TraceSpan } from "@/lib/shared/actor-trace";
import { searchHref } from "@/lib/shared/search-href";
import { fmtNum, formatTs } from "@/lib/shared/time";
import type { Section } from "@/lib/shared/actors";

// Свои цвета, не --chart-*: красный занят отказами, а в тёмной теме chart-1 серый.
const SECTION_COLOR: Record<Section, string> = {
  login: "#5b9cf5",
  app: "#3fb68b",
  host: "#e0a030",
  change: "#c678dd",
  other: "#9aa0a8",
  network: "#6b7280",
};

/** Сессий раскрыто сразу. */
const OPEN_SESSIONS = 3;

const hhmm = (ms: number) => formatTs(ms, "time").slice(0, 5);

function sessionTitle(s: TraceSession): string {
  const day = formatTs(s.first, "date");
  const sameDay = formatTs(s.last, "date") === day;
  return `${day} ${hhmm(s.first)} → ${sameDay ? "" : `${formatTs(s.last, "date")} `}${hhmm(s.last)}`;
}

function Track({ from, to, segments, color, dim }: { from: number; to: number; segments: [number, number][]; color: string; dim?: boolean }) {
  const total = Math.max(to - from, 1);
  return (
    <div className="relative h-3 w-full rounded-sm bg-[var(--muted)]/40">
      {segments.map(([a, b], i) => (
        <span
          key={i}
          className="absolute top-0 h-full rounded-sm"
          style={{
            left: `${((a - from) / total) * 100}%`,
            width: `max(3px, ${((b - a) / total) * 100}%)`,
            background: color,
            opacity: dim ? 0.45 : 0.9,
          }}
        />
      ))}
    </div>
  );
}

function Axis({ from, to }: { from: number; to: number }) {
  const ticks = [0, 0.25, 0.5, 0.75, 1].map((f) => from + (to - from) * f);
  return (
    <div className="relative h-4 font-mono text-[10px] text-muted-foreground">
      {ticks.map((t, i) => (
        <span key={i} className="absolute top-0" style={{ left: `${i * 25}%`, transform: i === 0 ? "none" : i === 4 ? "translateX(-100%)" : "translateX(-50%)" }}>{hhmm(t)}</span>
      ))}
    </div>
  );
}

const ROW = "grid grid-cols-[minmax(260px,38%)_1fr_80px] items-center gap-3 px-3 py-1";

function SpanRow({ origin, span, session, bucketSec }: { origin: string; span: TraceSpan; session: TraceSession; bucketSec: number }) {
  const label = spanLabel(span);
  const href = span.folded ? undefined : spanEventsHref(origin, span, bucketSec);
  const shownActions = span.actions.slice(0, 6);
  return (
    <div className={`${ROW} border-t border-border/30 hover:bg-[var(--muted)]/30`}>
      <div className="min-w-0 pl-6">
        <div className="flex min-w-0 items-center gap-2 text-xs">
          <span className="shrink-0 rounded-sm px-1.5 py-px font-mono text-[10px] uppercase tracking-wide" style={{ color: SECTION_COLOR[span.section], border: `1px solid ${SECTION_COLOR[span.section]}` }}>
            {TRACE_SECTION_LABELS[span.section]}
          </span>
          {href ? (
            <Link href={href} className="truncate font-mono hover:underline" title={`${label} — события в журнале`}>{label}</Link>
          ) : (
            <span className="truncate font-mono text-muted-foreground">{label}</span>
          )}
          {span.attached && <span className="shrink-0 text-[10px] text-muted-foreground" title="Событие без адреса источника — привязано к входу на этот узел в той же сессии">↳ после входа</span>}
        </div>
        {(shownActions.length > 0 || span.sources.length > 0) && (
          <div className="mt-0.5 flex flex-wrap gap-x-2 pl-1 font-mono text-[11px] text-muted-foreground">
            {shownActions.map((a) => (
              <Link key={`${a.source}|${a.action}`} href={spanEventsHref(origin, span, bucketSec, a.action)} className="hover:text-foreground hover:underline" title={`${a.source} · ${formatTs(a.first)} → ${formatTs(a.last)}`}>
                {a.action}
                {a.count > 1 && <span> ×{fmtNum(a.count)}</span>}
                {a.fails > 0 && <span className="text-[var(--status-err)]"> ✕{fmtNum(a.fails)}</span>}
              </Link>
            ))}
            {span.actions.length > shownActions.length && <span>+{span.actions.length - shownActions.length}</span>}
            {span.actions.length === 0 && <span>{span.sources.join(" · ")}</span>}
          </div>
        )}
      </div>
      <div title={`${formatTs(span.first)} → ${formatTs(span.last)} UTC`}>
        <Track from={session.first} to={session.last} segments={span.segments} color={SECTION_COLOR[span.section]} dim={span.section === "network"} />
      </div>
      <div className="text-right font-mono text-xs">
        {fmtNum(span.count)}
        {span.fails > 0 && <div className="text-[10px] text-[var(--status-err)]">отказов {fmtNum(span.fails)}</div>}
      </div>
    </div>
  );
}

function OriginBlock({ o, session, bucketSec }: { o: TraceOrigin; session: TraceSession; bucketSec: number }) {
  const nodes = new Set(o.spans.filter((s) => s.target_kind === "node").map((s) => s.target)).size;
  // Действия человека — сверху по времени; сеть — свёрнутым блоком в конце: это фон, а не поступки.
  const acts = o.spans.filter((s) => s.section !== "network");
  const net = o.spans.filter((s) => s.section === "network");
  const netTargets = net.reduce((n, s) => n + (s.folded ?? 1), 0);
  return (
    <div className="border-t border-border/60">
      <div className={`${ROW} bg-[var(--muted)]/20`}>
        <div className="flex min-w-0 items-center gap-2 text-xs">
          <span className="text-muted-foreground">{o.origin ? "из" : "без адреса источника"}</span>
          {o.origin && <Link href={searchHref.eventSrc(o.origin)} className="font-mono font-medium hover:underline">{o.origin}</Link>}
          <span className="truncate text-[11px] text-muted-foreground">
            {fmtDuration(o.last - o.first)}{nodes ? ` · узлов ${nodes}` : ""}
          </span>
        </div>
        <Track from={session.first} to={session.last} segments={[[o.first, o.last]]} color="var(--ring)" dim />
        <div className="text-right font-mono text-xs">
          {fmtNum(o.count)}
          {o.fails > 0 && <div className="text-[10px] text-[var(--status-err)]">отказов {fmtNum(o.fails)}</div>}
        </div>
      </div>
      {acts.map((s, i) => <SpanRow key={`${s.section}|${s.target_kind}|${s.target}|${i}`} origin={o.origin} span={s} session={session} bucketSec={bucketSec} />)}
      {net.length > 0 && (
        <details className="group/net">
          <summary className={`${ROW} cursor-pointer list-none border-t border-border/30 hover:bg-[var(--muted)]/30`}>
            <span className="flex min-w-0 items-center gap-2 pl-6 text-xs text-muted-foreground">
              <ChevronRight className="size-3 shrink-0 transition-transform group-open/net:rotate-90" strokeWidth={1.5} />
              <span className="rounded-sm px-1.5 py-px font-mono text-[10px] uppercase tracking-wide" style={{ color: SECTION_COLOR.network, border: `1px solid ${SECTION_COLOR.network}` }}>сеть</span>
              адресов {fmtNum(netTargets)}
            </span>
            <Track from={session.first} to={session.last} segments={net.flatMap((s) => s.segments)} color={SECTION_COLOR.network} dim />
            <span className="text-right font-mono text-xs text-muted-foreground">{fmtNum(net.reduce((n, s) => n + s.count, 0))}</span>
          </summary>
          {net.map((s, i) => <SpanRow key={`net|${s.target}|${s.dst_port}|${s.folded ?? ""}|${i}`} origin={o.origin} span={s} session={session} bucketSec={bucketSec} />)}
        </details>
      )}
    </div>
  );
}

function sessionSummary(s: TraceSession): string {
  const origins = s.origins.filter((o) => o.origin).map((o) => o.origin);
  const targets = new Set(s.origins.flatMap((o) => o.spans.filter((x) => x.section !== "network" && !x.folded).map((x) => spanLabel(x))));
  const parts = [
    origins.length ? `из ${origins.slice(0, 3).join(", ")}${origins.length > 3 ? ` +${origins.length - 3}` : ""}` : "без адреса источника",
    targets.size ? `→ ${[...targets].slice(0, 4).join(", ")}${targets.size > 4 ? ` +${targets.size - 4}` : ""}` : "",
  ];
  return parts.filter(Boolean).join(" ");
}

export function ActorTraceView({ trace }: { trace: ActorTrace }) {
  const interactive = trace.sessions.filter((s) => !s.networkOnly);
  const meta = `сессия — активность без перерыва дольше ${fmtDuration(trace.gapMs)} · сеть — топ ${trace.networkTop} адресов на источник${trace.truncated ? " · выборка упёрлась в потолок, показаны свежие" : ""}`;
  return (
    <Panel label={`Трассировка · сессий ${fmtNum(interactive.length)}${trace.sessions.length > interactive.length ? ` + только сеть ${fmtNum(trace.sessions.length - interactive.length)}` : ""}`} meta={meta} bodyClassName="p-0">
      {trace.sessions.length === 0 ? <Empty className="p-4">В периоде нет действий субъекта.</Empty> : (
        <div>
          {trace.sessions.map((s, i) => (
            <details key={s.id} open={!s.networkOnly && interactive.indexOf(s) < OPEN_SESSIONS && i < OPEN_SESSIONS * 2} className="group border-b border-border last:border-b-0">
              <summary className={`flex cursor-pointer list-none flex-wrap items-center gap-x-3 gap-y-1 px-3 py-2 hover:bg-[var(--muted)]/30 ${s.networkOnly ? "text-muted-foreground" : ""}`}>
                <ChevronRight className="size-3.5 shrink-0 transition-transform group-open:rotate-90" strokeWidth={1.5} />
                <span className="font-mono text-xs font-medium">{sessionTitle(s)}</span>
                <span className="font-mono text-[11px] text-muted-foreground">{fmtDuration(s.last - s.first)}</span>
                {s.networkOnly && <Badge variant="outline" className="text-[10px]">только сеть</Badge>}
                <span className="min-w-0 truncate text-xs">{sessionSummary(s)}</span>
                <span className="ml-auto flex items-center gap-2 font-mono text-[11px]">
                  {s.incidents.map((inc) => (
                    <Link key={inc.id} href={`/incidents/${inc.id}`} className="flex items-center gap-1 hover:underline" title={inc.rule_title}>
                      <LevelBadge level={inc.level} />{inc.id}
                    </Link>
                  ))}
                  {s.fails > 0 && <span className="text-[var(--status-err)]">отказов {fmtNum(s.fails)}</span>}
                  <span className="text-muted-foreground">событий {fmtNum(s.count)}</span>
                </span>
              </summary>
              <div className="pb-2">
                <div className={`${ROW} pt-0`}>
                  <span className="c-label">откуда → куда → действия</span>
                  <Axis from={s.first} to={s.last} />
                  <span className="c-label text-right">событий</span>
                </div>
                {s.origins.map((o) => <OriginBlock key={o.origin || "∅"} o={o} session={s} bucketSec={trace.bucketSec} />)}
              </div>
            </details>
          ))}
        </div>
      )}
    </Panel>
  );
}
