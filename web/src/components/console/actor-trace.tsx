// Сеансы субъекта (трассировка): сеанс → откуда → куда → действия, метки на
// шкале сеанса (как в трейсинге). Серверный компонент: раскрытие — <details>, без JS.
import Link from "next/link";
import { ChevronRight } from "lucide-react";
import { LevelBadge } from "@/components/console/incident-badges";
import { Empty, Led, Panel } from "@/components/console/panel";
import { cn } from "@/lib/utils";
import { fmtDuration, originEventsHref, ownerScope, spanEventsHref, spanLabel, TRACE_SECTION_LABELS, type ActorTrace, type OwnerScope, type TraceOrigin, type TraceSession, type TraceSpan } from "@/lib/shared/actor-trace";
import { feedKind, shortTarget } from "@/lib/shared/actor-feed";
import { fmtNum, formatTs } from "@/lib/shared/time";
import type { Alias, Section } from "@/lib/shared/actors";

/**
 * Цвета разделов — из синтаксической палитры (токены темы), не совпадают со
 * статусами: красный — только отказы, жёлтый — «внимание», синий login — тот
 * же, что у ссылок, но в трассировке ссылок-меток нет. app — бирюза палитры
 * (#89ddff), в токенах её нет. Сеть — третичный текст: это фон.
 */
const SECTION_CLASS: Record<Section, { bg: string; text: string; border: string }> = {
  login: { bg: "bg-fn", text: "text-fn", border: "border-fn/70" },
  app: { bg: "bg-[#89ddff]", text: "text-[#89ddff]", border: "border-[#89ddff]/70" },
  host: { bg: "bg-str", text: "text-str", border: "border-str/70" },
  change: { bg: "bg-kw", text: "text-kw", border: "border-kw/70" },
  other: { bg: "bg-[var(--fg-2)]", text: "text-[var(--fg-2)]", border: "border-[var(--fg-2)]/60" },
  network: { bg: "bg-[var(--text-tertiary)]", text: "text-[var(--text-tertiary)]", border: "border-[var(--text-tertiary)]/70" },
};

const hhmm = (ms: number) => formatTs(ms, "time").slice(0, 5);
const ddmm = (ms: number) => { const d = formatTs(ms, "date"); return `${d.slice(8, 10)}.${d.slice(5, 7)}`; };

/** «25.11 05:37–06:17», через полночь — «24.11 23:37–25.11 00:39». */
export function sessionTitle(s: Pick<TraceSession, "first" | "last">): string {
  const sameDay = formatTs(s.last, "date") === formatTs(s.first, "date");
  return `${ddmm(s.first)} ${hhmm(s.first)}–${sameDay ? "" : `${ddmm(s.last)} `}${hhmm(s.last)}`;
}

/** 1 адрес, 2 адреса, 5 адресов. */
function plural(n: number, one: string, few: string, many: string): string {
  const m10 = n % 10, m100 = n % 100;
  return m10 === 1 && m100 !== 11 ? one : m10 >= 2 && m10 <= 4 && (m100 < 12 || m100 > 14) ? few : many;
}

/** Метка короче этой доли шкалы — тонкая чёрточка 3px. */
const SHORT_SEG = 0.012;

function Track({ from, to, segments, cls, dim, thin, fail }: { from: number; to: number; segments: [number, number][]; cls: string; dim?: boolean; thin?: boolean; fail?: boolean }) {
  const total = Math.max(to - from, 1);
  return (
    <div className={cn("relative w-full rounded-[2px] bg-[var(--muted)]", thin ? "h-1" : "h-2", fail && "outline outline-1 outline-offset-1 outline-[var(--status-err)]/70")}>
      {segments.map(([a, b], i) => {
        const w = (b - a) / total;
        return (
          <span
            key={i}
            className={cn("absolute top-0 h-full", cls, w < SHORT_SEG ? "w-[3px] rounded-none" : "rounded-[2px]", dim ? "opacity-50" : "opacity-90")}
            style={{ left: `${((a - from) / total) * 100}%`, ...(w < SHORT_SEG ? {} : { width: `${w * 100}%` }) }}
          />
        );
      })}
    </div>
  );
}

function Axis({ from, to }: { from: number; to: number }) {
  const ticks = [0, 0.25, 0.5, 0.75, 1].map((f) => from + (to - from) * f);
  return (
    <div className="relative h-4 font-mono text-[11px] text-muted-foreground">
      {ticks.map((t, i) => (
        <span key={i} className="absolute top-0" style={{ left: `${i * 25}%`, transform: i === 0 ? "none" : i === 4 ? "translateX(-100%)" : "translateX(-50%)" }}>{hhmm(t)}</span>
      ))}
    </div>
  );
}

const s_title = (span: TraceSpan) => `${span.target_kind === "object" ? span.target : spanLabel(span)} — события в журнале${span.actors.length ? ` по ${span.actors[0]}${span.actors.length > 1 ? ` (ещё алиасов: ${span.actors.length - 1})` : ""}` : ""}`;

const ROW = "grid grid-cols-[minmax(240px,38%)_1fr_72px] items-center gap-3 px-3 py-1";

function SectionTag({ section }: { section: Section }) {
  const c = SECTION_CLASS[section];
  return (
    <span className={cn("shrink-0 rounded-[4px] border px-1.5 text-[11px] leading-4", c.text, c.border)}>
      {TRACE_SECTION_LABELS[section]}
    </span>
  );
}

function FailCount({ n }: { n: number }) {
  return n > 0 ? <div className="text-xs text-[var(--status-err)]">{fmtNum(n)} {plural(n, "отказ", "отказа", "отказов")}</div> : null;
}

function SpanRow({ origin, span, session, ctx }: { origin: string; span: TraceSpan; session: TraceSession; ctx: Ctx }) {
  const full = spanLabel(span);
  const label = shortTarget(full);
  const href = span.folded ? null : spanEventsHref(origin, span, ctx.bucketSec, undefined, ctx.owner);
  const shownActions = span.actions.slice(0, 6);
  const failed = span.fails > 0;
  // «Прочее», где все действия — запись/push, подписываем как в ленте: «изменение».
  const shownSection: Section = span.section === "other" && span.actions.length > 0 && span.actions.every((a) => feedKind("other", a.action) === "change") ? "change" : span.section;
  return (
    <div className={`${ROW} border-t border-border/30 hover:bg-[var(--muted)]/30`}>
      <div className="min-w-0 pl-6">
        <div className="flex min-w-0 items-center gap-2 text-xs">
          <SectionTag section={shownSection} />
          {href ? (
            <Link href={href} className={cn("truncate font-mono hover:underline", failed && "text-[var(--status-err)]")} title={s_title(span)}>{label}</Link>
          ) : (
            <span className={cn("truncate font-mono", failed ? "text-[var(--status-err)]" : "text-muted-foreground")} title={full}>{label}</span>
          )}
          {span.attached && <span className="shrink-0 text-[11px] text-muted-foreground" title="Источник не передал адрес — событие привязано к входу на этот узел в том же сеансе">↳ после входа</span>}
        </div>
        {(shownActions.length > 0 || span.sources.length > 0) && (
          <div className="mt-0.5 flex flex-wrap gap-x-2 pl-1 font-mono text-[11px] text-muted-foreground">
            {shownActions.map((a) => {
              const ah = span.folded ? null : spanEventsHref(origin, span, ctx.bucketSec, a, ctx.owner);
              const body = (
                <>
                  {a.action}
                  {a.count > 1 && <span> ×{fmtNum(a.count)}</span>}
                  {a.fails > 0 && <span className="text-[var(--status-err)]"> ✕{fmtNum(a.fails)}</span>}
                </>
              );
              const title = `${a.source}${a.actors[0] ? ` · ${a.actors[0]}` : ""} · ${formatTs(a.first)} → ${formatTs(a.last)}`;
              return ah
                ? <Link key={`${a.source}|${a.action}`} href={ah} className="hover:text-foreground hover:underline" title={title}>{body}</Link>
                : <span key={`${a.source}|${a.action}`} title={`${title} · ссылку в журнал построить нельзя`}>{body}</span>;
            })}
            {span.actions.length > shownActions.length && <span>+{span.actions.length - shownActions.length}</span>}
            {span.actions.length === 0 && <span>{span.sources.join(" · ")}</span>}
          </div>
        )}
      </div>
      <div title={`${formatTs(span.first)} → ${formatTs(span.last)}${failed ? ` · ${fmtNum(span.fails)} ${plural(span.fails, "отказ", "отказа", "отказов")}` : ""}`}>
        <Track from={session.first} to={session.last} segments={span.segments} cls={SECTION_CLASS[shownSection].bg} dim={span.section === "network"} fail={failed} />
      </div>
      <div className="text-right font-mono text-xs">
        {fmtNum(span.count)}
        <FailCount n={span.fails} />
      </div>
    </div>
  );
}

function OriginBlock({ o, session, ctx }: { o: TraceOrigin; session: TraceSession; ctx: Ctx }) {
  const originHref = o.origin ? originEventsHref(o) : null;
  const nodes = new Set(o.spans.filter((s) => s.target_kind === "node").map((s) => s.target)).size;
  // Действия человека — сверху по времени; сеть — свёрнутым блоком в конце: это фон, а не поступки.
  const acts = o.spans.filter((s) => s.section !== "network");
  const net = o.spans.filter((s) => s.section === "network");
  const netTargets = net.reduce((n, s) => n + (s.folded ?? 1), 0);
  return (
    <div className="border-t border-border/60">
      <div className={`${ROW} bg-[var(--muted)]/30`}>
        <div className="flex min-w-0 items-center gap-2 text-xs">
          {o.origin ? <span className="text-muted-foreground">с</span> : <span className="text-muted-foreground" title="Источник не передал IP">адрес неизвестен</span>}
          {o.origin && (originHref ? <Link href={originHref} title="События с этого адреса в окне ветки — всех субъектов" className="font-mono font-medium hover:underline">{o.origin}</Link> : <span className="font-mono font-medium">{o.origin}</span>)}
          <span className="truncate text-[11px] text-muted-foreground">
            {fmtDuration(o.last - o.first)}{nodes ? ` · ${nodes} ${plural(nodes, "узел", "узла", "узлов")}` : ""}{acts.length === 0 ? " · только трафик" : ""}
          </span>
        </div>
        <Track from={session.first} to={session.last} segments={[[o.first, o.last]]} cls="bg-[var(--ring)]" dim thin />
        <div className="text-right font-mono text-xs">
          {fmtNum(o.count)}
          <FailCount n={o.fails} />
        </div>
      </div>
      {acts.map((s, i) => <SpanRow key={`${s.section}|${s.target_kind}|${s.target}|${i}`} origin={o.origin} span={s} session={session} ctx={ctx} />)}
      {net.length > 0 && (
        <details className="group/net">
          <summary className={`${ROW} cursor-pointer list-none border-t border-border/30 hover:bg-[var(--muted)]/30`}>
            <span className="flex min-w-0 items-center gap-2 pl-6 text-xs text-muted-foreground">
              <ChevronRight className="size-3 shrink-0 transition-transform group-open/net:rotate-90" strokeWidth={1.5} aria-hidden />
              <SectionTag section="network" />
              {fmtNum(netTargets)} {plural(netTargets, "адрес назначения", "адреса назначения", "адресов назначения")}
            </span>
            <Track from={session.first} to={session.last} segments={net.flatMap((s) => s.segments)} cls={SECTION_CLASS.network.bg} dim />
            <span className="text-right font-mono text-xs text-muted-foreground">{fmtNum(net.reduce((n, s) => n + s.count, 0))}</span>
          </summary>
          {net.map((s, i) => <SpanRow key={`net|${s.target}|${s.dst_port}|${s.folded ?? ""}|${i}`} origin={o.origin} span={s} session={session} ctx={ctx} />)}
        </details>
      )}
    </div>
  );
}

function sessionSummary(s: TraceSession): string {
  const origins = s.origins.filter((o) => o.origin).map((o) => o.origin);
  const targets = new Set(s.origins.flatMap((o) => o.spans.filter((x) => x.section !== "network" && !x.folded).map((x) => shortTarget(spanLabel(x), 32))));
  const parts = [
    origins.length ? `с ${origins.slice(0, 3).join(", ")}${origins.length > 3 ? ` +${origins.length - 3}` : ""}` : "адрес неизвестен",
    targets.size ? `→ ${[...targets].slice(0, 4).join(", ")}${targets.size > 4 ? ` +${targets.size - 4}` : ""}` : "",
  ];
  return parts.filter(Boolean).join(" ");
}

/** Источники с действиями — первыми, только с сетью — после, «адрес неизвестен» — последним. */
function orderOrigins(origins: TraceOrigin[]): TraceOrigin[] {
  const rank = (o: TraceOrigin) => (o.origin ? 0 : 2) + (o.spans.some((s) => s.section !== "network") ? 0 : 1);
  return origins.map((o, i) => ({ o, i })).sort((a, b) => rank(a.o) - rank(b.o) || a.i - b.i).map((x) => x.o);
}

type Ctx = { bucketSec: number; owner?: OwnerScope };

function SessionBlock({ s, ctx, open }: { s: TraceSession; ctx: Ctx; open: boolean }) {
  const alarm = s.fails > 0 || s.incidents.length > 0;
  return (
    <details open={open} className="group border-b border-border last:border-b-0">
      <summary className={cn("flex cursor-pointer list-none flex-wrap items-center gap-x-3 gap-y-1 px-3 py-2 hover:bg-[var(--muted)]/30", s.networkOnly && "text-muted-foreground")}>
        <ChevronRight className="size-3.5 shrink-0 transition-transform group-open:rotate-90" strokeWidth={1.5} aria-hidden />
        {alarm && <Led color="var(--status-err)" title={s.fails > 0 ? "В сеансе были отказы" : "В сеансе есть инцидент"} />}
        <span className="font-mono text-xs font-medium">{sessionTitle(s)}</span>
        <span className="font-mono text-[11px] text-muted-foreground">{fmtDuration(s.last - s.first)}</span>
        <span className="min-w-0 truncate text-xs" title={sessionSummary(s)}>{sessionSummary(s)}</span>
        <span className="ml-auto flex items-center gap-3 text-xs">
          {s.incidents.map((inc) => (
            <Link key={inc.id} href={`/incidents/${inc.id}`} className="flex items-center gap-1 font-mono hover:underline" title={inc.rule_title}>
              <LevelBadge level={inc.level} />{inc.id}
            </Link>
          ))}
          {s.fails > 0 && <span className="text-[var(--status-err)]">{fmtNum(s.fails)} {plural(s.fails, "отказ", "отказа", "отказов")}</span>}
          <span className="text-muted-foreground">{fmtNum(s.count)} {plural(s.count, "событие", "события", "событий")}</span>
        </span>
      </summary>
      <div className="pb-2">
        <div className={`${ROW} pt-0`}>
          <span className="c-label">Адрес → система · действия</span>
          <Axis from={s.first} to={s.last} />
          <span className="c-label text-right">событий</span>
        </div>
        {orderOrigins(s.origins).map((o) => <OriginBlock key={o.origin || "∅"} o={o} session={s} ctx={ctx} />)}
      </div>
    </details>
  );
}

/** aliases — для границ ссылок в журнал по интервалам владения алиасами. */
export function ActorTraceView({ trace, aliases }: { trace: ActorTrace; aliases?: Alias[] }) {
  const ctx: Ctx = { bucketSec: trace.bucketSec, owner: aliases ? ownerScope(aliases) : undefined };
  const interactive = trace.sessions.filter((s) => !s.networkOnly);
  const netOnly = trace.sessions.filter((s) => s.networkOnly);
  const netEvents = netOnly.reduce((n, s) => n + s.count, 0);
  // Раскрыты: последний сеанс и все сеансы с отказами или инцидентами.
  const isOpen = (s: TraceSession, i: number) => i === 0 || s.fails > 0 || s.incidents.length > 0;
  const meta = `сеанс — активность с паузами не длиннее ${fmtDuration(trace.gapMs)}${trace.truncated ? " · показаны самые свежие" : ""}`;
  return (
    <Panel label={`Сеансы · ${fmtNum(interactive.length)}`} meta={meta} bodyClassName="p-0">
      {trace.sessions.length === 0 ? <Empty className="p-4">В периоде нет действий субъекта.</Empty> : (
        <div>
          {interactive.length === 0 && <Empty className="border-b border-border p-4">Сеансов с действиями в периоде нет — только сетевой трафик.</Empty>}
          {interactive.map((s, i) => <SessionBlock key={s.id} s={s} ctx={ctx} open={isOpen(s, i)} />)}
          {netOnly.length > 0 && (
            <details className="group/netonly">
              <summary className="flex cursor-pointer list-none items-center gap-3 px-3 py-2.5 text-xs text-muted-foreground hover:bg-[var(--muted)]/30 hover:text-foreground">
                <ChevronRight className="size-3.5 shrink-0 transition-transform group-open/netonly:rotate-90" strokeWidth={1.5} aria-hidden />
                <span>Только сетевой трафик · {fmtNum(netOnly.length)} {plural(netOnly.length, "период", "периода", "периодов")} · {fmtNum(netEvents)} {plural(netEvents, "событие", "события", "событий")}</span>
                <span className="ml-auto text-[11px]" title="Потоки без входов, команд и приложений: фон, а не поступки">топ {fmtNum(trace.networkTop)} адресов на источник</span>
              </summary>
              <div className="border-t border-border">
                {netOnly.map((s) => <SessionBlock key={s.id} s={s} ctx={ctx} open={false} />)}
              </div>
            </details>
          )}
        </div>
      )}
    </Panel>
  );
}
