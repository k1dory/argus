"use client";

import { useCallback, useEffect, useRef, useState } from "react";
import Link from "next/link";
import {
  Activity, ArrowLeftRight, ArrowRight, Box, ChevronRight, Cpu, FileText, LogIn, Minus, Pause, Plus, Radio, Server, ShieldAlert, Siren, UserCog, type LucideIcon,
} from "lucide-react";
import { Button } from "@/components/ui/button";
import { cn } from "@/lib/utils";
import { journalHref, withTerm, type IncidentRef, type JournalEvent, type JournalFilters, type JournalPatch, type TailState } from "@/lib/shared/journal";
import { errorStatus, MAX_ROWS, nextStatus, pollTail, TAIL_EVERY_MS, tailStatusText, type TailStatus } from "@/lib/shared/tail-poll";
import { SEVERITY, severityTone } from "@/lib/shared/severity";
import { LEVEL_TONE, STATUS_TONE, TONE_CLASS, toneFor } from "@/components/console/tone";
import { INCIDENT_LEVEL_LABELS } from "@/lib/shared/labels";
import { INCIDENT_STATUSES, isIncidentStatus } from "@/lib/shared/incidents";
import { formatTs, toDate } from "@/lib/shared/time";
import { groupFeedByDay } from "@/lib/shared/feed";
import { actionTitle, eventImportance, eventKind, isBadOutcome, outcomeWord, type EventKind } from "@/lib/shared/event-labels";
import { queryFieldLabel } from "@/lib/shared/query-fields";
import { toDtParam } from "@/lib/shared/journal";
import { FeedDay } from "@/components/console/feed";
import { RawBlock } from "./raw-block";

type Props = {
  initial: JournalEvent[];
  incidents: Record<string, IncidentRef[]>;
  filters: JournalFilters;
  /** Курсор tail «received_at|id» — снимок часов ClickHouse при загрузке страницы. */
  cursor: string;
  /** Live-tail имеет смысл только для «сейчас»: без точного интервала и на первой странице. */
  liveAllowed: boolean;
  /** Движок корреляции отвечает; иначе связь событий с инцидентами неизвестна. */
  engineUp: boolean;
};

/**
 * Лента журнала: двухстрочные строки (человеческий заголовок, сырые значения
 * второй строкой), группировка по дням UTC, подсветка важного, раскрытие
 * по клику на всю строку, слежение за новыми по курсору (received_at, id).
 */
export function EventFeed({ initial, incidents: initialIncidents, filters, cursor: initialCursor, liveAllowed, engineUp }: Props) {
  const [rows, setRows] = useState(initial);
  const [incidents, setIncidents] = useState(initialIncidents);
  const [open, setOpen] = useState<Set<string>>(() => new Set());
  const [fresh, setFresh] = useState<Set<string>>(() => new Set());
  const [live, setLive] = useState(false);
  const [status, setStatus] = useState<TailStatus | null>(null);
  // Новая выдача сервера (фильтры, страница) перемонтирует ленту через key на странице.
  // Состояние tail — в ref: цикл опроса читает и пишет его между await, без гонок с рендером.
  const cursor = useRef(initialCursor);
  const tail = useRef<TailState>({ rows: initial, seen: new Set(initial.map((r) => r.id)) });

  /** Один такт: порции подряд, пока сервер отвечает more (lib/shared/tail-poll). */
  const tick = useCallback(async (signal: AbortSignal) => {
    const r = await pollTail({ filters, cursor: cursor.current, state: tail.current, signal });
    cursor.current = r.cursor;
    tail.current = r.state;
    if (r.added.length) {
      setRows(r.state.rows);
      setFresh(new Set(r.added.map((x) => x.id)));
    }
    if (Object.keys(r.incidents).length) setIncidents((prev) => ({ ...prev, ...r.incidents }));
    return r;
  }, [filters]);

  // Опрос без наложения: следующий такт планируется только после завершения
  // предыдущего (setTimeout после await), скрытая вкладка такт пропускает.
  useEffect(() => {
    if (!live || !liveAllowed) return;
    const ctrl = new AbortController();
    let timer: ReturnType<typeof setTimeout> | undefined;
    const run = async () => {
      if (!document.hidden) {
        try {
          const r = await tick(ctrl.signal);
          if (ctrl.signal.aborted) return;
          setStatus((prev) => nextStatus(prev, r));
          if (r.throttled && !ctrl.signal.aborted) {
            timer = setTimeout(run, r.throttled * 1000);
            return;
          }
        } catch (e) {
          if (ctrl.signal.aborted) return;
          setStatus((prev) => errorStatus(prev, e));
        }
      }
      if (!ctrl.signal.aborted) timer = setTimeout(run, TAIL_EVERY_MS);
    };
    timer = setTimeout(run, 0);
    return () => {
      ctrl.abort();
      clearTimeout(timer);
    };
  }, [live, liveAllowed, tick]);

  const toggle = (id: string) =>
    setOpen((prev) => {
      const next = new Set(prev);
      if (next.has(id)) next.delete(id);
      else next.add(id);
      return next;
    });

  const groups = groupFeedByDay(rows, (r) => r.time);

  return (
    <div className="flex min-w-0 flex-col">
      <div className="flex flex-wrap items-center gap-3 border-b border-[var(--border)] px-4 py-2.5">
        <Button
          type="button"
          variant="secondary"
          size="sm"
          aria-pressed={live}
          disabled={!liveAllowed}
          onClick={() => setLive(!live)}
          title={liveAllowed ? `Подгружать новые события каждые ${TAIL_EVERY_MS / 1000} с` : "Слежение работает для «сейчас»: уберите точный интервал и вернитесь на первую страницу"}
        >
          {live ? <Pause strokeWidth={1.5} aria-hidden /> : <Radio strokeWidth={1.5} aria-hidden />}
          {live ? "Пауза" : "Следить за новыми"}
        </Button>
        <span className="text-[12px] text-[var(--text-tertiary)]" aria-live="polite">
          {live && <span className="mr-1.5 inline-block size-2 rounded-full bg-[var(--status-ok)] align-middle" aria-hidden />}
          {tailStatusText(status, live, liveAllowed)}
        </span>
        {status && status.trimmed > 0 && (
          <span className="text-[12px] text-num" role="status">
            {status.trimmed} старых строк ушли за нижний край ленты (лимит {MAX_ROWS}) — <a href={journalHref(filters, { page: filters.page })} className="underline">обновите</a>, чтобы листать полную выдачу
          </span>
        )}
        <span className="ml-auto text-[12px] text-[var(--text-tertiary)]">время — UTC</span>
      </div>

      {rows.length === 0 ? (
        <p className="px-4 py-12 text-center text-[13px] text-muted-foreground">Событий нет — расширьте интервал или уберите фильтры.</p>
      ) : (
        <div className="px-1.5 pb-1.5" role="region" aria-label="События">
          {groups.map((g) => (
            <FeedDay key={g.key} heading={g.heading} sticky>
              {g.items.map((e) => (
                <EventRow
                  key={e.id}
                  e={e}
                  open={open.has(e.id)}
                  fresh={fresh.has(e.id)}
                  incidents={incidents[e.id] ?? []}
                  filters={filters}
                  engineUp={engineUp}
                  onToggle={() => toggle(e.id)}
                />
              ))}
            </FeedDay>
          ))}
        </div>
      )}
    </div>
  );
}

const KIND_ICON: Record<EventKind, LucideIcon> = {
  auth: LogIn,
  priv: ShieldAlert,
  net: ArrowLeftRight,
  file: FileText,
  k8s: Box,
  threat: Siren,
  identity: UserCog,
  infra: Server,
  system: Cpu,
  other: Activity,
};

/** Вторая строка: сырые значения «действие · кто · где · что · источник», пустые части не выводятся. */
function metaParts(e: JournalEvent, rawAction: boolean): string[] {
  const what = e.object || (e.dst_ip ? `${e.dst_ip}${e.dst_port ? `:${e.dst_port}` : ""}` : "");
  const who = e.actor_name || e.src_ip;
  const action = rawAction && e.action && e.action !== "x" ? [e.action, e.outcome && e.outcome !== "unknown" ? e.outcome : ""].filter(Boolean).join(" ") : "";
  return [action, who, e.node, what, e.source].filter((p): p is string => Boolean(p && p.trim()));
}

function EventRow({ e, open, fresh, incidents, filters, engineUp, onToggle }: { e: JournalEvent; open: boolean; fresh: boolean; incidents: IncidentRef[]; filters: JournalFilters; engineUp: boolean; onToggle: () => void }) {
  const { title, known } = actionTitle(e.action, e.outcome);
  const Icon = KIND_ICON[eventKind(e.action, e.source_class)];
  const imp = eventImportance(e.severity);
  const parts = metaParts(e, known);
  const outcome = outcomeWord(e.outcome);
  const bad = isBadOutcome(e.outcome);
  const time = formatTs(e.time, "time");
  const toneVar = imp === "err" ? "var(--status-err)" : imp === "warn" ? "var(--status-warn)" : undefined;
  return (
    <li
      data-importance={imp ?? undefined}
      className={cn(
        "rounded-md",
        imp && "bg-[color-mix(in_oklab,var(--row-tone)_8%,transparent)] shadow-[inset_2px_0_0_var(--row-tone)]",
        fresh && "row-fresh",
      )}
      style={toneVar ? ({ "--row-tone": toneVar } as React.CSSProperties) : undefined}
    >
      <button
        type="button"
        aria-expanded={open}
        aria-controls={`ev-${e.id}`}
        aria-label={`${open ? "Свернуть" : "Раскрыть"} событие ${time} — ${title}`}
        onClick={onToggle}
        className={cn(
          "flex w-full min-w-0 items-center gap-3 rounded-md px-3 py-2 text-left transition-colors focus-visible:outline-offset-[-2px]",
          imp ? "hover:bg-[color-mix(in_oklab,var(--row-tone)_14%,transparent)]" : "hover:bg-[var(--surface-elevated)]",
          open && !imp && "bg-[var(--surface-elevated)]",
        )}
      >
        <ChevronRight strokeWidth={1.5} className={cn("size-4 shrink-0 text-[var(--text-tertiary)] transition-transform duration-150", open && "rotate-90 text-[var(--ring)]")} aria-hidden />
        <Icon strokeWidth={1.5} className="size-4 shrink-0" style={{ color: toneVar ?? "var(--text-tertiary)" }} aria-hidden />
        <span className="min-w-0 flex-1">
          <span className="flex min-w-0 items-center gap-2">
            <span className={cn("min-w-0 truncate text-[14px] text-foreground", !known && "font-mono text-[13px]")} title={title}>{title}</span>
            {outcome && <span className={cn("shrink-0 text-[12px]", bad ? "text-err" : "text-[var(--text-tertiary)]")}>{outcome}</span>}
            {incidents.length > 0 && (
              <span className={cn("shrink-0 rounded-[6px] border px-1.5 font-mono text-[11px]", TONE_CLASS[toneFor(LEVEL_TONE, incidents[0].level)])} title={`Инцидент: ${incidents[0].rule_title}`}>
                {incidents[0].incident_id}{incidents.length > 1 ? ` +${incidents.length - 1}` : ""}
              </span>
            )}
          </span>
          {parts.length > 0 && (
            <span className="mt-0.5 block truncate font-mono text-[12px] text-muted-foreground" title={parts.join(" · ")}>
              {parts.join(" · ")}
            </span>
          )}
        </span>
        <SevChip v={e.severity} />
        <time dateTime={formatTs(e.time, "iso")} title={`${formatTs(e.time)} UTC`} className="w-[4.5rem] shrink-0 text-right font-mono text-[12px] text-muted-foreground tabular-nums">
          {time}
        </time>
      </button>
      {open && (
        <div id={`ev-${e.id}`} className="border-t border-[var(--border)] px-4 pt-3 pb-5">
          <EventDetail e={e} incidents={incidents} filters={filters} engineUp={engineUp} />
        </div>
      )}
    </li>
  );
}

/** Уровень ≥ 1 — чип тоном шкалы событий; нулевой не показывается (это 80% ленты и шум). */
function SevChip({ v }: { v: number }) {
  if (!(v > 0)) return <span className="w-7 shrink-0" aria-hidden />;
  return (
    <span className={cn("inline-flex h-5 min-w-7 shrink-0 items-center justify-center rounded-[6px] border px-1.5 font-mono text-[11px] tabular-nums", TONE_CLASS[severityTone(SEVERITY.events, v)])} title={`Серьёзность ${v} из 10`}>
      <span className="sr-only">серьёзность </span>{v}
    </span>
  );
}

/** Поля единой схемы: подпись, имя поля в языке запроса (для «+»/«−»). Подписи полей запроса — из lib/shared/query-fields. */
const FIELDS: { key: keyof JournalEvent; label?: string; field?: string }[] = [
  { key: "time", label: "время события" },
  { key: "received", label: "принято" },
  { key: "severity", field: "severity" },
  { key: "source", field: "source" },
  { key: "source_class", field: "class" },
  { key: "vendor", field: "vendor" },
  { key: "product", field: "product" },
  { key: "action", field: "action" },
  { key: "outcome", field: "outcome" },
  { key: "actor_name", field: "actor" },
  { key: "actor_kind", label: "тип субъекта" },
  { key: "object", field: "object" },
  { key: "node", field: "node" },
  { key: "session_id", label: "сеанс" },
  { key: "src_ip", field: "src" },
  { key: "src_port", field: "sport" },
  { key: "dst_ip", field: "dst" },
  { key: "dst_port", field: "dport" },
  { key: "proto", field: "proto" },
  { key: "bytes", label: "байт" },
  { key: "packets", label: "пакетов" },
  { key: "value", label: "значение" },
  { key: "unit", label: "единица" },
  { key: "pii", field: "pii" },
];

const fieldLabel = (f: (typeof FIELDS)[number]): string => {
  const l = f.label ?? (f.field ? queryFieldLabel("events", f.field) : String(f.key));
  return l.charAt(0).toUpperCase() + l.slice(1);
};

function isEmpty(v: unknown): boolean {
  return v === "" || v === null || v === undefined || v === 0 || v === "0" || v === "unknown";
}

const AROUND_MS = 15 * 60_000;

function EventDetail({ e, incidents, filters, engineUp }: { e: JournalEvent; incidents: IncidentRef[]; filters: JournalFilters; engineUp: boolean }) {
  const fields = FIELDS.filter((f) => f.key === "severity" || !isEmpty(e[f.key]));
  const attrs = Object.entries(e.attrs).filter(([, v]) => v !== "");
  const filterHref = (field: string, value: string, negate: boolean): string => {
    // Источник и хост — структурные фильтры панели; остальное — условия свободного запроса.
    const patch: JournalPatch = !negate && field === "source" ? { source: value } : !negate && field === "node" ? { host: value } : { q: withTerm(filters.q, field, value, negate) };
    return journalHref(filters, patch);
  };
  const at = toDate(e.time)?.getTime();
  const around = e.node && at !== undefined ? journalHref({ q: "", range: filters.range }, { host: e.node, from: toDtParam(at - AROUND_MS), to: toDtParam(at + AROUND_MS) }) : null;
  return (
    <div className="flex flex-col gap-4">
      <IncidentStrip incidents={incidents} engineUp={engineUp} />
      {(e.actor_name || around) && (
        <div className="flex flex-wrap gap-x-5 gap-y-1 text-[13px]">
          {e.actor_name && (
            <Link href={`/actors/by-alias?v=${encodeURIComponent(e.actor_name)}`} className="inline-flex items-center gap-1 text-[var(--ring)] hover:underline">
              Паспорт субъекта <span className="font-mono">{e.actor_name}</span> <ArrowRight strokeWidth={1.5} className="size-3.5" aria-hidden />
            </Link>
          )}
          {around && (
            <Link href={around} className="inline-flex items-center gap-1 text-[var(--ring)] hover:underline">
              События хоста <span className="font-mono">{e.node}</span> за ±15 мин <ArrowRight strokeWidth={1.5} className="size-3.5" aria-hidden />
            </Link>
          )}
        </div>
      )}
      <div className="grid min-w-0 gap-5 xl:grid-cols-[minmax(0,5fr)_minmax(0,7fr)]">
        <section aria-label="Поля события" className="min-w-0">
          <h3 className="mb-2 text-[13px] font-semibold">Поля события <span className="font-normal text-[var(--text-tertiary)]">· приведены к единой схеме</span></h3>
          <dl className="grid grid-cols-[10rem_minmax(0,1fr)] border-t border-[var(--border)] text-[13px]">
            {fields.map((f) => (
              <FieldRow key={f.key} label={fieldLabel(f)} value={fmtField(f.key, e[f.key])} raw={String(e[f.key])} field={f.field} href={filterHref} />
            ))}
            {attrs.map(([k, v]) => (
              <FieldRow key={`attr.${k}`} label={k} prefix="attr." value={v} raw={v} field={`attr.${k}`} href={filterHref} mono />
            ))}
          </dl>
        </section>
        <section aria-label="Сырое событие" className="min-w-0">
          <h3 className="mb-2 text-[13px] font-semibold">Сырое событие <span className="font-normal text-[var(--text-tertiary)]">· как пришло от источника</span></h3>
          <RawBlock raw={e.raw} source={e.source} />
        </section>
      </div>
    </div>
  );
}

function fmtField(key: keyof JournalEvent, v: unknown): string {
  if (key === "time" || key === "received") return formatTs(String(v));
  if (key === "pii") return v ? "да" : "нет";
  return String(v);
}

function FieldRow({ label, prefix, value, raw, field, href, mono }: { label: string; prefix?: string; value: string; raw: string; field?: string; href: (field: string, value: string, negate: boolean) => string; mono?: boolean }) {
  return (
    <>
      <dt className={cn("border-b border-[var(--border)] py-1.5 pr-3 text-[12px] text-muted-foreground", mono && "truncate font-mono")} title={prefix ? `${prefix}${label}` : label}>
        {prefix && <span className="text-[var(--text-tertiary)]">{prefix}</span>}
        {label}
      </dt>
      <dd className="group/f flex min-w-0 items-center gap-2 border-b border-[var(--border)] py-1.5">
        <span className="min-w-0 flex-1 font-mono text-[12.5px] break-all text-foreground">{value}</span>
        {field && (
          <span className="flex shrink-0 gap-0.5 opacity-50 transition-opacity group-hover/f:opacity-100 group-focus-within/f:opacity-100">
            <Link href={href(field, raw, false)} aria-label={`Только ${label} = ${raw}`} title="Оставить только такие" className="inline-flex size-6 items-center justify-center rounded-md text-[var(--text-tertiary)] hover:bg-[var(--surface-elevated)] hover:text-foreground">
              <Plus strokeWidth={1.5} className="size-3.5" aria-hidden />
            </Link>
            <Link href={href(field, raw, true)} aria-label={`Исключить ${label} = ${raw}`} title="Исключить такие" className="inline-flex size-6 items-center justify-center rounded-md text-[var(--text-tertiary)] hover:bg-[var(--surface-elevated)] hover:text-foreground">
              <Minus strokeWidth={1.5} className="size-3.5" aria-hidden />
            </Link>
          </span>
        )}
      </dd>
    </>
  );
}

function IncidentStrip({ incidents, engineUp }: { incidents: IncidentRef[]; engineUp: boolean }) {
  if (incidents.length === 0) {
    return engineUp
      ? <p className="text-[13px] text-[var(--text-tertiary)]">Событие не вошло ни в один инцидент.</p>
      : <p className="text-[13px] text-[var(--status-warn)]">Связь с инцидентами сейчас неизвестна: движок корреляции недоступен.</p>;
  }
  return (
    <ul className="flex flex-col gap-2" aria-label="Связанные инциденты">
      {incidents.map((i) => (
        <li key={i.incident_id}>
          <Link
            href={`/incidents/${encodeURIComponent(i.incident_id)}`}
            className="flex flex-wrap items-center gap-x-3 gap-y-1 rounded-[10px] border border-[var(--border-strong)] bg-card px-3 py-2 transition-colors hover:border-[color-mix(in_oklab,var(--ring)_50%,transparent)]"
          >
            <span className="font-mono text-[13px] text-[var(--ring)]">{i.incident_id}</span>
            <span className={cn("rounded-[6px] border px-1.5 text-[11px]", TONE_CLASS[toneFor(LEVEL_TONE, i.level)])}>{INCIDENT_LEVEL_LABELS[i.level] ?? i.level}</span>
            <span className={cn("rounded-[6px] border px-1.5 text-[11px]", TONE_CLASS[toneFor(STATUS_TONE, i.status)])}>{isIncidentStatus(i.status) ? INCIDENT_STATUSES[i.status] : i.status}</span>
            <span className="min-w-0 flex-1 truncate text-[13px] text-foreground">{i.rule_title}</span>
            <span className="font-mono text-[12px] text-[var(--text-tertiary)]">{i.rule_id}</span>
            <span className="text-[12px] text-[var(--ring)]" aria-hidden>Открыть →</span>
          </Link>
        </li>
      ))}
    </ul>
  );
}
