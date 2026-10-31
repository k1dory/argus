"use client";

import { Fragment, useCallback, useEffect, useRef, useState } from "react";
import Link from "next/link";
import { ChevronRight, Minus, Plus, Radio, Pause } from "lucide-react";
import { Button } from "@/components/ui/button";
import { cn } from "@/lib/utils";
import { journalHref, withTerm, type IncidentRef, type JournalEvent, type JournalFilters, type JournalPatch, type TailState } from "@/lib/shared/journal";
import { errorStatus, MAX_ROWS, nextStatus, pollTail, TAIL_EVERY_MS, tailStatusText, type TailStatus } from "@/lib/shared/tail-poll";
import { SEVERITY, severityTone } from "@/lib/shared/severity";
import { LEVEL_TONE, STATUS_TONE, TONE_CLASS, toneFor } from "@/components/console/tone";
import { INCIDENT_LEVEL_LABELS } from "@/lib/shared/labels";
import { INCIDENT_STATUSES, isIncidentStatus } from "@/lib/shared/incidents";
import { formatTs } from "@/lib/shared/time";
import { RawBlock } from "./raw-block";

type Props = {
  initial: JournalEvent[];
  incidents: Record<string, IncidentRef[]>;
  filters: JournalFilters;
  /** Курсор tail «received_at|id» — снимок часов ClickHouse при загрузке страницы. */
  cursor: string;
  /** Live-tail имеет смысл только для «сейчас»: без точного интервала и на первой странице. */
  liveAllowed: boolean;
  showDate: boolean;
};

/** Лента журнала: плотные строки, раскрытие по клику, live-tail по курсору (received_at, id). */
export function EventFeed({ initial, incidents: initialIncidents, filters, cursor: initialCursor, liveAllowed, showDate }: Props) {
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
          title={liveAllowed ? `Подгружать новые события каждые ${TAIL_EVERY_MS / 1000} с` : "Live-tail работает для «сейчас»: уберите точный интервал и вернитесь на первую страницу"}
        >
          {live ? <Pause strokeWidth={1.5} aria-hidden /> : <Radio strokeWidth={1.5} aria-hidden />}
          {live ? "Пауза" : "Live-tail"}
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
        <span className="ml-auto text-[12px] text-[var(--text-tertiary)]">в ленте {rows.length}</span>
      </div>

      <div className="overflow-x-auto">
        <table className="w-full min-w-[960px] border-collapse text-[13px]">
          <thead>
            <tr className="border-b border-[var(--border)] text-left text-[12px] text-[var(--text-tertiary)]">
              <th scope="col" className="w-8 py-2 pl-3 font-medium"><span className="sr-only">Раскрыть</span></th>
              <th scope="col" className="py-2 pr-3 font-medium">Время, UTC</th>
              <th scope="col" className="py-2 pr-3 font-medium">Ур.</th>
              <th scope="col" className="py-2 pr-3 font-medium">Источник</th>
              <th scope="col" className="py-2 pr-3 font-medium">Хост</th>
              <th scope="col" className="py-2 pr-3 font-medium">Действие</th>
              <th scope="col" className="py-2 pr-3 font-medium">Субъект → объект</th>
              <th scope="col" className="py-2 pr-4 font-medium">Инцидент</th>
            </tr>
          </thead>
          <tbody>
            {rows.length === 0 && (
              <tr>
                <td colSpan={8} className="px-4 py-12 text-center text-muted-foreground">Событий нет — расширьте интервал или уберите фильтры.</td>
              </tr>
            )}
            {rows.map((e) => {
              const isOpen = open.has(e.id);
              const incs = incidents[e.id] ?? [];
              return (
                <Fragment key={e.id}>
                  <tr
                    className={cn(
                      "cursor-pointer border-b border-[var(--border)] align-middle font-mono text-[12.5px] transition-colors hover:bg-[var(--surface-elevated)]",
                      isOpen && "bg-[var(--surface-elevated)]",
                      fresh.has(e.id) && "row-fresh",
                    )}
                    onClick={() => toggle(e.id)}
                  >
                    <td className="py-1.5 pl-3">
                      <button
                        type="button"
                        aria-expanded={isOpen}
                        aria-controls={`ev-${e.id}`}
                        aria-label={isOpen ? "Свернуть событие" : "Раскрыть событие"}
                        onClick={(ev) => {
                          ev.stopPropagation();
                          toggle(e.id);
                        }}
                        className="inline-flex size-6 items-center justify-center rounded-md text-[var(--text-tertiary)] hover:text-foreground"
                      >
                        <ChevronRight strokeWidth={1.5} className={cn("size-4 transition-transform duration-150", isOpen && "rotate-90 text-[var(--ring)]")} aria-hidden />
                      </button>
                    </td>
                    <td className="py-1.5 pr-3 whitespace-nowrap text-foreground tabular-nums">
                      <time dateTime={formatTs(e.time, "iso")} title={formatTs(e.time)}>
                        {showDate && <span className="text-[var(--text-tertiary)]">{formatTs(e.time, "date").slice(5)} </span>}
                        {formatTs(e.time, "time")}
                      </time>
                    </td>
                    <td className="py-1.5 pr-3"><SevChip v={e.severity} /></td>
                    <td className="max-w-[12rem] truncate py-1.5 pr-3 text-muted-foreground" title={e.source}>{e.source}</td>
                    <td className="max-w-[12rem] truncate py-1.5 pr-3 text-foreground" title={e.node}>{e.node || <span className="text-[var(--text-disabled)]">—</span>}</td>
                    <td className="py-1.5 pr-3 whitespace-nowrap">
                      <span className="text-foreground">{e.action || "—"}</span>
                      {e.outcome && e.outcome !== "unknown" && <Outcome v={e.outcome} />}
                    </td>
                    <td className="max-w-[28rem] truncate py-1.5 pr-3 text-muted-foreground" title={summary(e)}>{summary(e)}</td>
                    <td className="py-1.5 pr-4 whitespace-nowrap">
                      {incs.length > 0 ? (
                        <Link href={`/incidents/${encodeURIComponent(incs[0].incident_id)}`} onClick={(ev) => ev.stopPropagation()} className="text-[var(--ring)] hover:underline" title={incs[0].rule_title}>
                          {incs[0].incident_id}
                          {incs.length > 1 && <span className="text-[var(--text-tertiary)]"> +{incs.length - 1}</span>}
                        </Link>
                      ) : (
                        <span className="text-[var(--text-disabled)]">—</span>
                      )}
                    </td>
                  </tr>
                  {isOpen && (
                    <tr id={`ev-${e.id}`} className="border-b border-[var(--border)] bg-[var(--surface-elevated)]/40">
                      <td colSpan={8} className="px-4 pt-3 pb-5">
                        <EventDetail e={e} incidents={incs} filters={filters} />
                      </td>
                    </tr>
                  )}
                </Fragment>
              );
            })}
          </tbody>
        </table>
      </div>
    </div>
  );
}

function summary(e: JournalEvent): string {
  const who = e.actor_name || e.src_ip || "";
  const what = e.object || (e.dst_ip ? `${e.dst_ip}${e.dst_port ? `:${e.dst_port}` : ""}` : "");
  if (who && what) return `${who} → ${what}`;
  return who || what || "—";
}

function SevChip({ v }: { v: number }) {
  return <span className={cn("inline-flex h-5 min-w-7 items-center justify-center rounded-[6px] border px-1.5 text-[11px] tabular-nums", TONE_CLASS[severityTone(SEVERITY.events, v)])}>{v}</span>;
}

function Outcome({ v }: { v: string }) {
  const bad = v === "deny" || v === "failure" || v === "detected";
  return <span className={cn("ml-2 text-[11px]", bad ? "text-err" : "text-[var(--text-tertiary)]")}>{v}</span>;
}

/** Поля единой схемы: подпись, имя поля в языке запроса (для «+»/«−»), значение. */
const FIELDS: { key: keyof JournalEvent; label: string; field?: string }[] = [
  { key: "time", label: "время события" },
  { key: "received", label: "принято" },
  { key: "severity", label: "серьёзность", field: "severity" },
  { key: "source", label: "источник", field: "source" },
  { key: "source_class", label: "класс", field: "class" },
  { key: "vendor", label: "вендор", field: "vendor" },
  { key: "product", label: "продукт", field: "product" },
  { key: "action", label: "действие", field: "action" },
  { key: "outcome", label: "исход", field: "outcome" },
  { key: "actor_name", label: "субъект", field: "actor" },
  { key: "actor_kind", label: "тип субъекта" },
  { key: "object", label: "объект", field: "object" },
  { key: "node", label: "хост", field: "node" },
  { key: "session_id", label: "сеанс" },
  { key: "src_ip", label: "src ip", field: "src" },
  { key: "src_port", label: "src port", field: "sport" },
  { key: "dst_ip", label: "dst ip", field: "dst" },
  { key: "dst_port", label: "dst port", field: "dport" },
  { key: "proto", label: "протокол", field: "proto" },
  { key: "bytes", label: "байт" },
  { key: "packets", label: "пакетов" },
  { key: "value", label: "значение" },
  { key: "unit", label: "единица" },
  { key: "pii", label: "ПДн", field: "pii" },
];

function isEmpty(v: unknown): boolean {
  return v === "" || v === null || v === undefined || v === 0 || v === "0" || v === "unknown";
}

function EventDetail({ e, incidents, filters }: { e: JournalEvent; incidents: IncidentRef[]; filters: JournalFilters }) {
  const fields = FIELDS.filter((f) => f.key === "severity" || !isEmpty(e[f.key]));
  const attrs = Object.entries(e.attrs).filter(([, v]) => v !== "");
  const filterHref = (field: string, value: string, negate: boolean): string => {
    // Источник и хост — структурные фильтры панели; остальное — условия свободного запроса.
    const patch: JournalPatch = !negate && field === "source" ? { source: value } : !negate && field === "node" ? { host: value } : { q: withTerm(filters.q, field, value, negate) };
    return journalHref(filters, patch);
  };
  return (
    <div className="flex flex-col gap-4">
      <IncidentStrip incidents={incidents} />
      <div className="grid min-w-0 gap-5 xl:grid-cols-[minmax(0,5fr)_minmax(0,7fr)]">
        <section aria-label="Нормализованные поля" className="min-w-0">
          <h3 className="mb-2 text-[13px] font-semibold">Нормализованные поля <span className="font-normal text-[var(--text-tertiary)]">· единая схема events</span></h3>
          <dl className="grid grid-cols-[9rem_minmax(0,1fr)] border-t border-[var(--border)] text-[13px]">
            {fields.map((f) => (
              <FieldRow key={f.key} label={f.label} value={fmtField(f.key, e[f.key])} raw={String(e[f.key])} field={f.field} href={filterHref} />
            ))}
            {attrs.map(([k, v]) => (
              <FieldRow key={`attr.${k}`} label={`attr.${k}`} value={v} raw={v} field={`attr.${k}`} href={filterHref} mono />
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

function FieldRow({ label, value, raw, field, href, mono }: { label: string; value: string; raw: string; field?: string; href: (field: string, value: string, negate: boolean) => string; mono?: boolean }) {
  return (
    <>
      <dt className={cn("border-b border-[var(--border)] py-1.5 pr-3 text-[12px] text-[var(--text-tertiary)]", mono && "truncate font-mono")} title={label}>{label}</dt>
      <dd className="group/f flex min-w-0 items-center gap-2 border-b border-[var(--border)] py-1.5">
        <span className="min-w-0 flex-1 font-mono text-[12.5px] break-all text-foreground">{value}</span>
        {field && (
          <span className="flex shrink-0 gap-0.5 opacity-0 transition-opacity group-hover/f:opacity-100 group-focus-within/f:opacity-100">
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

function IncidentStrip({ incidents }: { incidents: IncidentRef[] }) {
  if (incidents.length === 0) {
    return <p className="text-[13px] text-[var(--text-tertiary)]">Событие не вошло ни в один инцидент: движок не связал его с правилом корреляции.</p>;
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
