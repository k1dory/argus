import type { Metadata } from "next";
import Link from "next/link";
import { ChevronRight, SlidersHorizontal, Users } from "lucide-react";
import { Ago } from "@/components/console/ago";
import { Copyable } from "@/components/console/copyable";
import { ActorLookupForm } from "@/components/console/actor-lookup-form";
import { ActorPeriodTabs, DataWell, lookupHref, PersonCell } from "@/components/console/actors-section";
import { FilterTabs } from "@/components/console/filter-tabs";
import { Empty, PageHeader, Panel, StatTile } from "@/components/console/panel";
import { StorageUnavailable } from "@/components/console/storage-error";
import { RangeFilters } from "@/components/console/range-filters";
import { Alert, AlertDescription, AlertTitle } from "@/components/ui/alert";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { TableBody, TableCell, TableHead, TableHeader, TableRow } from "@/components/ui/table";
import { safeQuery } from "@/lib/clickhouse";
import { listPersons, unboundSubjects, type PersonSummary } from "@/lib/actors";
import { requireActorAccess } from "@/lib/actors-access";
import { parseActorRange, type ActorRange } from "@/lib/shared/actors";
import { byRisk, isSharedAccount, matchesPersonTab, parsePersonTab, PERSON_TAB_LABELS, PERSON_TABS } from "@/lib/shared/actors-ui";
import { RANGES } from "@/lib/shared/ranges";
import { searchHref } from "@/lib/shared/search-href";
import { fmtNum, formatAgo, formatTs } from "@/lib/shared/time";
import { describeChips, getParam, inRange, timeBounds, timeLabel } from "@/lib/shared/filters";
import { ACTOR_RANGE_FIELDS, actorRangeChips, parseActorRanges } from "@/lib/shared/page-filters";

export const dynamic = "force-dynamic";
export const metadata: Metadata = { title: "Субъекты" };

const THRESHOLDS = ["events_min", "events_max", "incidents_min", "incidents_max"] as const;
/** Сколько учёток без владельца видно сразу; остальные — под раскрытием. */
const UNBOUND_SHOWN = 8;
const RISK_ROW = "bg-[color-mix(in_oklab,var(--status-err)_6%,transparent)]";

export default async function ActorsPage({ searchParams }: PageProps<"/actors">) {
  const session = await requireActorAccess();
  const sp = await searchParams;
  // Один снимок «сейчас» на страницу: относительное время у всех строк от него.
  const now = new Date();
  // Точное окно активности (не шире 30 дней) главнее пресета; пороги событий и инцидентов — по итогам за окно.
  // Пресет — из общего парсера (range или синоним period), по умолчанию 7 дней.
  const ranges = parseActorRanges(sp);
  const range = parseActorRange(ranges.time.range);
  const tab = parsePersonTab(getParam(sp, "show"));
  const bounds = ranges.time.from ? timeBounds(ranges.time) : null;
  const window = bounds ? { fromMs: bounds.startMs, toMs: bounds.endMs } : null;
  const periodLabel = window ? timeLabel(ranges.time) : `за ${RANGES[range].label}`;
  const filtersText = describeChips(actorRangeChips(ranges));
  const thresholdsActive = THRESHOLDS.some((k) => getParam(sp, k) !== undefined);

  // Ссылки страницы: смена периода сохраняет пороги и вкладку и снимает точное окно;
  // смена вкладки сохраняет всё остальное.
  const url = (patch: Record<string, string | null>, dropWindow = false) => {
    const q = new URLSearchParams();
    for (const k of THRESHOLDS) { const v = getParam(sp, k); if (v !== undefined) q.set(k, v); }
    if (!dropWindow) for (const k of ["from", "to"]) { const v = getParam(sp, k); if (v !== undefined) q.set(k, v); }
    if (!window || dropWindow) q.set("range", range);
    if (tab !== "all") q.set("show", tab);
    for (const [k, v] of Object.entries(patch)) { if (v === null) q.delete(k); else q.set(k, v); }
    const s = q.toString();
    return s ? `/actors?${s}` : "/actors";
  };

  // Один период на всю страницу: и персоны, и учётки без владельца.
  const [pr, ur] = await Promise.all([safeQuery(() => listPersons(window ?? range)), safeQuery(() => unboundSubjects(window ?? range))]);
  const all = pr.ok ? pr.data : [];
  const filtered = all.filter((p) => inRange(p.events, ranges.events) && inRange(p.incidents, ranges.incidents));
  const shown = filtered.filter((p) => matchesPersonTab(p, tab)).sort(byRisk);
  const active = shown.filter((p) => p.events > 0 || p.incidents > 0);
  const idle = shown.filter((p) => !(p.events > 0 || p.incidents > 0));
  const isAdmin = session.role === "admin";
  const withIncidents = all.filter((p) => p.incidents > 0).length;
  const services = all.filter((p) => p.kind === "service").length;
  const latest = all.filter((p) => p.last_ts).reduce<PersonSummary | null>((m, p) => (!m || (p.last_ts ?? "") > (m.last_ts ?? "") ? p : m), null);
  const unbound = ur.ok ? ur.data : [];
  const tabCount = (t: (typeof PERSON_TABS)[number]) => filtered.filter((p) => matchesPersonTab(p, t)).length;

  const unboundTable = (rows: typeof unbound) => (
        <DataWell>
      <TableHeader>
        <TableRow className="border-border/60">
          <TableHead className="c-label">Учётка</TableHead>
          <TableHead className="c-label text-right">Событий</TableHead>
          <TableHead className="c-label">Источники</TableHead>
          <TableHead className="c-label">Последнее</TableHead>
          <TableHead className="c-label"><span className="sr-only">Действие</span></TableHead>
        </TableRow>
      </TableHeader>
      <TableBody>
        {rows.map((u) => (
          <TableRow key={u.actor_name} className="border-border/40">
            <TableCell className="text-xs">
              <Copyable value={u.actor_name} href={searchHref.actorEvents(u.actor_name)} label="Учётка" />
              {isSharedAccount(u.actor_name) && <div className="mt-0.5 text-[12px] text-muted-foreground">общая системная учётка — обычно не привязывают к человеку</div>}
            </TableCell>
            <TableCell className="text-right font-mono text-xs tabular-nums">{fmtNum(u.count)}</TableCell>
            <TableCell>
              <div className="flex max-w-[28rem] flex-wrap gap-1">
                {u.sources.length ? u.sources.map((s) => <Badge key={s} variant="outline" className="font-mono font-normal text-muted-foreground">{s}</Badge>) : "—"}
              </div>
            </TableCell>
            <TableCell className="font-mono text-xs"><Ago ts={u.last_ts} now={now} /></TableCell>
            <TableCell className="text-right">
              <Button asChild size="xs" variant="secondary">
                <Link href={lookupHref(u.actor_name, range)}>{isAdmin ? "Привязать" : "Чья это учётка?"}</Link>
              </Button>
            </TableCell>
          </TableRow>
        ))}
      </TableBody>
    </DataWell>
  );

  const unboundPanel = (
    <Panel id="unbound" label={`Учётки без владельца · ${periodLabel}`} meta="встречаются в журнале, но не связаны ни с одним человеком">
      {!ur.ok ? (
        <Alert>
          <AlertTitle>Список недоступен</AlertTitle>
          <AlertDescription>{ur.error}</AlertDescription>
        </Alert>
      ) : unbound.length === 0 ? (
        <Empty>Все учётки, активные {periodLabel}, связаны с людьми.</Empty>
      ) : (
        <div className="space-y-3">
          {unboundTable(unbound.slice(0, UNBOUND_SHOWN))}
          {unbound.length > UNBOUND_SHOWN && (
            <details className="group">
              <summary className="flex cursor-pointer list-none items-center gap-1.5 text-[13px] text-muted-foreground hover:text-foreground [&::-webkit-details-marker]:hidden">
                <ChevronRight className="size-3.5 transition-transform group-open:rotate-90" strokeWidth={1.5} aria-hidden />
                Ещё {fmtNum(unbound.length - UNBOUND_SHOWN)} учёток без владельца
              </summary>
              <div className="mt-3">{unboundTable(unbound.slice(UNBOUND_SHOWN))}</div>
            </details>
          )}
        </div>
      )}
    </Panel>
  );

  const personTable = (rows: PersonSummary[]) => (
    <DataWell>
      <TableHeader>
        <TableRow className="border-border/60">
          <TableHead className="c-label">Персона</TableHead>
          <TableHead className="c-label">Отдел</TableHead>
          <TableHead className="c-label text-right">Инциденты</TableHead>
          <TableHead className="c-label text-right">Событий</TableHead>
          <TableHead className="c-label">Последняя активность</TableHead>
        </TableRow>
      </TableHeader>
      <TableBody>
        {rows.map((p) => (
          <TableRow key={p.person_id} className={p.incidents > 0 ? `border-border/40 ${RISK_ROW}` : "border-border/40"}>
            <TableCell><PersonCell id={p.person_id} display={p.display} kind={p.kind} range={range} /></TableCell>
            <TableCell className="text-[13px] text-muted-foreground">{p.team || "—"}</TableCell>
            <TableCell className="text-right font-mono text-xs tabular-nums">{p.incidents > 0 ? <span className="text-[var(--status-err)]">{fmtNum(p.incidents)}</span> : <span className="text-[var(--text-tertiary)]">0</span>}</TableCell>
            <TableCell className="text-right font-mono text-xs tabular-nums text-muted-foreground">{fmtNum(p.events)}</TableCell>
            <TableCell className="font-mono text-xs">{p.last_ts ? <Ago ts={p.last_ts} now={now} /> : <span className="text-[var(--text-tertiary)]">нет за период</span>}</TableCell>
          </TableRow>
        ))}
      </TableBody>
    </DataWell>
  );

  return (
    <>
      <PageHeader
        title="Субъекты"
        subtitle="Люди и служебные учётки: кто что делал и кто связан с инцидентами. Каждое открытие паспорта записывается в журнал действий."
        actions={<ActorPeriodTabs current={window ? "" : range} href={(r: ActorRange) => url({ range: r }, true)} />}
      />

      <Panel label="Кому принадлежит" meta="почта, логин, телефон, IP, хост — чей сейчас и чей раньше">
        <ActorLookupForm range={range} />
      </Panel>

      {!pr.ok ? (
        <StorageUnavailable reason={pr.error} />
      ) : (
        <div className="grid grid-cols-2 gap-6 lg:grid-cols-4">
          <StatTile
            label="С инцидентами" value={fmtNum(withIncidents)} unit={withIncidents === 1 ? "персона" : "персон"}
            tone={withIncidents > 0 ? "err" : "ok"} sub={periodLabel} href={withIncidents > 0 ? `${url({ show: "incidents" })}#persons` : undefined}
          />
          <StatTile
            label="Без владельца" value={ur.ok ? fmtNum(unbound.length) : "—"} unit="учёток"
            tone={!ur.ok ? "muted" : unbound.length > 0 ? "warn" : "ok"} sub={`в журнале ${periodLabel}`} href={unbound.length > 0 ? "#unbound" : undefined}
          />
          <StatTile
            label="Последняя активность" size="sm"
            value={latest?.last_ts ? formatAgo(latest.last_ts, now) : "нет"}
            hint={latest?.last_ts ? formatTs(latest.last_ts) : undefined}
            sub={latest ? latest.display || latest.person_id : `ни одной персоны ${periodLabel}`}
          />
          <StatTile
            label="Активны" value={fmtNum(all.filter((p) => p.events > 0).length)} unit={`из ${fmtNum(all.length)}`}
            sub={services ? `в справочнике, из них служебных ${fmtNum(services)}` : "персон в справочнике"}
          />
        </div>
      )}

      {unbound.length > 0 && unboundPanel}

      {pr.ok && (
        <Panel
          id="persons" label={`Персоны · ${periodLabel}`}
          meta={<span title="События и инциденты считаются по алиасам персоны в их интервалах действия">{fmtNum(all.length)} в справочнике</span>}
        >
          {all.length === 0 ? (
            <Empty
              icon={Users} title="Персон пока нет"
              hint={unbound.length ? "Привяжите учётку из списка «Учётки без владельца» — персона создастся вместе с привязкой." : "Персоны появятся, когда учётки из журнала свяжут с людьми."}
            >
              {isAdmin && (
                <details className="mt-2 text-left">
                  <summary className="cursor-pointer">Другие способы завести персон</summary>
                  <p className="mt-2 max-w-[60ch]">Файл <span className="font-mono">identities.yml</span> у движка, события <span className="font-mono">identity.alias</span> от экспортёров или <span className="font-mono">PUT /api/v1/identities</span>.</p>
                </details>
              )}
            </Empty>
          ) : (
            <div className="space-y-4">
              <div className="flex flex-wrap items-center gap-3">
                <FilterTabs
                  label="Какие персоны показать" current={tab}
                  items={PERSON_TABS.map((t) => ({ key: t, label: PERSON_TAB_LABELS[t], href: url({ show: t === "all" ? null : t }), count: tabCount(t) }))}
                />
                <details className="group" open={thresholdsActive || !!window}>
                  <summary className="flex min-h-8 cursor-pointer list-none items-center gap-1.5 rounded-md px-2 text-[13px] text-muted-foreground hover:text-foreground [&::-webkit-details-marker]:hidden">
                    <SlidersHorizontal className="size-3.5" strokeWidth={1.5} aria-hidden />
                    Точные фильтры{thresholdsActive || window ? ` · ${filtersText}` : ""}
                  </summary>
                  <div className="mt-3"><RangeFilters time timeLabel="Окно активности, UTC (до 30 дней)" fields={ACTOR_RANGE_FIELDS} idPrefix="actors" /></div>
                </details>
              </div>
              {shown.length === 0 ? (
                <Empty>
                  {thresholdsActive || window ? <>Нет персон по фильтрам: {filtersText} — ослабьте пороги или расширьте окно.</> : <>Нет персон в этой вкладке {periodLabel}.</>}
                </Empty>
              ) : (
                <>
                  {active.length > 0 ? personTable(active) : <Empty>Никто не был активен {periodLabel}.</Empty>}
                  {idle.length > 0 && (
                    <details className="group">
                      <summary className="flex cursor-pointer list-none items-center gap-1.5 text-[13px] text-muted-foreground hover:text-foreground [&::-webkit-details-marker]:hidden">
                        <ChevronRight className="size-3.5 transition-transform group-open:rotate-90" strokeWidth={1.5} aria-hidden />
                        Ещё {fmtNum(idle.length)} без активности {periodLabel}
                      </summary>
                      <div className="mt-3">{personTable(idle)}</div>
                    </details>
                  )}
                </>
              )}
            </div>
          )}
        </Panel>
      )}

      {unbound.length === 0 && unboundPanel}
    </>
  );
}
