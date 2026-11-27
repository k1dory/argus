import type { Metadata } from "next";
import Link from "next/link";
import { Inbox, SlidersHorizontal, X } from "lucide-react";
import { RefreshDataButton } from "@/components/console/refresh-data-button";
import { Pager } from "@/components/console/pager";
import { Empty, PageHeader, Panel, StatTile } from "@/components/console/panel";
import { FeedDay, FeedList } from "@/components/console/feed";
import { FilterTabs } from "@/components/console/filter-tabs";
import { StorageUnavailable } from "@/components/console/storage-error";
import { IncidentRow, type IncidentRowNote } from "@/components/console/incidents/incident-row";
import { ScanSubnetTable, ScanSummaryBlock } from "@/components/console/incidents/scan-summary";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { listUsers, requirePageSession } from "@/lib/auth";
import { ScanGroupActions } from "@/components/console/scan-group-actions";
import { attackFormOptions } from "@/lib/shared/attack";
import { GROUP_ACTION_MAX, GROUP_ROWS_PAGE, isSubnetKey } from "@/lib/shared/scan-groups";
import { ROLE_RANK } from "@/lib/shared/incidents";
import { safeQuery } from "@/lib/clickhouse";
import { INCIDENT_STATUSES, incidentBlockStates, incidentClosuresFor, incidentQueueStats, incidentsList, scanGroupIncidents, scanGroups, scanSummary, verdictsFor } from "@/lib/argus-queries";
import { isIncidentStatus, verdictState } from "@/lib/shared/incidents";
import { REACTION_SECONDS } from "@/lib/shared/incident-sla";
import { incidentUrgency, isFinalStatus, plural } from "@/lib/shared/incident-view";
import { hideVerdicts } from "@/lib/blind";
import { INCIDENT_LEVEL_LABELS } from "@/lib/shared/labels";
import { clampPage } from "@/lib/shared/limits";
import { groupFeedByDay } from "@/lib/shared/feed";
import { fmtNum } from "@/lib/shared/time";
import { RangeFilters } from "@/components/console/range-filters";
import { RangePicker } from "@/components/console/range-picker";
import { describeChips } from "@/lib/shared/filters";
import { INCIDENT_RANGE_FIELDS, INCIDENT_RANGE_KEYS, incidentRangeChips, parseIncidentRanges, pickParams } from "@/lib/shared/page-filters";

export const dynamic = "force-dynamic";
export const metadata: Metadata = { title: "Инциденты" };

const LEVELS = Object.keys(INCIDENT_LEVEL_LABELS);
/** Сколько групп сканов показывать в раскрытой сводке за раз. */
const SCAN_GROUPS_SHOWN = 10;
const SLA_HINT = `Срок первой реакции, 24/7: ${Object.entries(REACTION_SECONDS).map(([l, s]) => `${INCIDENT_LEVEL_LABELS[l] ?? l} — ${s >= 3600 ? `${s / 3600} ч` : `${s / 60} мин`}`).join(", ")}`;
/** Ключи диапазона в адресе: снять чип — убрать их. */
const CHIP_KEYS: Record<string, string[]> = { time: ["range", "from", "to", "period"], level: ["level_min", "level_max"], events: ["events_min", "events_max"] };

export default async function IncidentsPage({ searchParams }: PageProps<"/incidents">) {
  const session = await requirePageSession();
  const params = await searchParams;
  const status = isIncidentStatus(params.status) ? params.status : undefined;
  // level=… — точный уровень (ссылки плиток и старые закладки); кнопок для него нет, в интерфейсе — диапазон.
  const level = typeof params.level === "string" && LEVELS.includes(params.level) ? params.level : undefined;
  const q = typeof params.q === "string" ? params.q.trim().slice(0, 200) : undefined;
  const page = clampPage(params.page);
  const queue = params.queue === "open" || params.queue === "mine" || params.queue === "unassigned" || params.queue === "overdue" ? params.queue : undefined;
  // Сканы снаружи (правила inbound-scan) по умолчанию свёрнуты в сводку над очередью;
  // scans=list — показать их в очереди по одному.
  const scansList = params.scans === "list";
  const subnet = typeof params.subnet === "string" && isSubnetKey(params.subnet) ? params.subnet : undefined;
  const gpage = clampPage(params.gpage);
  const spage = clampPage(params.spage);
  const canEdit = ROLE_RANK[session.role] >= ROLE_RANK.analyst;
  const ranges = parseIncidentRanges(params);
  const rangeQs = pickParams(params, INCIDENT_RANGE_KEYS);
  const rangeChips = incidentRangeChips(ranges);

  const href = (patch: Record<string, string | undefined>) => {
    const qs = new URLSearchParams();
    // Ссылки листания (page/gpage/spage, раскрытие подсети) сохраняют страницы групп; смена
    // фильтра (статус, уровень, очередь, вид сканов) начинает все списки с первой страницы.
    const paging = Object.keys(patch).every((k) => k === "page" || k === "gpage" || k === "spage" || k === "subnet");
    const next = { status, level, q, queue, scans: scansList ? "list" : undefined, subnet,
      gpage: paging && gpage > 1 ? String(gpage) : undefined, spage: paging && spage > 1 ? String(spage) : undefined, ...Object.fromEntries(new URLSearchParams(rangeQs)),
      page: undefined as string | undefined, ...patch };
    for (const [k, v] of Object.entries(next)) if (v) qs.set(k, v);
    const s = qs.toString();
    return s ? `/incidents?${s}` : "/incidents";
  };

  const r = await safeQuery(async () => {
    const [list, stats] = await Promise.all([
      incidentsList({ status, level, q, page, queue, user: session.user, groupScans: !scansList, ranges }),
      incidentQueueStats(session.user),
    ]);
    return { list, stats };
  });
  const filter = { status, level, q, queue, user: session.user, ranges } as const;
  // Сводка и группы сканов — отдельно: их недоступность не мешает очереди.
  const scans = r.ok && !scansList ? await safeQuery(async () => {
    const [summary, groups] = await Promise.all([scanSummary(filter), safeQuery(() => scanGroups({ ...filter, page: gpage }, SCAN_GROUPS_SHOWN))]);
    return { summary, groups };
  }) : null;
  const expanded = r.ok && !scansList && subnet ? await safeQuery(async () => {
    const rows = await scanGroupIncidents(subnet, { ...filter, page: spage });
    const [blocks, users] = await Promise.all([
      incidentBlockStates(rows.map((x) => x.incident_id)),
      session.role === "admin" ? listUsers() : Promise.resolve([]),
    ]);
    return { rows, blocks, users };
  }) : null;
  const verdicts = r.ok ? await safeQuery(() => verdictsFor(r.data.list.rows.map((x) => x.incident_id))) : null;
  const closures = r.ok ? await safeQuery(() => incidentClosuresFor(r.data.list.rows.map((x) => x.incident_id))) : null;
  const now = new Date();

  const chips: { key: string; label: string; remove: string }[] = [
    ...(status ? [{ key: "status", label: `статус: ${INCIDENT_STATUSES[status]}`, remove: href({ status: undefined }) }] : []),
    ...(level ? [{ key: "level-exact", label: `уровень: ${INCIDENT_LEVEL_LABELS[level]}`, remove: href({ level: undefined }) }] : []),
    ...(q ? [{ key: "q", label: `поиск: «${q}»`, remove: href({ q: undefined }) }] : []),
    ...rangeChips.map((c) => ({ key: c.key, label: `${c.label} ${c.value}`, remove: href(Object.fromEntries((CHIP_KEYS[c.key] ?? [`${c.key}_min`, `${c.key}_max`]).map((k) => [k, undefined]))) })),
  ];
  const panelFilters = (status ? 1 : 0) + (level ? 1 : 0) + rangeChips.length;

  return (
    <>
      <PageHeader
        title="Инциденты"
        subtitle={<>Что сработало и кто этим занимается{r.ok && <> · всего <span className="tabular-nums">{fmtNum(r.data.stats.total)}</span></>}</>}
        actions={<RefreshDataButton />}
      />

      {!r.ok ? (
        <StorageUnavailable reason={r.error} />
      ) : (
        <>
          <QueueTiles stats={r.data.stats} withScans={scansList} />

          {scans && (scans.ok ? (scans.data.summary.incidents > 0 || subnet) && (
            <ScanSummaryBlock
              summary={scans.data.summary}
              groups={scans.data.groups.ok ? scans.data.groups.data : []}
              groupsError={!scans.data.groups.ok}
              pageSize={SCAN_GROUPS_SHOWN}
              gpage={gpage}
              subnet={subnet}
              now={now}
              href={href}
            >
              {subnet && expanded && (!expanded.ok ? <p className="mt-3 text-[13px] text-destructive">Инциденты подсети {subnet} временно недоступны.</p> : <div className="mt-4 space-y-2">
                <div className="c-label">Подсеть {subnet} · {spage > 1 || expanded.data.rows.length === GROUP_ROWS_PAGE
                  ? `инциденты ${fmtNum((spage - 1) * GROUP_ROWS_PAGE + 1)}–${fmtNum((spage - 1) * GROUP_ROWS_PAGE + expanded.data.rows.length)}`
                  : `${fmtNum(expanded.data.rows.length)} ${plural(expanded.data.rows.length, ["открытый инцидент", "открытых инцидента", "открытых инцидентов"])}`}</div>
                <ScanSubnetTable rows={expanded.data.rows} blocks={expanded.data.blocks} now={now} />
                {(spage > 1 || expanded.data.rows.length === GROUP_ROWS_PAGE) && (
                  <div className="flex flex-wrap gap-3 text-[13px]">
                    {spage > 1 && <Link href={href({ spage: spage > 2 ? String(spage - 1) : undefined })} className="text-[var(--ring)] hover:underline">← предыдущие</Link>}
                    {expanded.data.rows.length === GROUP_ROWS_PAGE && <Link href={href({ spage: String(spage + 1) })} className="text-[var(--ring)] hover:underline">следующие →</Link>}
                  </div>
                )}
                {canEdit && spage === 1 && expanded.data.rows.length > 0 && expanded.data.rows.length <= GROUP_ACTION_MAX && <ScanGroupActions subnet={subnet}
                  ids={expanded.data.rows.map((x) => x.incident_id)} filter={{ status, level, q, queue, ranges: rangeQs }}
                  attack={attackFormOptions([...new Set(expanded.data.rows.flatMap((x) => x.tags))])}
                  isAdmin={session.role === "admin"} users={expanded.data.users.map((u) => ({ name: u.name, role: u.role }))} />}
                {canEdit && (spage > 1 || expanded.data.rows.length > GROUP_ACTION_MAX) && (
                  <p className="text-[13px] text-muted-foreground">Групповые действия — для группы до {GROUP_ACTION_MAX} инцидентов: уточните фильтр (уровень, очередь) или работайте с инцидентами по одному.</p>
                )}
              </div>)}
            </ScanSummaryBlock>
          ) : <p role="status" className="text-[13px] text-muted-foreground">Сводка сканов снаружи временно недоступна; очередь — без них.</p>)}
          {scansList && <p className="text-[13px] text-muted-foreground">Сканы снаружи показаны в очереди по одному · <Link href={href({ scans: undefined })} className="text-[var(--ring)] hover:underline">свернуть по подсетям</Link></p>}

          <Panel label="Очередь" meta={`${fmtNum(r.data.list.total)} ${plural(r.data.list.total, ["инцидент", "инцидента", "инцидентов"])}`}>
            <div className="mb-3 flex flex-wrap items-center gap-2">
              <FilterTabs
                label="Очередь работы"
                current={queue ?? "all"}
                items={[
                  { key: "all", label: "Все", href: href({ queue: undefined }) },
                  { key: "open", label: "Открытые", href: href({ queue: "open" }) },
                  { key: "mine", label: "Мои", href: href({ queue: "mine" }) },
                  { key: "unassigned", label: "Без ответственного", href: href({ queue: "unassigned" }) },
                  { key: "overdue", label: "Просрочены", href: href({ queue: "overdue" }) },
                ]}
              />
              <form action="/incidents" method="get" role="search" className="ml-auto flex min-w-0 items-center gap-2">
                {status && <input type="hidden" name="status" value={status} />}
                {level && <input type="hidden" name="level" value={level} />}
                {queue && <input type="hidden" name="queue" value={queue} />}
                {scansList && <input type="hidden" name="scans" value="list" />}
                {[...new URLSearchParams(rangeQs)].map(([k, v]) => <input key={k} type="hidden" name={k} value={v} />)}
                <label htmlFor="inc-q" className="sr-only">Поиск по инцидентам</label>
                <Input id="inc-q" name="q" type="search" defaultValue={q ?? ""} maxLength={200} placeholder="Поиск: INC-…, правило, кто, где" className="h-9 w-48 px-3 xl:w-72" />
                <Button type="submit" variant="secondary" size="sm" className="min-h-9">Найти</Button>
              </form>
              <details className="relative">
                <summary className="flex min-h-9 cursor-pointer list-none items-center gap-1.5 rounded-lg border border-[var(--border-strong)] px-3 text-[13px] text-muted-foreground hover:bg-[var(--surface-elevated)] hover:text-foreground [&::-webkit-details-marker]:hidden">
                  <SlidersHorizontal className="size-3.5" strokeWidth={1.5} aria-hidden />
                  Фильтры{panelFilters > 0 && <span className="font-mono text-[12px] text-foreground">({panelFilters})</span>}
                </summary>
                <div className="absolute right-0 z-30 mt-2 w-[min(calc(100vw-2rem),40rem)] space-y-4 rounded-[10px] border border-[var(--border-strong)] bg-[var(--card)] p-4 shadow-xl">
                  <div className="space-y-1.5">
                    <div className="c-label">Статус</div>
                    <FilterTabs
                      label="Статус"
                      current={status ?? "all"}
                      items={[{ key: "all", label: "Любой", href: href({ status: undefined }) }, ...Object.entries(INCIDENT_STATUSES).map(([k, v]) => ({ key: k, label: v, href: href({ status: k }) }))]}
                    />
                  </div>
                  <div className="space-y-1.5">
                    <div className="c-label">Начало инцидента</div>
                    <RangePicker value={ranges.time.range} keys={["24h", "7d", "30d"]} anyLabel="Всё время" />
                  </div>
                  <RangeFilters time timeLabel="Начало, точный интервал UTC" fields={INCIDENT_RANGE_FIELDS} legacy={["level"]} idPrefix="inc" />
                </div>
              </details>
            </div>
            {chips.length > 0 && (
              <ul className="mb-3 flex flex-wrap items-center gap-2" aria-label="Выбранные фильтры">
                {chips.map((c) => (
                  <li key={c.key}>
                    <Link href={c.remove} className="inline-flex min-h-7 items-center gap-1.5 rounded-md border border-border bg-[var(--surface-elevated)] px-2 text-[13px] text-[var(--fg-2)] hover:text-foreground" aria-label={`Снять фильтр: ${c.label}`}>
                      {c.label}<X className="size-3.5" strokeWidth={1.5} aria-hidden />
                    </Link>
                  </li>
                ))}
                {chips.length > 1 && <li><Link href={href({ status: undefined, level: undefined, q: undefined, ...Object.fromEntries(INCIDENT_RANGE_KEYS.map((k) => [k, undefined])) })} className="text-[13px] text-[var(--ring)] hover:underline">сбросить все</Link></li>}
              </ul>
            )}
            {verdicts && !verdicts.ok && (
              <p role="status" className="mb-3 text-[13px] text-[var(--status-warn)]">
                Короткие выводы модели временно недоступны; очередь и действия работают.
              </p>
            )}
            {r.data.list.rows.length === 0 ? (
              q || status || level || queue || rangeChips.length
                ? <Empty icon={Inbox} title="По этим условиям инцидентов нет" hint={rangeChips.length ? `Сейчас: ${describeChips(rangeChips)}.` : undefined}
                    action={<Link href="/incidents" className="text-[13px] text-[var(--ring)] hover:underline">Снять фильтры</Link>} />
                : <Empty icon={Inbox} title="Инцидентов нет" hint="Как только правило сработает, инцидент появится здесь." />
            ) : (
              <QueueFeed
                rows={r.data.list.rows}
                now={now}
                note={(row) => {
                  if (isFinalStatus(row.status)) {
                    const c = closures?.ok ? closures.data[row.incident_id] : undefined;
                    const who = c ? c.kind === "auto_close" ? "Закрыто автоматически" : `Закрыл ${c.actor}` : "Кто закрыл — не записано";
                    return { kind: "closure", text: c?.reason ? `${who} · «${c.reason}»` : who, title: c?.reason || "Причина не записана" };
                  }
                  if (hideVerdicts(row) || !verdicts?.ok) return undefined;
                  const v = verdicts.data[row.incident_id];
                  return verdictState(v) === "shown" && v?.summary_ru ? { kind: "verdict", text: v.summary_ru } : undefined;
                }}
              />
            )}
            <Pager
              page={r.data.list.page}
              pages={Math.max(1, Math.ceil(r.data.list.total / r.data.list.pageSize))}
              total={r.data.list.total}
              pageSize={r.data.list.pageSize}
              href={(p) => href({ page: p > 1 ? String(p) : undefined })}
            />
          </Panel>
        </>
      )}
    </>
  );
}

type Stats = Awaited<ReturnType<typeof incidentQueueStats>>;

/** Плитки про действие: что требует реакции сейчас. Сканы снаружи — второй строкой, пока они свёрнуты. */
function QueueTiles({ stats, withScans }: { stats: Stats; withScans: boolean }) {
  const tile = (key: "criticalOpen" | "overdue" | "unassigned" | "mine") => {
    const own = stats[key];
    const scan = stats.scans[key];
    return { value: withScans ? own + scan : own, scanSub: !withScans && scan > 0 ? `ещё ${fmtNum(scan)} в сканах снаружи` : undefined };
  };
  const crit = tile("criticalOpen");
  const over = tile("overdue");
  const free = tile("unassigned");
  const mine = tile("mine");
  return (
    <div className="grid grid-cols-2 gap-4 lg:grid-cols-4 lg:gap-6">
      <StatTile label="Критических открытых" value={fmtNum(crit.value)} href="/incidents?queue=open&level=critical" tone={crit.value > 0 ? "err" : undefined}
        sub={crit.scanSub ?? (crit.value > 0 ? "требуют внимания сейчас" : "нет")} />
      <StatTile label="Просрочено реакций" value={fmtNum(over.value)} href="/incidents?queue=overdue" tone={over.value > 0 ? "err" : undefined} hint={SLA_HINT}
        sub={over.scanSub ?? "никто не взял в срок"} />
      <StatTile label="Без ответственного" value={fmtNum(free.value)} href="/incidents?queue=unassigned" tone={free.value > 0 ? "warn" : undefined}
        sub={free.scanSub ?? "открытые, никто не взял"} />
      <StatTile label="Мои" value={fmtNum(mine.value)} href="/incidents?queue=mine" tone={mine.value > 0 ? "info" : undefined}
        sub="открытые, где я ответственный" />
    </div>
  );
}

type ListRow = Awaited<ReturnType<typeof incidentsList>>["rows"][number];

/** Лента очереди: сначала «Срочные» (тот же порядок, что ORDER BY запроса), затем по дням. */
function QueueFeed({ rows, now, note }: { rows: ListRow[]; now: Date; note: (row: ListRow) => IncidentRowNote | undefined }) {
  const urgent = rows.filter((x) => incidentUrgency(x, now) !== "normal");
  const rest = rows.filter((x) => incidentUrgency(x, now) === "normal");
  return (
    <FeedList label="Очередь инцидентов" className="p-1">
      {urgent.length > 0 && (
        <FeedDay heading={`Срочные · ${fmtNum(urgent.length)}`}>
          {urgent.map((row) => <IncidentRow key={row.incident_id} row={row} now={now} note={note(row)} blind={hideVerdicts(row)} />)}
        </FeedDay>
      )}
      {groupFeedByDay(rest, (x) => x.created_at, now).map((g) => (
        <FeedDay key={g.key} heading={g.heading}>
          {g.items.map((row) => <IncidentRow key={row.incident_id} row={row} now={now} note={note(row)} blind={hideVerdicts(row)} />)}
        </FeedDay>
      ))}
    </FeedList>
  );
}
