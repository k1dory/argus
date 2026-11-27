import type { Metadata } from "next";
import Link from "next/link";
import { Activity, PlugZap, RadioTower } from "lucide-react";
import { Copyable } from "@/components/console/copyable";
import { searchHref } from "@/lib/shared/search-href";
import { Empty, Led, PageHeader, Panel, StatTile } from "@/components/console/panel";
import { StorageUnavailable } from "@/components/console/storage-error";
import { Ago } from "@/components/console/ago";
import { FeedDay, FeedList, FeedRow } from "@/components/console/feed";
import { FilterTabs } from "@/components/console/filter-tabs";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from "@/components/ui/table";
import { requirePageSession } from "@/lib/auth";
import { safeQuery } from "@/lib/clickhouse";
import { eventsRecent, sourcesHealthReport, STALE_SOURCES_LIMIT, type EventRow, type SourceHealth } from "@/lib/argus-queries";
import { describeThreshold, RHYTHM_WINDOW_DAYS } from "@/lib/shared/source-health";
import { flowText, parseSourceStatus, sourceStatusPhrase, splitByStatus, type SourceStatusKey } from "@/lib/shared/source-status";
import { countOf, SOURCES_FORMS } from "@/lib/shared/plural";
import { fmtNum, formatTs } from "@/lib/shared/time";
import { groupFeedByDay } from "@/lib/shared/feed";
import { SEVERITY, severityTone } from "@/lib/shared/severity";
import { RangeFilters } from "@/components/console/range-filters";
import { SourceHealthFilters } from "@/components/console/source-health-filters";
import { RangePicker } from "@/components/console/range-picker";
import { describeChips, inRange, inTime, patchHref, type SearchParamsLike } from "@/lib/shared/filters";
import { parseSourceRanges, SOURCE_FEED_FIELDS, sourceFeedChips, sourceHealthChips, type SourceRanges } from "@/lib/shared/page-filters";
import { cn } from "@/lib/utils";

export const dynamic = "force-dynamic";
export const metadata: Metadata = { title: "Источники" };

export default async function SourcesPage({ searchParams }: PageProps<"/sources">) {
  await requirePageSession();
  const ingestBase = (process.env.INGEST_PUBLIC_URL || `https://${process.env.CONSOLE_HOST || "localhost"}:8089`).replace(/\/$/, "");
  const params = await searchParams;
  const source = typeof params.source === "string" ? params.source.slice(0, 200) : undefined;
  const sourceClass = typeof params.class === "string" && params.class ? params.class.slice(0, 64) : undefined;
  const status = parseSourceStatus(params.status);
  // Таблица — фильтр в памяти по статусу, классу, последнему приёму, событиям за час и EPS.
  // Лента — только выбранного источника (окно по received_at и серьёзность в запросе);
  // общая лента всех источников живёт в «Журнале».
  const ranges = parseSourceRanges(params);
  const r = await safeQuery(() => Promise.all([
    sourcesHealthReport(),
    source ? eventsRecent(source, 60, { time: ranges.time, severity: ranges.severity }) : Promise.resolve([] as EventRow[]),
  ]));

  return (
    <>
      <PageHeader
        title="Источники"
        subtitle="Откуда ARGUS получает события и кто из источников замолчал дольше своего обычного ритма."
        actions={<Button asChild variant="ghost" size="sm"><a href="#connect"><PlugZap strokeWidth={1.5} />Как подключить источник</a></Button>}
      />
      {!r.ok ? (
        <StorageUnavailable reason={r.error} />
      ) : (
        <SourcesBody
          health={r.data[0].sources}
          omitted={r.data[0].omitted}
          events={r.data[1]}
          source={source}
          sourceClass={sourceClass}
          status={status}
          ranges={ranges}
          sp={params}
        />
      )}
      <ConnectHelp ingestBase={ingestBase} />
    </>
  );
}

function SourcesBody({
  health, omitted, events, source, sourceClass, status, ranges, sp,
}: {
  health: SourceHealth[];
  omitted: number;
  events: EventRow[];
  source?: string;
  sourceClass?: string;
  status: SourceStatusKey;
  ranges: SourceRanges;
  sp: SearchParamsLike;
}) {
  const now = new Date();
  const all = splitByStatus(health);
  const silentTotal = all.silent.length + omitted;
  const total = health.length + omitted;
  const eps = health.reduce((a, h) => a + h.eps_60s, 0);
  const classes = new Set(health.map((h) => h.source_class));
  const healthText = describeChips(sourceHealthChips(ranges));
  // Фильтры условий и класса — до вкладок: счётчики вкладок показывают, сколько в каждой при этих условиях.
  const filtered = health.filter((h) =>
    (!sourceClass || h.source_class === sourceClass)
    && inTime(h.last_ts, ranges.seen, now.getTime()) && inRange(h.events_1h, ranges.events) && inRange(h.eps_60s, ranges.eps));
  const groups = splitByStatus(filtered);
  const shownGroups = [
    ...(status !== "alive" ? [{ key: "silent", title: "Молчат", rows: groups.silent }] : []),
    ...(status !== "silent" ? [{ key: "alive", title: "Работают", rows: groups.alive }] : []),
  ].filter((g) => g.rows.length > 0);
  const shown = shownGroups.reduce((a, g) => a + g.rows.length, 0);
  const tabHref = (key: SourceStatusKey) => patchHref("/sources", sp, { status: key === "all" ? undefined : key });

  return (
    <>
      <div className="grid grid-cols-2 gap-6 md:grid-cols-4">
        <StatTile
          label="Молчат"
          value={`${fmtNum(silentTotal)} из ${fmtNum(total)}`}
          tone={total === 0 ? "warn" : silentTotal > 0 ? "err" : "ok"}
          href={patchHref("/sources", sp, { status: "silent" })}
          sub={total === 0 ? "источников ещё нет" : silentTotal > 0 ? "дольше своего обычного ритма" : "все в своём ритме"}
        />
        <StatTile
          label="Работают"
          value={fmtNum(all.alive.length)}
          tone={all.alive.length > 0 ? "ok" : undefined}
          href={patchHref("/sources", sp, { status: "alive" })}
          sub="шлют события в своём ритме"
        />
        <StatTile
          label="Поток сейчас"
          value={eps > 0 ? fmtNum(eps, eps < 10 ? 1 : 0) : "0"}
          unit="соб/с"
          tone={eps === 0 && health.length > 0 ? "err" : undefined}
          sub="за последние 60 секунд"
          note={eps === 0 && health.length > 0 ? "приём остановлен" : undefined}
          noteTone="err"
        />
        <StatTile
          label={`Источники за ${RHYTHM_WINDOW_DAYS} суток`}
          value={countOf(total, SOURCES_FORMS)}
          size="sm"
          sub={`${fmtNum(classes.size)} ${classes.size === 1 ? "класс" : classes.size >= 2 && classes.size <= 4 ? "класса" : "классов"}`}
        />
      </div>

      <Panel label="Источники" meta={source ? undefined : "нажмите на источник, чтобы увидеть его события"}>
        {omitted > 0 && (
          <p className="mb-3 text-sm text-[var(--status-warn)]" role="status">
            Замолчавших источников больше {fmtNum(STALE_SOURCES_LIMIT)}: ещё {fmtNum(omitted)} давно молчащих не показаны.
          </p>
        )}
        <div className="mb-4 flex flex-wrap items-start justify-between gap-3">
          <div className="flex flex-wrap items-center gap-2">
            <FilterTabs
              label="Статус источников"
              current={status}
              items={[
                { key: "all", label: "Все", href: tabHref("all"), count: filtered.length },
                { key: "silent", label: "Молчат", href: tabHref("silent"), count: groups.silent.length, icon: RadioTower },
                { key: "alive", label: "Работают", href: tabHref("alive"), count: groups.alive.length, icon: Activity },
              ]}
            />
            {sourceClass && (
              <Button asChild variant="secondary" size="sm">
                <Link href={patchHref("/sources", sp, { class: undefined })} aria-label={`Убрать фильтр класса ${sourceClass}`}>
                  класс: <span className="font-mono">{sourceClass}</span> ✕
                </Link>
              </Button>
            )}
          </div>
          <div className="min-w-0 sm:max-w-[60%]"><SourceHealthFilters shown={shown} total={health.length} ranges={ranges} /></div>
        </div>
        {health.length === 0 ? (
          <Empty
            icon={RadioTower}
            title={`За последние ${RHYTHM_WINDOW_DAYS} суток событий нет`}
            hint="Подключите первый источник — адреса и порты приёма ниже."
            action={<Button asChild variant="secondary" size="sm"><a href="#connect">Как подключить источник</a></Button>}
          />
        ) : shown === 0 ? (
          <Empty>
            {status !== "all" && !healthText && !sourceClass
              ? status === "silent" ? "Молчащих источников нет — все шлют события в своём ритме." : "Работающих источников нет."
              : `Нет источников по фильтрам${healthText ? `: ${healthText}` : ""}${sourceClass ? `${healthText ? "," : ":"} класс ${sourceClass}` : ""} — ослабьте условия.`}
          </Empty>
        ) : (
          <div className="c-well overflow-x-auto p-2">
            <Table>
              <TableHeader>
                <TableRow className="border-border/60">
                  <TableHead className="c-label">Источник</TableHead>
                  <TableHead className="c-label">Класс</TableHead>
                  <TableHead className="c-label">Состояние</TableHead>
                  <TableHead className="c-label text-right">Поток</TableHead>
                </TableRow>
              </TableHeader>
              {shownGroups.map((g) => (
                <TableBody key={g.key}>
                  <TableRow className="border-border/60 hover:bg-transparent">
                    <TableCell colSpan={4} className="pt-4 pb-1.5">
                      <h3 className={cn("text-[12px] font-medium", g.key === "silent" ? "text-[var(--status-err)]" : "text-[var(--text-tertiary)]")}>
                        {g.title} — {fmtNum(g.rows.length)}
                      </h3>
                    </TableCell>
                  </TableRow>
                  {(status === "all" ? g.rows.slice(0, GROUP_PREVIEW) : g.rows).map((h) => <SourceRow key={h.source} h={h} active={h.source === source} sp={sp} now={now} />)}
                  {status === "all" && g.rows.length > GROUP_PREVIEW && (
                    <TableRow className="border-border/40 hover:bg-transparent">
                      <TableCell colSpan={4} className="py-2 text-xs">
                        <Link href={tabHref(g.key as SourceStatusKey)} className="text-[var(--ring)] hover:underline">
                          Ещё {fmtNum(g.rows.length - GROUP_PREVIEW)} — показать все {g.key === "silent" ? "молчащие" : "работающие"} →
                        </Link>
                      </TableCell>
                    </TableRow>
                  )}
                </TableBody>
              ))}
            </Table>
          </div>
        )}
      </Panel>

      {source ? (
        <SourceFeed source={source} events={events} ranges={ranges} sp={sp} now={now} />
      ) : (
        <p className="text-sm text-muted-foreground">
          Последние события всех источников — в <Link href="/events" className="text-[var(--ring)] hover:underline">Журнале →</Link>
        </p>
      )}
    </>
  );
}

/** Во вкладке «Все» каждая группа — первые строки; полный список — во вкладке статуса. */
const GROUP_PREVIEW = 10;

function SourceRow({ h, active, sp, now }: { h: SourceHealth; active: boolean; sp: SearchParamsLike; now: Date }) {
  const phrase = sourceStatusPhrase(h);
  const silent = !h.alive;
  return (
    <TableRow
      className={cn("border-border/40", silent && "bg-[color-mix(in_oklab,var(--status-err)_6%,transparent)]", active && "bg-[var(--muted)]")}
      aria-current={active ? "true" : undefined}
    >
      <TableCell className="text-xs">
        <span className="flex min-w-0 items-center gap-2">
          {active && <span className="text-[var(--ring)]" aria-hidden>▸</span>}
          <Link
            href={patchHref("/sources", sp, { source: h.source })}
            className="truncate font-mono text-foreground hover:text-[var(--ring)] hover:underline"
            title={`События источника ${h.source}`}
          >
            {h.source}
          </Link>
          {h.pii_share > 0 && (
            <Badge variant="outline" className="shrink-0 text-[11px] text-[var(--status-warn)]" title="Доля событий с персональными данными за час">
              ПДн {fmtNum(h.pii_share, 1)} %
            </Badge>
          )}
        </span>
      </TableCell>
      <TableCell className="text-xs text-muted-foreground">{h.source_class}</TableCell>
      <TableCell className="text-xs">
        <span className="flex flex-wrap items-center gap-x-2 gap-y-0.5" title={describeThreshold(h.silence_threshold_sec, h.silent_for_sec)}>
          <Led color={silent ? "var(--status-err)" : "var(--status-ok)"} />
          <span className={silent ? "font-medium text-[var(--status-err)]" : "text-foreground"}>{phrase.head}</span>
          <span className="text-muted-foreground">· {phrase.rhythm}</span>
          <span className="text-[var(--text-tertiary)]">
            · последнее событие {silent
              ? <time dateTime={formatTs(h.last_ts, "iso")} title={formatTs(h.last_ts)}>{formatTs(h.last_ts, "short")}</time>
              : <Ago ts={h.last_ts} now={now} />}
          </span>
        </span>
      </TableCell>
      <TableCell className={cn("text-right font-mono text-xs tabular-nums", h.eps_60s > 0 ? "text-foreground" : "text-[var(--text-tertiary)]")}>
        {flowText(h.eps_60s)}
      </TableCell>
    </TableRow>
  );
}

const OUTCOME_TEXT: Record<string, string> = { success: "успех", ok: "успех", failure: "отказ", fail: "отказ", denied: "отказ", error: "ошибка" };
const SEV_LABEL: Record<string, string> = { err: "критичная", warn: "высокая", neutral: "средняя", muted: "низкая" };

function SourceFeed({ source, events, ranges, sp, now }: { source: string; events: EventRow[]; ranges: SourceRanges; sp: SearchParamsLike; now: Date }) {
  const feedText = describeChips(sourceFeedChips(ranges));
  return (
    <Panel
      label={`События источника ${source}`}
      actions={
        <>
          <Button asChild variant="ghost" size="xs"><Link href={searchHref.source(source)}>В журнале →</Link></Button>
          <Button asChild variant="ghost" size="xs"><Link href={patchHref("/sources", sp, { source: undefined })}>Закрыть</Link></Button>
        </>
      }
    >
      <div className="mb-4 flex flex-wrap items-center gap-3">
        <RangePicker value={ranges.time.from || ranges.time.to ? undefined : ranges.time.range} keys={["1h", "24h", "7d", "30d"]} />
        <details className="group">
          <summary className="cursor-pointer list-none text-[13px] text-muted-foreground hover:text-foreground">
            Точный интервал и серьёзность <span aria-hidden className="inline-block transition-transform group-open:rotate-180">▾</span>
          </summary>
          <div className="mt-3"><RangeFilters time timeLabel="Поступило, точный интервал UTC" fields={SOURCE_FEED_FIELDS} idPrefix="src-feed" /></div>
        </details>
      </div>
      {events.length === 0 ? (
        <Empty>{feedText ? `Поступлений от «${source}» по фильтрам нет: ${feedText}.` : `За 24 часа новых поступлений от «${source}» нет.`}</Empty>
      ) : (
        <FeedList label={`События источника ${source}`}>
          {groupFeedByDay(events, (e) => e.received_at, now).map((g) => (
            <FeedDay key={g.key} heading={g.heading}>
              {g.items.map((e, i) => {
                const tone = severityTone(SEVERITY.events, e.severity);
                const hot = tone === "err" || tone === "warn";
                const outcome = OUTCOME_TEXT[e.outcome?.toLowerCase()] ?? "";
                const target = e.object || (e.dst_ip ? `${e.dst_ip}:${e.dst_port}` : e.src_ip);
                const lag = Math.abs((Date.parse(e.received_at.replace(" ", "T") + "Z") - Date.parse(e.ts.replace(" ", "T") + "Z")) / 60000);
                return (
                  <FeedRow
                    key={`${e.ts}|${e.action}|${e.actor_name}|${i}`}
                    title={`${e.action || "—"}${outcome ? ` · ${outcome}` : ""}`}
                    badge={
                      <span className="flex shrink-0 items-center gap-1.5">
                        <Badge variant="outline" className={cn("text-[11px]", hot ? (tone === "err" ? "text-[var(--status-err)]" : "text-[var(--status-warn)]") : "text-muted-foreground")}>
                          {SEV_LABEL[tone] ?? "низкая"}
                        </Badge>
                        {e.pii === 1 && <Badge variant="outline" className="text-[11px]">ПДн</Badge>}
                      </span>
                    }
                    meta={[
                      e.actor_name ? <Copyable value={e.actor_name} href={searchHref.actor(e.actor_name)} label="Субъект" className="[&_a]:text-[var(--fg-2)] [&_a:hover]:text-[var(--ring)]" /> : null,
                      target ? <span className="font-mono">{target}</span> : null,
                      e.node ? <Copyable value={e.node} href={searchHref.node(e.node)} label="Узел" className="[&_a]:text-muted-foreground [&_a:hover]:text-[var(--ring)]" /> : null,
                      Number.isFinite(lag) && lag > 1 ? <span className="text-[var(--status-warn)]">событие {formatTs(e.ts, "time")}, пришло с задержкой {fmtNum(Math.round(lag))} мин</span> : null,
                    ]}
                    time={formatTs(e.received_at, "time")}
                    timeTitle={formatTs(e.received_at)}
                    flagged={hot}
                    tone={hot ? tone : undefined}
                  />
                );
              })}
            </FeedDay>
          ))}
        </FeedList>
      )}
    </Panel>
  );
}

/** Адреса приёма — свёрнуты внизу; ссылка «Как подключить источник» в шапке раскрывает их якорем. */
function ConnectHelp({ ingestBase }: { ingestBase: string }) {
  return (
    <details id="connect" className="win group open:pb-1">
      <summary className="flex cursor-pointer list-none items-center gap-2 px-5 py-3 text-sm font-medium text-foreground">
        <PlugZap className="size-4 text-muted-foreground" strokeWidth={1.5} aria-hidden />
        Как подключить источник
        <span aria-hidden className="ml-auto text-muted-foreground transition-transform group-open:rotate-180">▾</span>
      </summary>
      <dl className="grid gap-x-6 gap-y-3 px-5 pb-4 text-sm sm:grid-cols-[auto_1fr]">
        <dt className="text-muted-foreground">Syslog и CEF</dt>
        <dd><Copyable value=":5514" label="Порт" /> <span className="text-muted-foreground">TCP/UDP</span></dd>
        <dt className="text-muted-foreground">NetFlow v9</dt>
        <dd><Copyable value=":2055" label="Порт" /> <span className="text-muted-foreground">UDP</span></dd>
        <dt className="text-muted-foreground">Вебхуки (HTTPS)</dt>
        <dd className="min-w-0"><Copyable value={`${ingestBase}/ingest/<тип>`} label="Адрес" /> <span className="text-muted-foreground">с заголовком</span> <Copyable value="X-Argus-Token" label="Заголовок" /></dd>
      </dl>
    </details>
  );
}
