import type { Metadata } from "next";
import Link from "next/link";
import { notFound } from "next/navigation";
import { ChevronRight } from "lucide-react";
import { Copyable } from "@/components/console/copyable";
import { DownloadButton } from "@/components/console/download-button";
import { ActorRangeLinks, BindAliasForm, CloseAliasButton, ConfirmAliasButton } from "@/components/console/actor-forms";
import { LevelBadge, StatusBadge } from "@/components/console/incident-badges";
import { Empty, Led, PageHeader, Panel, StatTile } from "@/components/console/panel";
import { StorageUnavailable } from "@/components/console/storage-error";
import { Alert, AlertDescription, AlertTitle } from "@/components/ui/alert";
import { Badge } from "@/components/ui/badge";
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from "@/components/ui/table";
import { safeQuery } from "@/lib/clickhouse";
import { audit } from "@/lib/argus-queries";
import { actorReport, actorTrace, getPerson, personAliases } from "@/lib/actors";
import { ActorTraceView } from "@/components/console/actor-trace";
import { attachIncidents, ownerScope, type ActorTrace } from "@/lib/shared/actor-trace";
import { ActorFeed } from "@/components/console/actor-feed";
import { buildFeed, parseFeedFilter, type FeedFilter } from "@/lib/shared/actor-feed";
import { ALIAS_KIND_LABELS, tsMs, aliasEventsHref, aliasKey, holdPolicy, isHeld, parseActorRange, PERSON_ID_RE, primaryAlias, SECTION_LABELS, SECTIONS, type ActorRange, type ActorReport, type Alias, type Section } from "@/lib/shared/actors";
import { isIncidentStatus } from "@/lib/shared/incidents";
import type { LogItem } from "@/lib/shared/log-query";
import { RANGES } from "@/lib/shared/ranges";
import { searchHref } from "@/lib/shared/search-href";
import { fmtNum, formatTs } from "@/lib/shared/time";
import { requireActorAccess } from "@/lib/actors-access";

export const dynamic = "force-dynamic";

export async function generateMetadata({ params }: PageProps<"/actors/[id]">): Promise<Metadata> {
  const { id } = await params;
  return { title: `${PERSON_ID_RE.test(id) ? id : "Субъект"} · Субъекты` };
}

const TIMELINE_LIMIT = 200;

export default async function ActorPage({ params, searchParams }: PageProps<"/actors/[id]">) {
  const session = await requireActorAccess();
  const { id } = await params;
  if (!PERSON_ID_RE.test(id)) notFound();
  const sp = await searchParams;
  const range = parseActorRange(typeof sp.range === "string" ? sp.range : undefined);
  const feed = parseFeedFilter(typeof sp.feed === "string" ? sp.feed : undefined);
  const base = `/actors/${encodeURIComponent(id)}`;

  // Сначала журнал действий: нет записи о просмотре — нет данных.
  try {
    await audit(session.user, "actor.view", id, range, { strict: true });
  } catch (err) {
    return (
      <>
        <PageHeader title={<span className="font-mono">{id}</span>} />
        <Panel label="Журнал действий недоступен" meta="console_audit">
          <p className="flex items-center gap-2 text-sm"><Led color="var(--status-err)" />{err instanceof Error ? err.message : "запись о просмотре не выполнена"}</p>
          <p className="mt-2 text-sm text-muted-foreground">Паспорт показывается только с записью о просмотре в журнале. Проверьте ClickHouse и повторите.</p>
        </Panel>
      </>
    );
  }

  const pr = await safeQuery(() => Promise.all([getPerson(id), personAliases(id)]));
  if (!pr.ok) {
    return (
      <>
        <PageHeader title={<span className="font-mono">{id}</span>} />
        <StorageUnavailable reason={pr.error} />
      </>
    );
  }
  const [person, aliases] = pr.data;
  if (!person) notFound();
  const [rr, tr] = await Promise.all([
    safeQuery(() => actorReport(person, aliases, range, TIMELINE_LIMIT)),
    safeQuery(() => actorTrace(aliases, range)),
  ]);
  if (rr.ok && tr.ok) attachIncidents(tr.data.sessions, rr.data.incidents, tr.data.gapMs);
  const isAdmin = session.role === "admin";

  const aliasesBlock = (
    <AliasesFold
      aliases={aliases}
      ambiguous={rr.ok ? rr.data.ambiguous : []}
      range={range}
      isAdmin={isAdmin}
      personId={person.person_id}
    />
  );

  return (
    <>
      <PageHeader
        back={{ href: "/actors", label: "Субъекты" }}
        title={<>{person.display || person.person_id} <span className="font-mono text-muted-foreground">{person.person_id}</span></>}
        subtitle={[person.kind === "service" ? "служебная учётка" : "человек", person.team && `отдел ${person.team}`, person.note].filter(Boolean).join(" · ")}
        actions={
          <div className="flex flex-wrap items-center gap-2">
            <ActorRangeLinks current={range} base={base} />
            <DownloadButton href={`/api/v1/actors/${encodeURIComponent(id)}/report?range=${range}`} filename={`actor-${id}.md`}>Markdown</DownloadButton>
          </div>
        }
      />

      {!rr.ok ? (
        <>
          <StorageUnavailable reason={rr.error} />
          {aliasesBlock}
        </>
      ) : (
        <ReportBody r={rr.data} range={range} trace={tr.ok ? tr.data : null} traceError={tr.ok ? null : tr.error} feed={feed} base={base} aliasesBlock={aliasesBlock} />
      )}
    </>
  );
}

/** Сворачиваемый блок второго плана: заголовок как у панели, содержимое по клику. */
function Fold({ title, meta, open, children, id }: { title: string; meta?: React.ReactNode; open?: boolean; children: React.ReactNode; id?: string }) {
  return (
    <details className="win group/fold" open={open} id={id}>
      <summary className="flex min-h-10 cursor-pointer list-none flex-wrap items-center gap-x-3 gap-y-1 rounded-[11px] px-4 py-2 hover:bg-[var(--surface-elevated)]/60">
        <ChevronRight className="size-3.5 shrink-0 text-muted-foreground transition-transform group-open/fold:rotate-90" strokeWidth={1.5} aria-hidden />
        <h2 className="text-[13px] font-semibold">{title}</h2>
        {meta && <span className="ml-auto min-w-0 truncate text-[12px] text-[var(--text-tertiary)]">{meta}</span>}
      </summary>
      <div className="border-t border-border p-4">{children}</div>
    </details>
  );
}

function AliasesFold({ aliases, ambiguous, range, isAdmin, personId }: { aliases: Alias[]; ambiguous: string[]; range: string; isAdmin: boolean; personId: string }) {
  const held = aliases.filter(isHeld).length;
  const amb = aliases.filter((a) => ambiguous.includes(aliasKey(a))).length;
  const meta = [amb ? `неоднозначных ${fmtNum(amb)}` : "", held ? `на удержании ${fmtNum(held)}` : "", "интервалы действия в UTC"].filter(Boolean).join(" · ");
  return (
    <Fold title={`Алиасы · ${fmtNum(aliases.length)}`} meta={meta} open={aliases.length === 0 || amb > 0 || held > 0}>
      {aliases.length === 0 ? <Empty>Алиасов нет — паспорт пуст. Добавьте их через identities.yml, событие identity.alias или форму ниже.</Empty> : (
        <div className="overflow-x-auto">
          <Table>
            <TableHeader>
              <TableRow className="border-border/60">
                <TableHead className="c-label">Вид</TableHead>
                <TableHead className="c-label">Значение</TableHead>
                <TableHead className="c-label">Действует с</TableHead>
                <TableHead className="c-label">По</TableHead>
                <TableHead className="c-label">Источник</TableHead>
                <TableHead className="c-label text-right">Уверенность</TableHead>
                <TableHead className="c-label">Журнал</TableHead>
                {isAdmin && <TableHead className="c-label" />}
              </TableRow>
            </TableHeader>
            <TableBody>
              {aliases.map((a) => {
                const isAmb = ambiguous.includes(aliasKey(a));
                const isH = isHeld(a);
                const policy = holdPolicy(a);
                return (
                  <TableRow key={`${a.kind}|${a.value}|${a.valid_from}`} className={isH ? "border-border/40 text-muted-foreground" : "border-border/40"}>
                    <TableCell className="text-xs">{ALIAS_KIND_LABELS[a.kind]}</TableCell>
                    <TableCell className="font-mono text-xs">
                      <span className="flex items-center gap-2">
                        <Copyable value={a.value} label="Алиас" />
                        {isAmb && <Badge variant="destructive" title="В этом периоде алиас действует и у другой персоны">неоднозначно</Badge>}
                        {isH && <Badge variant="outline" className="text-[var(--status-warn)]" title={`Удержан политикой идентичности${policy ? `: ${policy}` : ""} — события не сшиваются, пока администратор не подтвердит`}>на удержании</Badge>}
                      </span>
                    </TableCell>
                    <TableCell className="font-mono text-xs whitespace-nowrap">{formatTs(a.valid_from)}</TableCell>
                    <TableCell className="font-mono text-xs whitespace-nowrap">{a.valid_to ? formatTs(a.valid_to) : <span className="font-sans text-[var(--status-ok)]">действует</span>}</TableCell>
                    <TableCell className="font-mono text-xs">
                      {a.source}
                      {isH && policy ? <span className="text-[var(--status-warn)]"> · политика {policy}</span> : a.note ? <span className="text-muted-foreground"> · {a.note}</span> : null}
                    </TableCell>
                    <TableCell className="text-right font-mono text-xs">{a.confidence.toFixed(2)}</TableCell>
                    <TableCell className="text-xs"><Link href={aliasEventsHref(a, range as ActorRange)} className="text-[var(--ring)] hover:underline">события</Link></TableCell>
                    {isAdmin && (
                      <TableCell className="text-right">
                        <span className="flex items-center justify-end gap-1">
                          {isH && <ConfirmAliasButton personId={personId} kind={a.kind} value={a.value} policy={policy} />}
                          {a.valid_to === null && <CloseAliasButton personId={personId} kind={a.kind} value={a.value} />}
                        </span>
                      </TableCell>
                    )}
                  </TableRow>
                );
              })}
            </TableBody>
          </Table>
        </div>
      )}
      {isAdmin && (
        <div className="mt-4 border-t border-border pt-4">
          <div className="c-label mb-2">Добавить алиас</div>
          <BindAliasForm persons={[]} personId={personId} />
        </div>
      )}
    </Fold>
  );
}

function ReportBody({ r, range, trace, traceError, feed, base, aliasesBlock }: { r: ActorReport; range: string; trace: ActorTrace | null; traceError: string | null; feed: FeedFilter; base: string; aliasesBlock: React.ReactNode }) {
  // «Сейчас» — момент сборки отчёта: чистый рендер, и время ленты сходится с окном.
  const now = tsMs(r.generated_at) ?? 0;
  const primary = primaryAlias(r.aliases);
  const feedItems = trace ? buildFeed(trace, { incidents: r.incidents, owner: ownerScope(r.aliases), primary: primary ?? undefined }) : [];
  const feedHref = (f: FeedFilter) => `${base}?range=${range}${f === "all" ? "" : `&feed=${f}`}#activity`;
  const failedRows = feedItems.filter((i) => i.fails > 0).length;
  const fails = feedItems.reduce((n, i) => n + i.fails, 0);
  const lastAct = feedItems.find((i) => i.kind !== "incident");
  const lastTs = lastAct?.at ?? r.sources.reduce<number | null>((m, s) => { const t = tsMs(s.last_ts); return t !== null && (m === null || t > m) ? t : m; }, null);
  const lastFrom = lastAct?.from?.replace(/^(после входа )?с /, "");
  const nodesN = r.summary.nodes.length;
  const ipsN = r.summary.src_ips.length;
  return (
    <>
      {r.missing.length > 0 && (
        <Alert>
          <AlertTitle>Часть данных временно недоступна</AlertTitle>
          <AlertDescription>Не удалось загрузить: {r.missing.join(", ")}. Остальные разделы показаны.</AlertDescription>
        </Alert>
      )}
      <div className="grid grid-cols-2 gap-4 lg:grid-cols-4">
        {trace ? (
          <StatTile
            label="Отказы"
            value={fmtNum(fails)}
            tone={fails > 0 ? "err" : undefined}
            sub={fails > 0 ? `${plural(fails, "отклонённое событие", "отклонённых события", "отклонённых событий")} в ${fmtNum(failedRows)} ${plural(failedRows, "действии", "действиях", "действиях")}` : "отклонённых действий нет"}
            href={fails > 0 ? feedHref("flagged") : undefined}
            hint="Действия с отказами — отмеченные строки ленты"
          />
        ) : (
          // Сеансы не построились — отказы неизвестны, а не «нет»: ноль здесь был бы ложью.
          <StatTile label="Отказы" value="—" sub="неизвестно: сеансы не загрузились" hint="Отказы считаются по сеансам; см. «События списком» ниже" />
        )}
        <StatTile
          label="Инциденты"
          value={fmtNum(r.summary.incidents)}
          tone={r.summary.incidents > 0 ? "warn" : undefined}
          sub={r.summary.incidents > 0 ? "с участием субъекта" : `за ${RANGES[r.range.key].label}`}
          href={r.summary.incidents > 0 ? "#incidents" : undefined}
        />
        <StatTile label="Узлы · адреса" value={`${fmtNum(nodesN)} · ${fmtNum(ipsN)}`} sub="где действовал · откуда заходил" />
        <StatTile
          label="Последняя активность"
          value={lastTs === null ? "—" : formatTs(lastTs, "short")}
          size="sm"
          sub={lastFrom ? <>с <span className="font-mono">{lastFrom}</span></> : lastTs === null ? "в периоде нет событий" : "адрес неизвестен"}
          hint={lastTs === null ? undefined : formatTs(lastTs)}
        />
      </div>

      {trace && <ActorFeed items={feedItems} filter={feed} now={now} hrefFor={feedHref} />}

      {trace ? <ActorTraceView trace={trace} aliases={r.aliases} /> : (
        <Panel label="Сеансы" meta="недоступны">
          <p className="text-sm text-muted-foreground">Не удалось построить сеансы: {traceError ?? "ошибка хранилища"}. Ниже — события по разделам.</p>
        </Panel>
      )}

      {r.incidents.length > 0 && (
        <Panel id="incidents" label={`Инциденты · ${fmtNum(r.incidents.length)}`} meta="где субъект указан участником на момент начала" bodyClassName="p-0">
          <ul className="divide-y divide-border/70">
            {r.incidents.map((i) => (
              <li key={i.id}>
                <Link href={`/incidents/${i.id}`} className="flex flex-wrap items-center gap-x-3 gap-y-1 px-4 py-2.5 text-sm hover:bg-[var(--surface-elevated)]" title={`Правило ${i.rule_id}`}>
                  <LevelBadge level={i.level} />
                  {isIncidentStatus(i.status) ? <StatusBadge status={i.status} /> : <span className="text-xs">{i.status}</span>}
                  <span className="min-w-0 flex-1 truncate">{i.rule_title || i.rule_id}</span>
                  <span className="font-mono text-xs text-muted-foreground">{i.id}</span>
                  <span className="text-xs tabular-nums text-muted-foreground">{formatTs(i.created_at, "datetime")}</span>
                </Link>
              </li>
            ))}
          </ul>
        </Panel>
      )}

      <Fold title="Охват и источники" meta={`${fmtNum(r.summary.events)} событий за ${RANGES[r.range.key].label} · ${formatTs(r.range.from, "datetime")} – ${formatTs(r.range.to, "datetime")} UTC`}>
        <div className="grid gap-6 lg:grid-cols-[minmax(0,3fr)_minmax(0,2fr)]">
          <div className="min-w-0 overflow-x-auto">
            {r.sources.length === 0 ? <Empty>В периоде нет событий по алиасам.</Empty> : (
              <Table>
                <TableHeader>
                  <TableRow className="border-border/60">
                    <TableHead className="c-label">Источник</TableHead>
                    <TableHead className="c-label text-right">Событий</TableHead>
                    <TableHead className="c-label">Первое</TableHead>
                    <TableHead className="c-label">Последнее</TableHead>
                  </TableRow>
                </TableHeader>
                <TableBody>
                  {r.sources.map((s) => (
                    <TableRow key={s.source} className="border-border/40">
                      <TableCell className="font-mono text-xs">{s.source}</TableCell>
                      <TableCell className="text-right font-mono text-xs tabular-nums">{fmtNum(s.count)}</TableCell>
                      <TableCell className="font-mono text-xs whitespace-nowrap">{formatTs(s.first_ts, "short")}</TableCell>
                      <TableCell className="font-mono text-xs whitespace-nowrap">{formatTs(s.last_ts, "short")}</TableCell>
                    </TableRow>
                  ))}
                </TableBody>
              </Table>
            )}
          </div>
          <dl className="grid content-start grid-cols-[auto_1fr] gap-x-6 gap-y-2 text-[13px]">
            <dt className="text-[var(--text-tertiary)]">Узлы</dt>
            <dd className="flex flex-wrap gap-x-3 gap-y-1 font-mono text-xs">{nodesN ? r.summary.nodes.map((n) => <span key={n.node}><Copyable value={n.node} href={searchHref.node(n.node)} label="Узел" /> <span className="text-muted-foreground">{fmtNum(n.count)}</span></span>) : "—"}</dd>
            <dt className="text-[var(--text-tertiary)]">Адреса</dt>
            <dd className="flex flex-wrap gap-x-3 gap-y-1 font-mono text-xs">{ipsN ? r.summary.src_ips.map((n) => <span key={n.src_ip}><Copyable value={n.src_ip} href={searchHref.eventSrc(n.src_ip)} label="IP" /> <span className="text-muted-foreground">{fmtNum(n.count)}</span></span>) : "—"}</dd>
            <dt className="text-[var(--text-tertiary)]">По классам</dt>
            <dd className="font-mono text-xs">{Object.keys(r.summary.by_source_class).length ? Object.entries(r.summary.by_source_class).map(([c, n]) => `${c} ${fmtNum(n)}`).join(" · ") : "—"}</dd>
          </dl>
        </div>
      </Fold>

      {aliasesBlock}

      <Fold title="События списком" meta="по разделам и последние события" open={!trace}>
        <div className="space-y-6">
          {SECTIONS.filter((s): s is Exclude<Section, "other"> => s !== "other").map((s) => (
            <SectionPanel key={s} section={s} items={r.sections[s]} limit={r.limit} />
          ))}
          <Panel
            label={`Последние события · ${fmtNum(r.timeline.length)}${r.timeline.length >= r.limit ? ` из не больше ${fmtNum(r.limit)}` : ""}`}
            headingLevel={3}
            meta={primary ? <Link href={aliasEventsHref(primary, range as ActorRange)} className="text-[var(--ring)] hover:underline">открыть в журнале по {primary.value}</Link> : undefined}
            bodyClassName="p-0"
          >
            {r.timeline.length === 0 ? <Empty className="p-4">Событий нет.</Empty> : <EventTable items={r.timeline} />}
          </Panel>
        </div>
      </Fold>

      <Fold title="Ограничения данных" meta="чего паспорт не знает">
        <ul className="list-disc space-y-1 pl-5 text-sm text-muted-foreground">
          <li>Сеанс — активность с паузами не длиннее 30 мин, а не вход и выход: выхода источники почти не пишут. Сеть показана топом адресов назначения. События, для которых источник не передал адрес, привязываются ко входу на тот же узел в этом сеансе — это вывод, а не факт из журнала.</li>
          <li>Содержимого данных внутри приложений: паспорт строится по журналу событий, а не по данным систем.</li>
          <li>Событий вне интервалов действия алиасов: до «действует с» и после «по» они субъекту не приписываются.</li>
          <li>Источников, не подключённых к ARGUS, и событий старше срока хранения.</li>
          <li>Разделы «Входы» … «Изменения» берут последние {fmtNum(r.limit)} событий каждого раздела за период, на странице — первые {fmtNum(SECTION_SHOWN)}; полностью — в экспорте Markdown и в API. Охват — по всем событиям.</li>
          {r.ambiguous.length > 0 && <li>Алиасы с пометкой «неоднозначно» делятся с другой персоной — их события могут быть не этого субъекта.</li>}
          {r.aliases.some(isHeld) && <li>Алиасы «на удержании» (нарушение политики идентичности) в сшивку не входят: их события в паспорте не учтены, пока администратор не подтвердит алиас.</li>}
        </ul>
      </Fold>
    </>
  );
}

/** 1 событие, 2 события, 5 событий. */
function plural(n: number, one: string, few: string, many: string): string {
  const m10 = n % 10, m100 = n % 100;
  return m10 === 1 && m100 !== 11 ? one : m10 >= 2 && m10 <= 4 && (m100 < 12 || m100 > 14) ? few : many;
}

/** Строк раздела на странице; выборка — до limit (экспорт и API отдают её целиком). */
const SECTION_SHOWN = 50;

function SectionPanel({ section, items, limit }: { section: Exclude<Section, "other">; items: LogItem[]; limit: number }) {
  const meta: Record<Exclude<Section, "other">, string> = {
    login: "auth.* · login · logon · sshd",
    host: "priv.* · sudo · su · session.*",
    network: "netflow · ngfw · net.*",
    app: "app.* · authorize · oauth",
    change: "identity.* · create · update · delete · change · modify — успешные",
  };
  const fail = items.filter((e) => /fail|deny|denied|error/i.test(e.outcome)).length;
  return (
    <Panel headingLevel={3} label={`${SECTION_LABELS[section]} · ${fmtNum(items.length)}`} meta={`${meta[section]}${fail ? ` · отказов ${fmtNum(fail)}` : ""} · выборка до ${fmtNum(limit)}`} bodyClassName="p-0">
      {items.length === 0 ? <Empty className="p-4">Нет событий этого раздела в периоде.</Empty> : (
        <>
          <EventTable items={items.slice(0, SECTION_SHOWN)} />
          {items.length > SECTION_SHOWN && (
            <p className="border-t border-border/60 px-4 py-2 text-xs text-muted-foreground">
              Показаны последние {fmtNum(SECTION_SHOWN)} из {fmtNum(items.length)}{items.length >= limit ? ` (выборка ограничена ${fmtNum(limit)})` : ""} — полностью в экспорте Markdown и API.
            </p>
          )}
        </>
      )}
    </Panel>
  );
}

function EventTable({ items }: { items: LogItem[] }) {
  return (
    <div className="overflow-x-auto">
      <Table>
        <TableHeader>
          <TableRow className="border-border/60">
            <TableHead className="c-label">Время (UTC)</TableHead>
            <TableHead className="c-label">Источник</TableHead>
            <TableHead className="c-label">Действие</TableHead>
            <TableHead className="c-label">Исход</TableHead>
            <TableHead className="c-label">Субъект</TableHead>
            <TableHead className="c-label">Узел</TableHead>
            <TableHead className="c-label">Адрес</TableHead>
            <TableHead className="c-label">Объект</TableHead>
          </TableRow>
        </TableHeader>
        <TableBody>
          {items.map((e, i) => (
            <TableRow key={`${e.ts}|${i}`} className="border-border/40 align-top">
              <TableCell className="font-mono text-xs whitespace-nowrap">{formatTs(e.ts)}</TableCell>
              <TableCell className="font-mono text-xs">{e.source}</TableCell>
              <TableCell className="font-mono text-xs">{e.action}</TableCell>
              <TableCell className="font-mono text-xs">{/fail|deny|denied|error/i.test(e.outcome) ? <span className="text-[var(--status-err)]">{e.outcome}</span> : e.outcome || "—"}</TableCell>
              <TableCell className="font-mono text-xs">{e.actor_name || "—"}</TableCell>
              <TableCell className="font-mono text-xs">{e.node ? <Copyable value={e.node} href={searchHref.node(e.node)} label="Узел" /> : "—"}</TableCell>
              <TableCell className="font-mono text-xs">{e.src_ip ? <Copyable value={e.src_ip} href={searchHref.eventSrc(e.src_ip)} label="IP" /> : "—"}</TableCell>
              <TableCell className="max-w-md truncate text-xs" title={e.object}>{e.object || "—"}</TableCell>
            </TableRow>
          ))}
        </TableBody>
      </Table>
    </div>
  );
}
