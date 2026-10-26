import type { Metadata } from "next";
import Link from "next/link";
import { notFound } from "next/navigation";
import { ArrowLeft } from "lucide-react";
import { Copyable } from "@/components/console/copyable";
import { DownloadButton } from "@/components/console/download-button";
import { ActorRangeLinks, ALIAS_KIND_LABELS, BindAliasForm, CloseAliasButton, ConfirmAliasButton } from "@/components/console/actor-forms";
import { LevelBadge, StatusBadge } from "@/components/console/incident-badges";
import { Empty, Led, PageHeader, Panel, StatTile } from "@/components/console/panel";
import { StorageUnavailable } from "@/components/console/storage-error";
import { Alert, AlertDescription, AlertTitle } from "@/components/ui/alert";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from "@/components/ui/table";
import { safeQuery } from "@/lib/clickhouse";
import { audit } from "@/lib/argus-queries";
import { actorReport, getPerson, personAliases } from "@/lib/actors";
import { aliasEventsHref, aliasKey, holdPolicy, isHeld, parseActorRange, PERSON_ID_RE, primaryAlias, SECTION_LABELS, SECTIONS, type ActorReport, type Section } from "@/lib/shared/actors";
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
  const rr = await safeQuery(() => actorReport(person, aliases, range, TIMELINE_LIMIT));
  const isAdmin = session.role === "admin";

  return (
    <>
      <PageHeader
        title={<>{person.display || person.person_id} <span className="font-mono text-muted-foreground">{person.person_id}</span></>}
        subtitle={[person.kind === "service" ? "служебная учётка" : "человек", person.team && `команда ${person.team}`, person.note].filter(Boolean).join(" · ")}
      >
        <div className="flex flex-wrap items-center gap-2">
          <ActorRangeLinks current={range} base={base} />
          <DownloadButton href={`/api/v1/actors/${encodeURIComponent(id)}/report?range=${range}`} filename={`actor-${id}.md`}>Markdown</DownloadButton>
          <Button asChild variant="ghost" size="sm"><Link href="/actors"><ArrowLeft strokeWidth={1.5} />К списку</Link></Button>
        </div>
      </PageHeader>

      <Panel label="Алиасы" meta={`${fmtNum(aliases.length)}${aliases.some(isHeld) ? ` · на удержании ${fmtNum(aliases.filter(isHeld).length)}` : ""} · интервалы действия в UTC`}>
        {aliases.length === 0 ? <Empty>Алиасов нет — паспорт пуст. Добавьте их через identities.yml, событие identity.alias или форму ниже.</Empty> : (
          <div className="c-well overflow-x-auto p-2">
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
                  const amb = rr.ok && rr.data.ambiguous.includes(aliasKey(a));
                  const held = isHeld(a);
                  const policy = holdPolicy(a);
                  return (
                    <TableRow key={`${a.kind}|${a.value}|${a.valid_from}`} className={held ? "border-border/40 text-muted-foreground" : "border-border/40"}>
                      <TableCell className="text-xs">{ALIAS_KIND_LABELS[a.kind]}</TableCell>
                      <TableCell className="font-mono text-xs">
                        <span className="flex items-center gap-2">
                          <Copyable value={a.value} label="Алиас" />
                          {amb && <Badge variant="destructive" title="В этом периоде алиас действует и у другой персоны">неоднозначно</Badge>}
                          {held && <Badge variant="outline" className="text-[var(--status-warn)]" title={`Удержан политикой идентичности${policy ? `: ${policy}` : ""} — события не сшиваются, пока администратор не подтвердит`}>на удержании</Badge>}
                        </span>
                      </TableCell>
                      <TableCell className="font-mono text-xs whitespace-nowrap">{formatTs(a.valid_from)}</TableCell>
                      <TableCell className="font-mono text-xs whitespace-nowrap">{a.valid_to ? formatTs(a.valid_to) : <span className="text-[var(--status-ok)]">действует</span>}</TableCell>
                      <TableCell className="font-mono text-xs">
                        {a.source}
                        {held && policy ? <span className="text-[var(--status-warn)]"> · политика {policy}</span> : a.note ? <span className="text-muted-foreground"> · {a.note}</span> : null}
                      </TableCell>
                      <TableCell className="text-right font-mono text-xs">{a.confidence.toFixed(2)}</TableCell>
                      <TableCell className="text-xs"><Link href={aliasEventsHref(a, range)} className="text-[var(--ring)] hover:underline">события</Link></TableCell>
                      {isAdmin && (
                        <TableCell className="text-right">
                          <span className="flex items-center justify-end gap-1">
                            {held && <ConfirmAliasButton personId={person.person_id} kind={a.kind} value={a.value} policy={policy} />}
                            {a.valid_to === null && <CloseAliasButton personId={person.person_id} kind={a.kind} value={a.value} />}
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
            <BindAliasForm persons={[]} personId={person.person_id} />
          </div>
        )}
      </Panel>

      {!rr.ok ? <StorageUnavailable reason={rr.error} /> : <ReportBody r={rr.data} range={range} />}
    </>
  );
}

function ReportBody({ r, range }: { r: ActorReport; range: string }) {
  const primary = primaryAlias(r.aliases);
  return (
    <>
      {r.missing.length > 0 && (
        <Alert>
          <AlertTitle>Часть данных временно недоступна</AlertTitle>
          <AlertDescription>Не удалось загрузить: {r.missing.join(", ")}. Остальные разделы показаны.</AlertDescription>
        </Alert>
      )}
      <div className="grid grid-cols-2 gap-6 md:grid-cols-4">
        <StatTile label={`Событий за ${RANGES[r.range.key].label}`} value={fmtNum(r.summary.events)} />
        <StatTile label="Узлов" value={fmtNum(r.summary.nodes.length)} />
        <StatTile label="Адресов" value={fmtNum(r.summary.src_ips.length)} />
        <StatTile label="Инцидентов" value={fmtNum(r.summary.incidents)} led={r.summary.incidents > 0 ? "var(--status-warn)" : "var(--status-ok)"} />
      </div>

      <Panel label="Сводка" meta={`${formatTs(r.range.from)} → ${formatTs(r.range.to)}`}>
        <dl className="grid grid-cols-[auto_1fr] gap-x-6 gap-y-1.5 text-[13px]">
          <dt className="text-[var(--text-tertiary)]">по классам</dt>
          <dd className="font-mono text-xs">{Object.keys(r.summary.by_source_class).length ? Object.entries(r.summary.by_source_class).map(([c, n]) => `${c} ${fmtNum(n)}`).join(" · ") : "—"}</dd>
          <dt className="text-[var(--text-tertiary)]">узлы</dt>
          <dd className="flex flex-wrap gap-x-3 gap-y-1 font-mono text-xs">{r.summary.nodes.length ? r.summary.nodes.map((n) => <span key={n.node}><Copyable value={n.node} href={searchHref.node(n.node)} label="Узел" /> <span className="text-muted-foreground">{fmtNum(n.count)}</span></span>) : "—"}</dd>
          <dt className="text-[var(--text-tertiary)]">адреса</dt>
          <dd className="flex flex-wrap gap-x-3 gap-y-1 font-mono text-xs">{r.summary.src_ips.length ? r.summary.src_ips.map((n) => <span key={n.src_ip}><Copyable value={n.src_ip} href={searchHref.eventSrc(n.src_ip)} label="IP" /> <span className="text-muted-foreground">{fmtNum(n.count)}</span></span>) : "—"}</dd>
          <dt className="text-[var(--text-tertiary)]">источники</dt>
          <dd className="font-mono text-xs">{r.sources.length ? r.sources.map((s) => `${s.source} (${fmtNum(s.count)}, ${formatTs(s.first_ts, "short")} → ${formatTs(s.last_ts, "short")})`).join(" · ") : "в окне нет событий по алиасам"}</dd>
        </dl>
      </Panel>

      {SECTIONS.filter((s): s is Exclude<Section, "other"> => s !== "other").map((s) => (
        <SectionPanel key={s} section={s} items={r.sections[s]} limit={r.limit} />
      ))}

      <Panel label="Инциденты" meta="actor_name инцидента ∈ алиасов, действовавших на его начало">
        {r.incidents.length === 0 ? <Empty>Инцидентов с субъектом в периоде нет.</Empty> : (
          <ul className="space-y-1 font-mono text-xs">
            {r.incidents.map((i) => (
              <li key={i.id} className="flex flex-wrap items-center gap-2 border-l border-border pl-3">
                <Link href={`/incidents/${i.id}`} className="text-[var(--ring)] hover:underline">{i.id}</Link>
                <LevelBadge level={i.level} />
                {isIncidentStatus(i.status) ? <StatusBadge status={i.status} /> : <span>{i.status}</span>}
                <span>{i.rule_title}</span>
                <span className="text-muted-foreground">· {formatTs(i.created_at)}</span>
              </li>
            ))}
          </ul>
        )}
      </Panel>

      <Panel
        label={`Таймлайн · последние ${fmtNum(r.timeline.length)}${r.timeline.length >= r.limit ? ` из не больше ${fmtNum(r.limit)}` : ""}`}
        meta={primary ? <Link href={aliasEventsHref(primary, range as "24h" | "7d" | "30d")} className="text-[var(--ring)] hover:underline">открыть в журнале по {primary.value}</Link> : undefined}
        bodyClassName="p-0"
      >
        {r.timeline.length === 0 ? <Empty className="p-4">Событий нет.</Empty> : <EventTable items={r.timeline} />}
      </Panel>

      <Panel label="Чего нет в данных">
        <ul className="list-disc space-y-1 pl-5 text-sm text-muted-foreground">
          <li>Содержимого данных внутри приложений: паспорт строится по журналу событий, а не по данным систем.</li>
          <li>Событий вне интервалов действия алиасов: до «действует с» и после «по» они субъекту не приписываются.</li>
          <li>Источников, не подключённых к ARGUS, и событий старше срока хранения.</li>
          <li>Разделы «Входы» … «Изменения» построены по последним {fmtNum(r.limit)} событиям периода, сводка — по всем.</li>
          {r.ambiguous.length > 0 && <li>Алиасы с пометкой «неоднозначно» делятся с другой персоной — их события могут быть не этого субъекта.</li>}
          {r.aliases.some(isHeld) && <li>Алиасы «на удержании» (нарушение политики идентичности) в сшивку не входят: их события в паспорте не учтены, пока администратор не подтвердит алиас.</li>}
        </ul>
      </Panel>
    </>
  );
}

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
    <Panel label={`${SECTION_LABELS[section]} · ${fmtNum(items.length)}`} meta={`${meta[section]}${fail ? ` · отказов ${fmtNum(fail)}` : ""} · по последним ${fmtNum(limit)}`} bodyClassName="p-0">
      {items.length === 0 ? <Empty className="p-4">Нет событий этого раздела среди последних в периоде.</Empty> : <EventTable items={items.slice(0, 50)} />}
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
