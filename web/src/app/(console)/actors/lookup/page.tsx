import type { Metadata } from "next";
import Link from "next/link";
import { ArrowRight, ChevronRight, RotateCw, SearchX } from "lucide-react";
import { Ago } from "@/components/console/ago";
import { Copyable } from "@/components/console/copyable";
import { BindAliasForm, CloseAliasButton } from "@/components/console/actor-forms";
import { ActorLookupForm } from "@/components/console/actor-lookup-form";
import { ActorPeriodTabs, DataWell, lookupHref, passportHref, PersonCell } from "@/components/console/actors-section";
import { Empty, PageHeader, Panel } from "@/components/console/panel";
import { StorageUnavailable } from "@/components/console/storage-error";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { TableBody, TableCell, TableHead, TableHeader, TableRow } from "@/components/ui/table";
import { safeQuery } from "@/lib/clickhouse";
import { audit } from "@/lib/argus-queries";
import { aliasHistory, aliasSightings, getPerson, listPersonOptions, recentLookups, resolveAlias } from "@/lib/actors";
import { ALIAS_KIND_LABELS, ALIAS_VALUE_MAX, isIp, parseActorRange, PERSON_ID_RE, type ActorRange } from "@/lib/shared/actors";
import { aliasNoteLabel, aliasSourceLabel, guessAliasKind, LOOKUP_EXAMPLES, sightingTitle } from "@/lib/shared/actors-ui";
import { RANGES } from "@/lib/shared/ranges";
import { searchHref } from "@/lib/shared/search-href";
import { fmtNum, formatTs } from "@/lib/shared/time";
import { requireActorAccess } from "@/lib/actors-access";

export const dynamic = "force-dynamic";
export const metadata: Metadata = { title: "Кому принадлежит · Субъекты" };

/** Сколько строк «где встречалось» видно сразу. */
const SIGHT_SHOWN = 10;
const FAIL_ROW = "bg-[color-mix(in_oklab,var(--status-err)_8%,transparent)]";
const LINK = "text-[var(--ring)] hover:underline";
const day = (v: string | null) => formatTs(v, "date");

/**
 * /actors/lookup?v=<значение>&range=: кому принадлежит идентификатор сейчас
 * (вывод наверху; для «ничьё» — форма привязки у admin, для «неоднозначно» —
 * кандидаты с закрытием алиаса), кому принадлежал раньше (все интервалы,
 * включая закрытые и удержанные) и где значение встречалось за период.
 * Каждый поиск — в журнале действий (actor.lookup, strict): нет журнала — нет ответа.
 */
export default async function LookupPage({ searchParams }: PageProps<"/actors/lookup">) {
  const session = await requireActorAccess();
  const sp = await searchParams;
  const raw = typeof sp.v === "string" ? sp.v.trim().slice(0, ALIAS_VALUE_MAX) : "";
  const range = parseActorRange(typeof sp.range === "string" ? sp.range : undefined);
  const isAdmin = session.role === "admin";
  // Один снимок «сейчас» на страницу: относительное время у всех строк от него.
  const now = new Date();
  const periodHref = (r: ActorRange) => (raw ? lookupHref(raw, r) : `/actors/lookup?range=${r}`);
  const header = (
    <PageHeader
      title="Кому принадлежит"
      back={{ href: `/actors?range=${range}`, label: "К списку" }}
      subtitle="Почта, логин, телефон, IP, хост или id персоны: чей он сейчас, чьим был раньше и где встречался в журнале. Каждый поиск записывается в журнал действий."
      actions={<ActorPeriodTabs current={range} href={periodHref} />}
    />
  );
  if (!raw) {
    const recent = await safeQuery(() => recentLookups(session.user));
    const chip = (v: string, label: React.ReactNode, key: string) => (
      <Link key={key} href={lookupHref(v, range)} className="inline-flex min-h-8 items-center gap-1.5 rounded-md border border-border bg-[var(--surface-deep)] px-2.5 text-[13px] text-muted-foreground transition-colors hover:border-[var(--border-strong)] hover:text-foreground">
        {label}
      </Link>
    );
    return (
      <>
        {header}
        <Panel label="Поиск">
          <div className="space-y-5">
            <ActorLookupForm range={range} autoFocus />
            {recent.ok && recent.data.length > 0 && (
              <div className="space-y-2">
                <p className="c-label">Вы недавно искали</p>
                <div className="flex flex-wrap gap-2">
                  {recent.data.map((r) => chip(r.value, <><span className="font-mono text-foreground">{r.value}</span><Ago ts={r.last_ts} now={now} className="text-xs text-[var(--text-tertiary)]" /></>, r.value))}
                </div>
              </div>
            )}
            <div className="space-y-2">
              <p className="c-label">Например</p>
              <div className="flex flex-wrap gap-2">
                {LOOKUP_EXAMPLES.map((e) => chip(e.value, <>{e.label} <span className="font-mono text-foreground">{e.value}</span></>, e.value))}
              </div>
            </div>
          </div>
        </Panel>
      </>
    );
  }

  // Сначала журнал действий: нет записи о поиске — нет данных.
  try {
    await audit(session.user, "actor.lookup", raw, range, { strict: true });
  } catch (err) {
    return (
      <>
        {header}
        <Panel label="Журнал действий недоступен" tone="err">
          <p className="text-sm">Поиск не записан в журнал действий, поэтому результат не показан.</p>
          <div className="mt-3 flex flex-wrap items-center gap-4">
            <Button asChild variant="secondary" size="sm"><Link href={lookupHref(raw, range)}><RotateCw strokeWidth={1.5} />Повторить</Link></Button>
            <details className="text-xs text-muted-foreground">
              <summary className="cursor-pointer">Техническая причина</summary>
              <p className="mt-1 font-mono">{err instanceof Error ? err.message : "запись о поиске не выполнена"}</p>
            </details>
          </div>
        </Panel>
      </>
    );
  }
  const ip = isIp(raw);
  const [owner, hist, seen, person, options] = await Promise.all([
    safeQuery(() => resolveAlias(raw)),
    safeQuery(() => aliasHistory(raw)),
    safeQuery(() => aliasSightings(raw, range)),
    PERSON_ID_RE.test(raw.toLowerCase()) ? safeQuery(() => getPerson(raw.toLowerCase())) : Promise.resolve(null),
    isAdmin ? safeQuery(() => listPersonOptions()) : Promise.resolve(null),
  ]);
  const journal = ip ? searchHref.eventSrc(raw) : searchHref.actorEvents(raw);
  const asPerson = person?.ok ? person.data : null;
  const guess = guessAliasKind(raw);

  // Вывод: чьё значение сейчас. Персона с таким id — в том же блоке (если это
  // не та же персона, что владеет значением как алиасом).
  const sameOwner = owner.ok && owner.data.status === "resolved" && owner.data.matches[0].person_id === asPerson?.person_id;
  const personLine = asPerson && !sameOwner && (
    <p className="text-sm text-muted-foreground">
      <span className="font-mono">{asPerson.person_id}</span> — это id персоны{" "}
      <Link href={passportHref(asPerson.person_id, range)} className={LINK}>{asPerson.display || asPerson.person_id}</Link>.
    </p>
  );
  let verdict: React.ReactNode;
  if (!owner.ok) {
    verdict = <StorageUnavailable reason={owner.error} />;
  } else if (owner.data.status === "resolved") {
    const m = owner.data.matches[0];
    verdict = (
      <Panel label="Сейчас">
        <div className="flex flex-wrap items-center justify-between gap-4">
          <div className="min-w-0 space-y-1.5">
            <p className="text-lg leading-snug text-foreground">
              <span className="font-mono break-all">{raw}</span> сейчас принадлежит{" "}
              <Link href={passportHref(m.person_id, range)} className={`font-medium ${LINK}`}>{m.display || m.person_id}</Link>
              {m.display && <span className="font-mono text-sm text-[var(--text-tertiary)]"> ({m.person_id})</span>}
            </p>
            <p className="text-[13px] text-muted-foreground">{ALIAS_KIND_LABELS[m.alias_kind]} · с {day(m.valid_from)}{m.kind === "service" ? " · служебная учётка" : ""}</p>
            {personLine}
          </div>
          <Button asChild variant="secondary" className="min-h-10"><Link href={passportHref(m.person_id, range)}>Открыть паспорт<ArrowRight strokeWidth={1.5} /></Link></Button>
        </div>
      </Panel>
    );
  } else if (owner.data.status === "unbound" && asPerson) {
    // id персоны — не алиас: привязывать нечего, ответ — сама персона.
    verdict = (
      <Panel label="Сейчас">
        <div className="flex flex-wrap items-center justify-between gap-4">
          <p className="min-w-0 text-lg leading-snug text-foreground">
            <span className="font-mono break-all">{raw}</span> — это id персоны{" "}
            <Link href={passportHref(asPerson.person_id, range)} className={`font-medium ${LINK}`}>{asPerson.display || asPerson.person_id}</Link>
          </p>
          <Button asChild variant="secondary" className="min-h-10"><Link href={passportHref(asPerson.person_id, range)}>Открыть паспорт<ArrowRight strokeWidth={1.5} /></Link></Button>
        </div>
      </Panel>
    );
  } else if (owner.data.status === "unbound") {
    verdict = (
      <Panel label="Сейчас" tone="warn">
        <div className="space-y-1.5">
          <p className="text-lg leading-snug text-foreground"><span className="font-mono break-all">{raw}</span> сейчас ничьё</p>
          <p className="text-[13px] text-muted-foreground">
            Значение не связано ни с одной персоной. События по нему остаются <Link href={journal} className={LINK}>в журнале</Link>
            {hist.ok && hist.data.length > 0 ? "; прежние владельцы — в истории ниже." : "."}
            {!isAdmin && " Привязать его к персоне может администратор."}
          </p>
          {personLine}
        </div>
        {isAdmin && (
          <div className="mt-5 border-t border-border/60 pt-4">
            <h3 className="mb-3 text-[15px] text-foreground">Привязать к персоне</h3>
            {options && !options.ok ? <p className="text-sm text-muted-foreground">Список персон недоступен — попробуйте позже.</p> : (
              <BindAliasForm persons={(options?.ok ? options.data : []).map((p) => ({ person_id: p.person_id, display: p.display }))} value={raw} kind={guess} kindGuessed />
            )}
          </div>
        )}
      </Panel>
    );
  } else {
    verdict = (
      <Panel label="Сейчас" tone="err" meta={`${fmtNum(owner.data.matches.length)} владельца`}>
        <p className="text-lg leading-snug text-foreground"><span className="font-mono break-all">{raw}</span> сейчас принадлежит нескольким персонам</p>
        <p className="mt-1.5 text-[13px] text-muted-foreground">Кто из них настоящий владелец, автоматически не выбирается. {isAdmin ? "Закройте лишний алиас — события с этого момента перестанут относиться к той персоне." : "Закрыть лишний алиас может администратор."}</p>
        <ul className="mt-4 divide-y divide-border/50 border-y border-border/50">
          {owner.data.matches.map((m) => (
            <li key={`${m.person_id}|${m.alias_kind}|${m.valid_from}`} className="flex flex-wrap items-center justify-between gap-3 py-2.5">
              <PersonCell id={m.person_id} display={m.display} kind={m.kind} range={range} />
              <div className="flex items-center gap-3">
                <span className="text-[13px] text-muted-foreground">{ALIAS_KIND_LABELS[m.alias_kind]} · с {day(m.valid_from)}</span>
                {isAdmin && <CloseAliasButton personId={m.person_id} kind={m.alias_kind} value={raw} />}
              </div>
            </li>
          ))}
        </ul>
        {personLine && <div className="mt-3">{personLine}</div>}
      </Panel>
    );
  }

  // Сначала строки с отказами, затем свежие: подозрительное — наверху.
  const sightRows = seen.ok ? [...seen.data.rows].sort((a, b) => Number(b.fails > 0) - Number(a.fails > 0) || (a.last_ts < b.last_ts ? 1 : a.last_ts > b.last_ts ? -1 : 0)) : [];
  const seenKind = seen.ok ? seen.data.kind : "actor";
  const sightTable = (rows: typeof sightRows) => (
    <DataWell>
      <TableHeader><TableRow className="border-border/60">
        <TableHead className="c-label">Что происходило</TableHead>
        <TableHead className="c-label">{seenKind === "ip" ? "Кто" : "С адресов"}</TableHead>
        {seenKind === "ip" && <TableHead className="c-label">Куда</TableHead>}
        <TableHead className="c-label text-right">Событий</TableHead><TableHead className="c-label text-right">Отказов</TableHead>
        <TableHead className="c-label">Последнее</TableHead>
      </TableRow></TableHeader>
      <TableBody>
        {rows.map((r) => (
          <TableRow key={`${r.source}|${r.action}|${r.who}|${r.where}`} className={r.fails > 0 ? `border-border/40 ${FAIL_ROW}` : "border-border/40"}>
            <TableCell>
              <div className="text-[13px] text-foreground">{sightingTitle(r)}</div>
              <div className="font-mono text-xs text-[var(--text-tertiary)]">{r.source} · {r.action}</div>
            </TableCell>
            {seenKind === "ip" ? (
              <TableCell className="font-mono text-xs">{r.who ? <Link href={lookupHref(r.who, range)} className={LINK}>{r.who}</Link> : <span className="text-muted-foreground">—</span>}</TableCell>
            ) : (
              <TableCell className="font-mono text-xs"><IpList ips={r.ips} range={range} /></TableCell>
            )}
            {seenKind === "ip" && <TableCell className="font-mono text-xs"><IpList ips={r.ips} range={range} /></TableCell>}
            <TableCell className="text-right font-mono text-xs tabular-nums">{fmtNum(r.events)}</TableCell>
            <TableCell className="text-right font-mono text-xs tabular-nums">{r.fails > 0 ? <span className="text-[var(--status-err)]">{fmtNum(r.fails)}</span> : <span className="text-[var(--text-tertiary)]">0</span>}</TableCell>
            <TableCell className="font-mono text-xs" title={`первое ${formatTs(r.first_ts)}`}><Ago ts={r.last_ts} now={now} /></TableCell>
          </TableRow>
        ))}
      </TableBody>
    </DataWell>
  );

  const vpn = seen.ok && seen.data.kind === "ip" ? seen.data.vpn : [];
  const vpnTable = (
    <DataWell>
      <TableHeader><TableRow className="border-border/60">
        <TableHead className="c-label">Учётка</TableHead><TableHead className="c-label">Устройство</TableHead><TableHead className="c-label">Адрес в VPN</TableHead>
        <TableHead className="c-label text-right">Событий</TableHead><TableHead className="c-label">Последнее</TableHead>
      </TableRow></TableHeader>
      <TableBody>
        {vpn.map((c) => (
          <TableRow key={`${c.actor_name}|${c.peer_name}`} className="border-border/40">
            <TableCell className="font-mono text-xs">{c.actor_name ? <Link href={lookupHref(c.actor_name, range)} className={LINK}>{c.actor_name}</Link> : "—"}</TableCell>
            <TableCell className="font-mono text-xs">{c.peer_name || "—"}</TableCell>
            <TableCell className="font-mono text-xs">{c.peer_ip ? <Link href={lookupHref(c.peer_ip, range)} className={LINK}>{c.peer_ip}</Link> : "—"}</TableCell>
            <TableCell className="text-right font-mono text-xs tabular-nums">{fmtNum(c.events)}</TableCell>
            <TableCell className="font-mono text-xs" title={`первое ${formatTs(c.first_ts)}`}><Ago ts={c.last_ts} now={now} /></TableCell>
          </TableRow>
        ))}
      </TableBody>
    </DataWell>
  );

  return (
    <>
      {header}
      <Panel label="Поиск"><ActorLookupForm value={raw} range={range} /></Panel>

      {verdict}

      {!hist.ok ? <StorageUnavailable reason={hist.error} /> : (
        <Panel label="История владения" meta={`${fmtNum(hist.data.length)} ${hist.data.length === 1 ? "интервал" : "интервалов"} за всё время`}>
          {hist.data.length === 0 ? <Empty>Это значение ни разу не было связано с персоной.</Empty> : (
            <DataWell>
              <TableHeader><TableRow className="border-border/60">
                <TableHead className="c-label">Персона</TableHead><TableHead className="c-label">Вид</TableHead><TableHead className="c-label">С</TableHead>
                <TableHead className="c-label">По</TableHead><TableHead className="c-label">Откуда</TableHead><TableHead className="c-label">Пометка</TableHead>
              </TableRow></TableHeader>
              <TableBody>
                {hist.data.map((a) => {
                  const note = aliasNoteLabel(a);
                  return (
                    <TableRow key={`${a.person_id}|${a.kind}|${a.valid_from}|${a.source}`} className="border-border/40">
                      <TableCell><PersonCell id={a.person_id} display={a.display} kind={a.person_kind} range={range} /></TableCell>
                      <TableCell className="text-[13px]">{ALIAS_KIND_LABELS[a.kind]}</TableCell>
                      <TableCell className="font-mono text-xs whitespace-nowrap" title={formatTs(a.valid_from)}>{day(a.valid_from)}</TableCell>
                      <TableCell className="font-mono text-xs whitespace-nowrap">{a.valid_to ? <span title={formatTs(a.valid_to)}>{day(a.valid_to)}</span> : <Badge variant="secondary">действует</Badge>}</TableCell>
                      <TableCell className="text-[13px] text-muted-foreground">{aliasSourceLabel(a.source)}</TableCell>
                      <TableCell className="text-[13px] text-muted-foreground">
                        {a.held && <Badge variant="outline" className="mr-1.5">на удержании</Badge>}
                        {note}
                      </TableCell>
                    </TableRow>
                  );
                })}
              </TableBody>
            </DataWell>
          )}
        </Panel>
      )}

      {!seen.ok ? <StorageUnavailable reason={seen.error} /> : (
        <>
          <Panel label={`Где встречалось · ${RANGES[range].label}`} meta={seen.data.kind === "ip" ? "как адрес, с которого шли действия" : "как учётка в событиях"}>
            {seen.data.rows.length === 0 ? (
              <Empty icon={SearchX} title={`За ${RANGES[range].label} в журнале не встречалось`} action={<Link href={journal} className={LINK}>Открыть журнал</Link>} />
            ) : (
              <>
                {sightTable(sightRows.slice(0, SIGHT_SHOWN))}
                {sightRows.length > SIGHT_SHOWN && (
                  <details className="group mt-3">
                    <summary className="flex cursor-pointer list-none items-center gap-1.5 text-[13px] text-muted-foreground hover:text-foreground [&::-webkit-details-marker]:hidden">
                      <ChevronRight className="size-3.5 transition-transform group-open:rotate-90" strokeWidth={1.5} aria-hidden />
                      Ещё {fmtNum(sightRows.length - SIGHT_SHOWN)} строк
                    </summary>
                    <div className="mt-3">{sightTable(sightRows.slice(SIGHT_SHOWN))}</div>
                  </details>
                )}
                <p className="mt-3 text-sm text-muted-foreground">Отдельные события — <Link href={journal} className={LINK}>в журнале</Link>.</p>
              </>
            )}
          </Panel>
          {seen.data.kind === "ip" && (vpn.length > 0 ? (
            <Panel label={`Подключения к VPN с этого адреса · ${RANGES[range].label}`} meta="внешний адрес, с которого подключался клиент VPN">{vpnTable}</Panel>
          ) : (
            <details className="group text-[13px] text-muted-foreground">
              <summary className="flex cursor-pointer list-none items-center gap-1.5 hover:text-foreground [&::-webkit-details-marker]:hidden">
                <ChevronRight className="size-3.5 transition-transform group-open:rotate-90" strokeWidth={1.5} aria-hidden />
                Подключения к VPN с этого адреса · {RANGES[range].label}: нет
              </summary>
              <p className="mt-2 pl-5">За период клиенты VPN не подключались с <Copyable value={raw} />.</p>
            </details>
          ))}
        </>
      )}
    </>
  );
}

/** Адреса через запятую-пробел с переносом; каждый — ссылка «чей это адрес». */
function IpList({ ips, range }: { ips: string[]; range: ActorRange }) {
  if (!ips.length) return <span className="text-muted-foreground">—</span>;
  return (
    <span className="flex max-w-[22rem] flex-wrap gap-x-2 gap-y-0.5">
      {ips.map((ip) => <Link key={ip} href={lookupHref(ip, range)} className={`break-all ${LINK}`}>{ip}</Link>)}
    </span>
  );
}
