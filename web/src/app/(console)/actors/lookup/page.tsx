import type { Metadata } from "next";
import Link from "next/link";
import { ArrowLeft } from "lucide-react";
import { Copyable } from "@/components/console/copyable";
import { ALIAS_KIND_LABELS } from "@/components/console/actor-forms";
import { ActorLookupForm } from "@/components/console/actor-lookup-form";
import { Empty, Led, PageHeader, Panel } from "@/components/console/panel";
import { StorageUnavailable } from "@/components/console/storage-error";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from "@/components/ui/table";
import { safeQuery } from "@/lib/clickhouse";
import { audit } from "@/lib/argus-queries";
import { aliasHistory, aliasSightings, getPerson, resolveAlias } from "@/lib/actors";
import { ALIAS_VALUE_MAX, isIp, parseActorRange, PERSON_ID_RE } from "@/lib/shared/actors";
import { RANGES } from "@/lib/shared/ranges";
import { searchHref } from "@/lib/shared/search-href";
import { fmtNum, formatTs } from "@/lib/shared/time";
import { requireActorAccess } from "@/lib/actors-access";

export const dynamic = "force-dynamic";
export const metadata: Metadata = { title: "Кому принадлежит · Субъекты" };

const passport = (id: string) => `/actors/${encodeURIComponent(id)}`;

/**
 * /actors/lookup?v=<значение>&range=: кому принадлежит идентификатор сейчас,
 * кому принадлежал раньше (все интервалы алиасов, включая закрытые и
 * удержанные) и где значение встречалось в журнале за период. Каждый поиск —
 * в журнале действий (actor.lookup, strict): нет журнала — нет ответа.
 */
export default async function LookupPage({ searchParams }: PageProps<"/actors/lookup">) {
  const session = await requireActorAccess();
  const sp = await searchParams;
  const raw = typeof sp.v === "string" ? sp.v.trim().slice(0, ALIAS_VALUE_MAX) : "";
  const range = parseActorRange(typeof sp.range === "string" ? sp.range : undefined);
  const header = (
    <PageHeader title="Кому принадлежит" subtitle="Почта, логин, телефон, IP, хост или id персоны: чей он сейчас, чьим был раньше и где встречался в журнале. Каждый поиск записывается в журнал действий.">
      <Button asChild variant="ghost" size="sm"><Link href="/actors"><ArrowLeft strokeWidth={1.5} />Субъекты</Link></Button>
    </PageHeader>
  );
  if (!raw) {
    return (
      <>
        {header}
        <Panel label="Поиск"><ActorLookupForm range={range} /></Panel>
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
        <Panel label="Журнал действий недоступен" meta="console_audit">
          <p className="flex items-center gap-2 text-sm"><Led color="var(--status-err)" />{err instanceof Error ? err.message : "запись о поиске не выполнена"}</p>
          <p className="mt-2 text-sm text-muted-foreground">Поиск владельца показывается только с записью в журнале действий. Проверьте ClickHouse и повторите.</p>
        </Panel>
      </>
    );
  }
  const ip = isIp(raw);
  const [now, hist, seen, person] = await Promise.all([
    safeQuery(() => resolveAlias(raw)),
    safeQuery(() => aliasHistory(raw)),
    safeQuery(() => aliasSightings(raw, range)),
    PERSON_ID_RE.test(raw.toLowerCase()) ? safeQuery(() => getPerson(raw.toLowerCase())) : Promise.resolve(null),
  ]);
  const journal = ip ? searchHref.eventSrc(raw) : searchHref.actorEvents(raw);

  return (
    <>
      {header}
      <Panel label="Поиск"><ActorLookupForm value={raw} range={range} /></Panel>

      {person?.ok && person.data && (
        <Panel label="Это персона">
          <p className="text-sm"><Link href={passport(person.data.person_id)} className="text-[var(--ring)] hover:underline">{person.data.display || person.data.person_id}</Link>
            <span className="text-muted-foreground"> · {person.data.person_id} · паспорт с входами, узлами, сетью и инцидентами</span></p>
        </Panel>
      )}

      {!now.ok ? <StorageUnavailable reason={now.error} /> : (
        <Panel label="Сейчас" meta="действующие алиасы на текущий момент">
          {now.data.status === "unbound" ? (
            <p className="flex items-center gap-2 text-sm"><Led color="var(--status-warn)" />Сейчас <Copyable value={raw} /> не принадлежит ни одной персоне.</p>
          ) : (
            <ul className="space-y-1 text-sm">
              {now.data.status === "ambiguous" && <li className="flex items-center gap-2"><Led color="var(--status-err)" />Действует у нескольких персон одновременно — проверьте, какой алиас лишний.</li>}
              {now.data.matches.map((m) => (
                <li key={`${m.person_id}|${m.alias_kind}`} className="flex items-center gap-2">
                  <Led color="var(--status-ok)" />
                  <Link href={passport(m.person_id)} className="text-[var(--ring)] hover:underline">{m.display || m.person_id}</Link>
                  <span className="font-mono text-xs text-muted-foreground">{m.person_id} · {ALIAS_KIND_LABELS[m.alias_kind]} · с {formatTs(m.valid_from)}</span>
                </li>
              ))}
            </ul>
          )}
        </Panel>
      )}

      {!hist.ok ? <StorageUnavailable reason={hist.error} /> : (
        <Panel label="История владения" meta={`${fmtNum(hist.data.length)} интервалов · все время`}>
          {hist.data.length === 0 ? <Empty>Это значение ни разу не было алиасом персоны.</Empty> : (
            <Table>
              <TableHeader><TableRow>
                <TableHead>Персона</TableHead><TableHead>Вид</TableHead><TableHead>С</TableHead><TableHead>По</TableHead><TableHead>Откуда</TableHead><TableHead>Пометка</TableHead>
              </TableRow></TableHeader>
              <TableBody>
                {hist.data.map((a) => (
                  <TableRow key={`${a.person_id}|${a.kind}|${a.valid_from}|${a.source}`}>
                    <TableCell><Link href={passport(a.person_id)} className="text-[var(--ring)] hover:underline">{a.display || a.person_id}</Link>
                      {a.display && <span className="ml-1 font-mono text-xs text-muted-foreground">{a.person_id}</span>}</TableCell>
                    <TableCell className="text-xs">{ALIAS_KIND_LABELS[a.kind]}</TableCell>
                    <TableCell className="font-mono text-xs whitespace-nowrap">{formatTs(a.valid_from)}</TableCell>
                    <TableCell className="font-mono text-xs whitespace-nowrap">{a.valid_to ? formatTs(a.valid_to) : <Badge variant="secondary">действует</Badge>}</TableCell>
                    <TableCell className="font-mono text-xs">{a.source}</TableCell>
                    <TableCell className="text-xs text-muted-foreground">{a.held ? <Badge variant="outline">на удержании</Badge> : null} {a.note}</TableCell>
                  </TableRow>
                ))}
              </TableBody>
            </Table>
          )}
        </Panel>
      )}

      {!seen.ok ? <StorageUnavailable reason={seen.error} /> : (
        <>
          {seen.data.kind === "ip" && (
            <Panel label={`Подключения к VPN с этого адреса · ${RANGES[range].label}`} meta="внешний адрес клиента NetBird (attrs.connection_ip)">
              {seen.data.vpn.length === 0 ? <Empty>С этого адреса клиенты VPN не подключались.</Empty> : (
                <Table>
                  <TableHeader><TableRow><TableHead>Учётка</TableHead><TableHead>Устройство</TableHead><TableHead>Адрес в VPN</TableHead><TableHead>Снимков</TableHead><TableHead>Первый</TableHead><TableHead>Последний</TableHead></TableRow></TableHeader>
                  <TableBody>
                    {seen.data.vpn.map((c) => (
                      <TableRow key={`${c.actor_name}|${c.peer_name}`}>
                        <TableCell className="font-mono text-xs"><Link href={`/actors/lookup?v=${encodeURIComponent(c.actor_name)}&range=${range}`} className="text-[var(--ring)] hover:underline">{c.actor_name || "—"}</Link></TableCell>
                        <TableCell className="font-mono text-xs">{c.peer_name || "—"}</TableCell>
                        <TableCell className="font-mono text-xs">{c.peer_ip ? <Link href={`/actors/lookup?v=${encodeURIComponent(c.peer_ip)}&range=${range}`} className="text-[var(--ring)] hover:underline">{c.peer_ip}</Link> : "—"}</TableCell>
                        <TableCell className="text-xs">{fmtNum(c.events)}</TableCell>
                        <TableCell className="font-mono text-xs whitespace-nowrap">{formatTs(c.first_ts)}</TableCell>
                        <TableCell className="font-mono text-xs whitespace-nowrap">{formatTs(c.last_ts)}</TableCell>
                      </TableRow>
                    ))}
                  </TableBody>
                </Table>
              )}
            </Panel>
          )}
          <Panel label={`Где встречалось · ${RANGES[range].label}`} meta={seen.data.kind === "ip" ? "как адрес источника, без NetFlow" : "как субъект события"}>
            {seen.data.rows.length === 0 ? <Empty>За период в журнале нет. <Link href={journal} className="text-[var(--ring)] hover:underline">Открыть журнал</Link></Empty> : (
              <>
                <Table>
                  <TableHeader><TableRow>
                    <TableHead>Источник</TableHead><TableHead>Действие</TableHead><TableHead>{seen.data.kind === "ip" ? "Кто" : "Узел"}</TableHead><TableHead>{seen.data.kind === "ip" ? "Куда" : "С адресов"}</TableHead><TableHead>Событий</TableHead><TableHead>Последнее</TableHead>
                  </TableRow></TableHeader>
                  <TableBody>
                    {seen.data.rows.map((r) => (
                      <TableRow key={`${r.source}|${r.action}|${r.who}|${r.where}`}>
                        <TableCell className="font-mono text-xs">{r.source}</TableCell>
                        <TableCell className="font-mono text-xs">{r.action}</TableCell>
                        <TableCell className="font-mono text-xs">{seen.data.kind === "ip"
                          ? (r.who ? <Link href={`/actors/lookup?v=${encodeURIComponent(r.who)}&range=${range}`} className="text-[var(--ring)] hover:underline">{r.who}</Link> : <span className="text-muted-foreground">{r.where || "—"}</span>)
                          : (r.where || "—")}</TableCell>
                        <TableCell className="font-mono text-xs">{r.ips.length ? r.ips.join(", ") : "—"}</TableCell>
                        <TableCell className="text-xs">{fmtNum(r.events)}</TableCell>
                        <TableCell className="font-mono text-xs whitespace-nowrap" title={`с ${formatTs(r.first_ts)}`}>{formatTs(r.last_ts)}</TableCell>
                      </TableRow>
                    ))}
                  </TableBody>
                </Table>
                <p className="mt-3 text-sm text-muted-foreground">Отдельные события — <Link href={journal} className="text-[var(--ring)] hover:underline">в журнале</Link>.</p>
              </>
            )}
          </Panel>
        </>
      )}
    </>
  );
}
