import type { Metadata } from "next";
import Link from "next/link";
import { redirect } from "next/navigation";
import { ArrowLeft } from "lucide-react";
import { Copyable } from "@/components/console/copyable";
import { BindAliasForm } from "@/components/console/actor-forms";
import { Empty, Led, PageHeader, Panel } from "@/components/console/panel";
import { StorageUnavailable } from "@/components/console/storage-error";
import { Button } from "@/components/ui/button";
import { safeQuery } from "@/lib/clickhouse";
import { listPersons, resolveAlias } from "@/lib/actors";
import { ALIAS_VALUE_MAX, isIp, type AliasKind } from "@/lib/shared/actors";
import { searchHref } from "@/lib/shared/search-href";
import { formatTs } from "@/lib/shared/time";
import { requireActorAccess } from "@/lib/actors-access";

export const dynamic = "force-dynamic";
export const metadata: Metadata = { title: "Субъект по алиасу · Субъекты" };

/**
 * /actors/by-alias?v=<actor_name | IP | хост>: резолв в персону на «сейчас».
 * Одна персона — переход в паспорт; ни одной — «не привязан» со ссылкой в
 * журнал (и формой привязки для admin); несколько — «неоднозначно» с кандидатами.
 */
export default async function ByAliasPage({ searchParams }: PageProps<"/actors/by-alias">) {
  const session = await requireActorAccess();
  const sp = await searchParams;
  const raw = typeof sp.v === "string" ? sp.v.trim().slice(0, ALIAS_VALUE_MAX) : "";
  const back = (
    <Button asChild variant="ghost" size="sm"><Link href="/actors"><ArrowLeft strokeWidth={1.5} />К списку</Link></Button>
  );
  if (!raw) {
    return (
      <>
        <PageHeader title="Субъект по алиасу">{back}</PageHeader>
        <Panel label="Нет значения"><Empty>Укажите значение в параметре <span className="font-mono">v</span>: имя субъекта, адрес или хост.</Empty></Panel>
      </>
    );
  }
  const rr = await safeQuery(() => resolveAlias(raw));
  if (rr.ok && rr.data.status === "resolved") redirect(`/actors/${encodeURIComponent(rr.data.matches[0].person_id)}`);

  const ip = isIp(raw);
  const eventsHref = ip ? searchHref.eventSrc(raw) : searchHref.actorEvents(raw);
  const isAdmin = session.role === "admin";
  const persons = isAdmin ? await safeQuery(() => listPersons("24h")) : null;
  const guessKind: AliasKind = ip ? "ip" : raw.includes("@") ? "email" : "login";

  return (
    <>
      <PageHeader title={<>Субъект <span className="font-mono">{raw}</span></>}>{back}</PageHeader>
      {!rr.ok ? <StorageUnavailable reason={rr.error} /> : rr.data.status === "unbound" ? (
        <Panel label="Не привязан" meta="алиас не действует ни у одной персоны сейчас">
          <p className="flex items-center gap-2 text-sm"><Led color="var(--status-warn)" />Значение <Copyable value={raw} /> не привязано ни к одной персоне на текущий момент.</p>
          <p className="mt-2 text-sm text-muted-foreground">
            События по нему остаются в журнале: <Link href={eventsHref} className="text-[var(--ring)] hover:underline">открыть в журнале</Link>.
            {!isAdmin && " Привязать алиас к персоне может администратор."}
          </p>
        </Panel>
      ) : (
        <Panel label="Неоднозначно" meta={`${rr.data.matches.length} совпадений`}>
          <p className="flex items-center gap-2 text-sm"><Led color="var(--status-err)" />Значение сейчас действует у нескольких персон — выбор не делается автоматически.</p>
          <ul className="mt-3 space-y-1 font-mono text-xs">
            {rr.data.matches.map((m) => (
              <li key={`${m.person_id}|${m.alias_kind}|${m.valid_from}`} className="border-l border-border pl-3">
                <Link href={`/actors/${encodeURIComponent(m.person_id)}`} className="text-[var(--ring)] hover:underline">{m.display || m.person_id}</Link>
                <span className="text-muted-foreground"> · {m.person_id} · {m.alias_kind} · с {formatTs(m.valid_from)}{m.valid_to ? ` по ${formatTs(m.valid_to)}` : ""}</span>
              </li>
            ))}
          </ul>
          <p className="mt-3 text-sm text-muted-foreground">Закройте лишний алиас в паспорте одной из персон. События — <Link href={eventsHref} className="text-[var(--ring)] hover:underline">в журнале</Link>.</p>
        </Panel>
      )}
      {isAdmin && rr.ok && (
        <Panel label="Привязать к персоне" meta="только администратор · source = api">
          {persons && !persons.ok ? <Empty>Список персон недоступен: {persons.error}</Empty> : (
            <BindAliasForm persons={(persons?.ok ? persons.data : []).map((p) => ({ person_id: p.person_id, display: p.display }))} value={raw} kind={guessKind} />
          )}
        </Panel>
      )}
    </>
  );
}
