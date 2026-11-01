import type { Metadata } from "next";
import Link from "next/link";
import { Copyable } from "@/components/console/copyable";
import { ActorRangeLinks } from "@/components/console/actor-forms";
import { ActorLookupForm } from "@/components/console/actor-lookup-form";
import { Led, PageHeader, Panel, StatTile } from "@/components/console/panel";
import { StorageUnavailable } from "@/components/console/storage-error";
import { Alert, AlertDescription, AlertTitle } from "@/components/ui/alert";
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from "@/components/ui/table";
import { safeQuery } from "@/lib/clickhouse";
import { listPersons, unboundSubjects } from "@/lib/actors";
import { requireActorAccess } from "@/lib/actors-access";
import { parseActorRange } from "@/lib/shared/actors";
import { RANGES } from "@/lib/shared/ranges";
import { searchHref } from "@/lib/shared/search-href";
import { fmtNum, formatAgo, formatTs } from "@/lib/shared/time";
import { RangeFilters } from "@/components/console/range-filters";
import { describeChips, inRange, timeBounds, timeLabel } from "@/lib/shared/filters";
import { ACTOR_RANGE_FIELDS, actorRangeChips, parseActorRanges } from "@/lib/shared/page-filters";

export const dynamic = "force-dynamic";
export const metadata: Metadata = { title: "Субъекты" };

export default async function ActorsPage({ searchParams }: PageProps<"/actors">) {
  const session = await requireActorAccess();
  const sp = await searchParams;
  const range = parseActorRange(typeof sp.range === "string" ? sp.range : undefined);
  // Точное окно активности (не шире 30 дней) главнее пресета; пороги событий и инцидентов — по итогам за окно.
  const ranges = parseActorRanges(sp);
  const bounds = ranges.time.from ? timeBounds(ranges.time) : null;
  const window = bounds ? { fromMs: bounds.startMs, toMs: bounds.endMs } : null;
  const periodLabel = window ? `интервал ${timeLabel(ranges.time)}` : `за ${RANGES[range].label}`;
  const filtersText = describeChips(actorRangeChips(ranges));
  const [pr, ur] = await Promise.all([safeQuery(() => listPersons(window ?? range)), safeQuery(() => unboundSubjects("24h"))]);
  const persons = pr.ok ? pr.data.filter((p) => inRange(p.events, ranges.events) && inRange(p.incidents, ranges.incidents)) : [];
  const isAdmin = session.role === "admin";

  return (
    <>
      <PageHeader title="Субъекты" subtitle="Паспорт — срез журнала по человеку или служебной учётке за период с учётом времени действия алиасов. Каждый просмотр паспорта записывается в журнал действий.">
        <ActorRangeLinks current={window ? "" : range} base="/actors" />
      </PageHeader>

      <Panel label="Кому принадлежит" meta="почта, логин, телефон, IP, хост — чей сейчас, чей раньше, где встречался">
        <ActorLookupForm range={range} />
      </Panel>

      {!pr.ok ? (
        <StorageUnavailable reason={pr.error} />
      ) : (
        <>
          <div className="grid grid-cols-2 gap-6 md:grid-cols-4">
            <StatTile label="Персон" value={fmtNum(pr.data.length)} />
            <StatTile label={`Активны ${periodLabel}`} value={fmtNum(pr.data.filter((p) => p.events > 0).length)} />
            <StatTile label="Служебных учёток" value={fmtNum(pr.data.filter((p) => p.kind === "service").length)} />
            <StatTile label="С инцидентами" value={fmtNum(pr.data.filter((p) => p.incidents > 0).length)} led={pr.data.some((p) => p.incidents > 0) ? "var(--status-warn)" : "var(--status-ok)"} />
          </div>

          <Panel label={`Персоны · активность ${periodLabel}`} meta="события и инциденты считаются по алиасам в их интервалах действия">
            <div className="mb-4"><RangeFilters time timeLabel="Окно активности, UTC (до 30 дней)" fields={ACTOR_RANGE_FIELDS} idPrefix="actors" /></div>
            {pr.data.length > 0 && persons.length === 0 ? (
              <p className="text-sm text-muted-foreground">Нет персон по фильтрам: {filtersText} — ослабьте пороги или расширьте окно.</p>
            ) : pr.data.length === 0 ? (
              <div className="space-y-2 text-sm text-muted-foreground">
                <p>Персон пока нет.</p>
                <p>Источники: файл <span className="font-mono">identities.yml</span> у движка, события <span className="font-mono">identity.alias</span> от экспортеров, <span className="font-mono">PUT /api/v1/identities</span> или привязка непривязанного субъекта ниже.</p>
              </div>
            ) : (
              <div className="c-well overflow-x-auto p-2">
                <Table>
                  <TableHeader>
                    <TableRow className="border-border/60">
                      <TableHead className="c-label">Персона</TableHead>
                      <TableHead className="c-label">Идентификатор</TableHead>
                      <TableHead className="c-label">Вид</TableHead>
                      <TableHead className="c-label">Команда</TableHead>
                      <TableHead className="c-label text-right">Алиасов</TableHead>
                      <TableHead className="c-label text-right">Событий</TableHead>
                      <TableHead className="c-label text-right">Инцидентов</TableHead>
                      <TableHead className="c-label">Последняя активность (UTC)</TableHead>
                    </TableRow>
                  </TableHeader>
                  <TableBody>
                    {persons.map((p) => (
                      <TableRow key={p.person_id} className="border-border/40">
                        <TableCell><Link href={`/actors/${encodeURIComponent(p.person_id)}?range=${range}`} className="text-[var(--ring)] hover:underline">{p.display || p.person_id}</Link></TableCell>
                        <TableCell className="font-mono text-xs"><Copyable value={p.person_id} label="Идентификатор" /></TableCell>
                        <TableCell className="text-xs">{p.kind === "service" ? "служебная" : "человек"}</TableCell>
                        <TableCell className="text-xs">{p.team || "—"}</TableCell>
                        <TableCell className="text-right font-mono text-xs">{fmtNum(p.aliases)}</TableCell>
                        <TableCell className="text-right font-mono text-xs">{fmtNum(p.events)}</TableCell>
                        <TableCell className="text-right font-mono text-xs">{p.incidents > 0 ? <span className="text-[var(--status-warn)]">{fmtNum(p.incidents)}</span> : "0"}</TableCell>
                        <TableCell className="font-mono text-xs whitespace-nowrap" title={p.last_ts ? formatAgo(p.last_ts) : undefined}>{p.last_ts ? formatTs(p.last_ts) : "—"}</TableCell>
                      </TableRow>
                    ))}
                  </TableBody>
                </Table>
              </div>
            )}
          </Panel>
        </>
      )}

      <Panel label="Не привязанные субъекты · 24 часа" meta="actor_name без действующего алиаса на момент последней активности">
        {!ur.ok ? (
          <Alert>
            <AlertTitle>Список недоступен</AlertTitle>
            <AlertDescription>{ur.error}</AlertDescription>
          </Alert>
        ) : ur.data.length === 0 ? (
          <p className="text-sm text-muted-foreground">Все активные субъекты за сутки привязаны к персонам.</p>
        ) : (
          <div className="c-well overflow-x-auto p-2">
            <Table>
              <TableHeader>
                <TableRow className="border-border/60">
                  <TableHead className="c-label">Субъект</TableHead>
                  <TableHead className="c-label text-right">Событий</TableHead>
                  <TableHead className="c-label">Источники</TableHead>
                  <TableHead className="c-label">Последнее (UTC)</TableHead>
                  <TableHead className="c-label">Действие</TableHead>
                </TableRow>
              </TableHeader>
              <TableBody>
                {ur.data.map((u) => (
                  <TableRow key={u.actor_name} className="border-border/40">
                    <TableCell className="font-mono text-xs"><Copyable value={u.actor_name} href={searchHref.actorEvents(u.actor_name)} label="Субъект" /></TableCell>
                    <TableCell className="text-right font-mono text-xs">{fmtNum(u.count)}</TableCell>
                    <TableCell className="font-mono text-xs">{u.sources.join(", ") || "—"}</TableCell>
                    <TableCell className="font-mono text-xs whitespace-nowrap">{formatTs(u.last_ts)}</TableCell>
                    <TableCell className="text-xs">
                      <span className="flex items-center gap-2">
                        <Led color="var(--status-warn)" />
                        {isAdmin
                          ? <Link href={searchHref.actor(u.actor_name)} className="text-[var(--ring)] hover:underline">привязать</Link>
                          : <Link href={searchHref.actor(u.actor_name)} className="text-[var(--ring)] hover:underline">проверить</Link>}
                      </span>
                    </TableCell>
                  </TableRow>
                ))}
              </TableBody>
            </Table>
          </div>
        )}
      </Panel>
    </>
  );
}
