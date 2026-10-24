import type { Metadata } from "next";
import Link from "next/link";
import { RefreshDataButton } from "@/components/console/refresh-data-button";
import { Pager } from "@/components/console/pager";
import { PageHeader, Panel, StatTile } from "@/components/console/panel";
import { LevelBadge, StatusBadge } from "@/components/console/incident-badges";
import { StorageUnavailable } from "@/components/console/storage-error";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import {
  Table,
  TableBody,
  TableCell,
  TableHead,
  TableHeader,
  TableRow,
} from "@/components/ui/table";
import { requirePageSession } from "@/lib/auth";
import { safeQuery } from "@/lib/clickhouse";
import { INCIDENT_STATUSES, incidentClosuresFor, incidentStats, incidentsList, verdictsFor, type VerdictRow } from "@/lib/argus-queries";
import { isIncidentStatus } from "@/lib/shared/incidents";
import { reactionDeadline, reactionOverdue } from "@/lib/shared/incident-sla";
import { verdictState, type VerdictState } from "@/lib/shared/incidents";
import { INCIDENT_LEVEL_LABELS } from "@/lib/shared/labels";
import { clampPage } from "@/lib/shared/limits";
import { fmtNum, formatAgo, formatTs } from "@/lib/shared/time";

export const dynamic = "force-dynamic";
export const metadata: Metadata = { title: "Инциденты" };

const VERDICT_CELL: Record<VerdictState, (v: VerdictRow | undefined) => React.ReactNode> = {
  missing: () => <span className="font-mono text-xs">разбор ещё не готов</span>,
  error: (v) => <span className="font-mono text-xs text-destructive">аналитик: {v?.error}</span>,
  hidden: (v) => <span className="font-mono text-xs">уверенность {fmtNum(v?.confidence, 2)} ниже порога — разбор скрыт</span>,
  shown: (v) => <span className="line-clamp-3" title={v?.summary_ru}>{v?.summary_ru}</span>,
};
function VerdictCell({ v, unavailable = false }: { v: VerdictRow | undefined; unavailable?: boolean }) {
  if (unavailable) return <span className="font-mono text-xs text-destructive">разбор временно недоступен</span>;
  return <>{VERDICT_CELL[verdictState(v)](v)}</>;
}

const LEVELS = Object.keys(INCIDENT_LEVEL_LABELS);

export default async function IncidentsPage({ searchParams }: PageProps<"/incidents">) {
  const session = await requirePageSession();
  const params = await searchParams;
  const status = isIncidentStatus(params.status) ? params.status : undefined;
  const level = typeof params.level === "string" && LEVELS.includes(params.level) ? params.level : undefined;
  const q = typeof params.q === "string" ? params.q.trim().slice(0, 200) : undefined;
  const page = clampPage(params.page);
  const queue = params.queue === "open" || params.queue === "mine" || params.queue === "unassigned" || params.queue === "overdue" ? params.queue : undefined;

  const href = (patch: Record<string, string | undefined>) => {
    const qs = new URLSearchParams();
    const next = { status, level, q, queue, page: undefined as string | undefined, ...patch };
    for (const [k, v] of Object.entries(next)) if (v) qs.set(k, v);
    const s = qs.toString();
    return s ? `/incidents?${s}` : "/incidents";
  };

  const r = await safeQuery(async () => {
    const [list, stats] = await Promise.all([incidentsList({ status, level, q, page, queue, user: session.user }), incidentStats()]);
    return { list, stats };
  });
  const verdicts = r.ok ? await safeQuery(() => verdictsFor(r.data.list.rows.map((x) => x.incident_id))) : null;
  const closures = r.ok ? await safeQuery(() => incidentClosuresFor(r.data.list.rows.map((x) => x.incident_id))) : null;
  const now = new Date();

  return (
    <>
      <PageHeader title="Инциденты">
        <div className="flex flex-wrap items-center gap-4">
          <RefreshDataButton />
          <span className="c-label">лента дежурного · правила из rules/</span>
        </div>
      </PageHeader>

      {!r.ok ? (
        <StorageUnavailable reason={r.error} />
      ) : (
        <>
          <div className="grid grid-cols-2 gap-6 md:grid-cols-4">
            <StatTile label="Всего" value={fmtNum(r.data.stats.total)} href="/incidents" />
            <StatTile label="Открытых" value={fmtNum(r.data.stats.open)} href="/incidents?queue=open" led={r.data.stats.open > 0 ? "var(--status-warn)" : "var(--status-ok)"} />
            <StatTile label="Эскалация" value={fmtNum(r.data.stats.escalated)} href="/incidents?status=escalated" led={r.data.stats.escalated > 0 ? "var(--status-err)" : "var(--status-ok)"} />
            <StatTile label="С ПДн" value={fmtNum(r.data.stats.pii)} />
          </div>

          <Panel label={`Очередь · ${fmtNum(r.data.list.total)} инцидентов`} meta={`страница ${r.data.list.page} из ${Math.max(1, Math.ceil(r.data.list.total / r.data.list.pageSize))}`}>
            {verdicts && !verdicts.ok && (
              <p role="status" className="mb-4 text-xs text-destructive">
                Вердикты модели временно недоступны; список инцидентов и действия остаются доступными.
              </p>
            )}
            <form action="/incidents" method="get" className="mb-4 flex flex-wrap items-end gap-2">
              {status && <input type="hidden" name="status" value={status} />}
              {level && <input type="hidden" name="level" value={level} />}
              {queue && <input type="hidden" name="queue" value={queue} />}
              <div className="w-full space-y-1 sm:w-96">
                <Label htmlFor="inc-q" className="c-label">Поиск</Label>
                <Input id="inc-q" name="q" defaultValue={q ?? ""} maxLength={200} placeholder="INC-…, правило, субъект, узел, источник" className="h-10 px-3" />
              </div>
              <Button type="submit" variant="secondary" className="min-h-10">Найти</Button>
              {q && (
                <Button asChild variant="ghost" className="min-h-10"><Link href={href({ q: undefined })}>сбросить</Link></Button>
              )}
            </form>
            <div className="mb-3 flex flex-wrap items-center gap-2" role="group" aria-label="Очередь работы">
              {([ [undefined, "Все"], ["open", "Открытые"], ["mine", "Мои"], ["unassigned", "Без ответственного"], ["overdue", "Просрочены"] ] as const).map(([key, label]) => (
                <Button key={key ?? "all"} asChild variant="secondary" size="sm" aria-pressed={queue === key}>
                  <Link href={href({ queue: key })}>{label}</Link>
                </Button>
              ))}
              <span className="text-[12px] text-[var(--text-tertiary)]">Реакция 24/7: критический — 15 мин, высокий — 1 ч, средний — 4 ч, низкий — 24 ч</span>
            </div>
            <div className="mb-5 flex flex-wrap items-center gap-2" role="group" aria-label="Фильтр по статусу и уровню">
              <Button asChild variant="secondary" size="sm" aria-pressed={!status}>
                <Link href={href({ status: undefined })}>все статусы</Link>
              </Button>
              {Object.entries(INCIDENT_STATUSES).map(([k, v]) => (
                <Button key={k} asChild variant="secondary" size="sm" aria-pressed={status === k}>
                  <Link href={href({ status: k })}>{v}</Link>
                </Button>
              ))}
              <span className="mx-2 h-5 w-px bg-border" aria-hidden />
              {LEVELS.map((l) => (
                <Button key={l} asChild variant="secondary" size="sm" aria-pressed={level === l}>
                  <Link href={href({ level: level === l ? undefined : l })}>{INCIDENT_LEVEL_LABELS[l]}</Link>
                </Button>
              ))}
            </div>
            <div className="c-well overflow-x-auto p-2">
              <Table className="min-w-[1050px] table-fixed">
                <colgroup>
                  <col className="w-[7%]" /><col className="w-[11%]" /><col className="w-[10%]" /><col className="w-[19%]" />
                  <col className="w-[9%]" /><col className="w-[21%]" /><col className="w-[12%]" /><col className="w-[11%]" />
                </colgroup>
                <TableHeader>
                  <TableRow className="border-border/60">
                    <TableHead className="c-label">Инцидент</TableHead>
                    <TableHead className="c-label">Начало (UTC)</TableHead>
                    <TableHead className="c-label">Источники</TableHead>
                    <TableHead className="c-label">Правило</TableHead>
                    <TableHead className="c-label">Уровень</TableHead>
                    <TableHead className="c-label">Вердикт модели</TableHead>
                    <TableHead className="c-label">Статус</TableHead>
                    <TableHead className="c-label">Ответственный / реакция</TableHead>
                  </TableRow>
                </TableHeader>
                <TableBody>
                  {r.data.list.rows.length === 0 && (
                    <TableRow>
                      <TableCell colSpan={8} className="py-8 text-center font-mono text-muted-foreground">
                        {q || status || level || queue ? "По этим условиям инцидентов нет — снимите фильтры" : "Инцидентов нет — движок ждёт событий (make replay заливает записанный трафик)"}
                      </TableCell>
                    </TableRow>
                  )}
                  {r.data.list.rows.map((row) => {
                    const v = verdicts?.ok ? verdicts.data[row.incident_id] : undefined;
                    const closure = closures?.ok ? closures.data[row.incident_id] : undefined;
                    return (
                      <TableRow key={row.incident_id} className="border-border/40">
                        <TableCell className="font-mono text-xs whitespace-normal break-words">
                          <Link href={`/incidents/${row.incident_id}`} className="text-[var(--ring)] hover:underline">
                            {row.incident_id}
                          </Link>
                          {row.pii === 1 && <span className="ml-2 text-[var(--status-warn)]" title="содержит ПДн">ПДн</span>}
                        </TableCell>
                        <TableCell className="font-mono text-xs whitespace-nowrap">
                          <time dateTime={formatTs(row.first_ts, "iso")} title={`${formatTs(row.first_ts)} · ${formatAgo(row.first_ts, now)}`}>
                            {formatTs(row.first_ts, "datetime")}
                          </time>
                        </TableCell>
                        <TableCell className="font-mono text-xs whitespace-normal break-words">{row.sources.join(" + ")}</TableCell>
                        <TableCell className="text-sm whitespace-normal break-words">
                          {row.rule_title}
                          <div className="font-mono text-xs text-muted-foreground">{row.rule_id} · {row.actor_name || "—"}</div>
                        </TableCell>
                        <TableCell><LevelBadge level={row.level} /></TableCell>
                        <TableCell className="text-sm whitespace-normal break-words text-muted-foreground">
                          <VerdictCell v={v} unavailable={verdicts !== null && !verdicts.ok} />
                        </TableCell>
                        <TableCell className="whitespace-normal break-words">
                          <StatusBadge status={row.status} />
                          {(row.status === "closed" || row.status === "false_positive") && (
                            <div className="mt-1 max-w-44 font-mono text-xs text-muted-foreground" title={closure?.reason || "Причина не зафиксирована"}>
                              {closure ? closure.kind === "auto_close" ? "ARGUS · автоматически" : `закрыл: ${closure.actor}` : "кто закрыл: неизвестно"}
                              <div className="line-clamp-2">{closure?.reason || "причина не записана"}</div>
                            </div>
                          )}
                        </TableCell>
                        <TableCell className="font-mono text-xs whitespace-normal break-words">
                          <div>{row.owner || "не назначен"}</div>
                          {row.status === "new" && reactionDeadline(row.created_at, row.level) && (
                            <div className={reactionOverdue(row.created_at, row.level, row.status, now) ? "text-destructive" : "text-muted-foreground"}>
                              {reactionOverdue(row.created_at, row.level, row.status, now) ? "просрочено · " : "до "}
                              {formatTs(reactionDeadline(row.created_at, row.level), "datetime")} UTC
                            </div>
                          )}
                        </TableCell>
                      </TableRow>
                    );
                  })}
                </TableBody>
              </Table>
            </div>
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
