import type { Metadata } from "next";
import Link from "next/link";
import { notFound } from "next/navigation";
import { ArrowLeft } from "lucide-react";
import { ResponseLog } from "@/components/console/response-log";
import { ChainTable } from "@/components/console/chain-table";
import { Copyable } from "@/components/console/copyable";
import { searchHref } from "@/lib/shared/search-href";
import { DownloadButton } from "@/components/console/download-button";
import { Led, PageHeader, Panel } from "@/components/console/panel";
import { IncidentWiki } from "@/components/console/incident-wiki";
import { IncidentActionBoundary } from "@/components/console/incident-action-boundary";
import { LevelBadge, StatusBadge } from "@/components/console/incident-badges";
import { IncidentStatusForm } from "@/components/console/incident-status-form";
import { BlockIpButton } from "@/components/console/block-ip-button";
import { UnblockIpButton } from "@/components/console/unblock-ip-button";
import { StorageUnavailable } from "@/components/console/storage-error";
import { Button } from "@/components/ui/button";
import { Alert, AlertDescription, AlertTitle } from "@/components/ui/alert";
import { RefreshDataButton } from "@/components/console/refresh-data-button";
import { TriageReopenButton } from "@/components/console/triage-reopen-button";
import { listUsers, requirePageSession } from "@/lib/auth";
import { safeQuery } from "@/lib/clickhouse";
import { unblockIpAction } from "@/lib/incident-actions";
import { ROLE_RANK } from "@/lib/shared/incidents";
import { closingEvent, incidentMarkdown } from "@/lib/shared/incident-wiki";
import { reactionDeadline, reactionLate, reactionOverdue } from "@/lib/shared/incident-sla";
import { parseSimilarLine } from "@/lib/shared/incident-lines";
import { fmtNum, formatTs } from "@/lib/shared/time";
import { agentVerdictsFor, incidentComments, incidentFirstResponse, incidentGet, incidentStateHistory, blockCandidatesFor, verdictGet, responseLog, respondStatus, triageVerdictClaim, INCIDENT_STATUSES } from "@/lib/argus-queries";
import { MarkdownBody } from "@/components/console/markdown-body";
import { VERDICT_RU } from "@/lib/shared/triage-verdict";
import { closureLabelText, isOpsIncident } from "@/lib/shared/closure-label";
import { blindComments, hideVerdicts } from "@/lib/blind";

export const dynamic = "force-dynamic";

const ID_RE = /^INC-\d{1,9}$/;

export async function generateMetadata({ params }: PageProps<"/incidents/[id]">): Promise<Metadata> {
  const { id } = await params;
  return { title: `${ID_RE.test(id) ? id : "Инцидент"} · Инциденты` };
}

export default async function IncidentPage({ params }: PageProps<"/incidents/[id]">) {
  const session = await requirePageSession();
  const canEdit = ROLE_RANK[session.role] >= ROLE_RANK.analyst;
  const { id } = await params;
  if (!ID_RE.test(id)) notFound();

  const r = await safeQuery(() => incidentGet(id));
  if (!r.ok) {
    return (
      <>
        <PageHeader title={<span className="font-mono">{id}</span>} />
        <StorageUnavailable reason={r.error} />
      </>
    );
  }
  const inc = r.data;
  if (!inc) notFound();

  // Слепая выборка: до завершения консоль не показывает вердикт агента и анализ
  // модели — ответ человека должен быть независим от них. Не запрашиваем вовсе,
  // чтобы ничего не утекло в разметку страницы.
  const blind = hideVerdicts(inc);
  const [vr, ur, rr, cr, hr, fr, tr, ar] = await Promise.all([
    safeQuery(() => blind ? Promise.resolve(null) : verdictGet(id)),
    safeQuery(() => session.role === "admin" ? listUsers() : Promise.resolve([])),
    safeQuery(() => responseLog({ incidentId: id, limit: 20 })),
    safeQuery(() => incidentComments(id)),
    safeQuery(() => incidentStateHistory(id)),
    safeQuery(() => incidentFirstResponse(id)),
    safeQuery(() => triageVerdictClaim(id)),
    safeQuery(() => blind ? Promise.resolve([]) : agentVerdictsFor(id)),
  ]);
  const triageClaim = tr.ok ? tr.data : null;
  const agentVerdicts = ar.ok ? ar.data : [];
  const verdict = vr.ok ? vr.data : null;
  const users = ur.ok ? ur.data : [];
  const responses = rr.ok ? rr.data : [];
  // Комментарий agent:* — копия Markdown вердикта: в слепом разборе не уходит в props.
  const comments = cr.ok ? (blind ? blindComments(cr.data) : cr.data) : [];
  const changes = hr.ok ? hr.data : [];
  const firstResponse = fr.ok ? fr.data : null;
  const missing = [!vr.ok && "анализ модели", !ur.ok && "список сотрудников", !rr.ok && "журнал реагирования", !cr.ok && "записи команды", !hr.ok && "история изменений", !fr.ok && "время первой реакции", !ar.ok && "вердикты агента"].filter(Boolean);

  const mitre = inc.tags.filter((t) => t.startsWith("attack.t")).map((t) => t.replace("attack.", "").toUpperCase());
  const blockable = blockCandidatesFor(inc);
  const closure = closingEvent(inc.status, changes);
  const markdown = incidentMarkdown(inc, verdict, changes, comments, { verdict: !vr.ok, history: !hr.ok, comments: !cr.ok, blind });
  // Активные блокировки движка — только когда есть кому их снимать и что показывать.
  const respond = canEdit ? await respondStatus() : null;
  const activeBlocks = (respond?.active ?? []).filter((b) => b.incident === inc.incident_id || blockable.includes(b.ip));
  const activeIps = new Set(activeBlocks.map((b) => b.ip));
  const similar = inc.similar.map(parseSimilarLine).filter((s): s is NonNullable<typeof s> => s !== null);
  const deadline = reactionDeadline(inc.created_at, inc.level);
  const late = reactionLate(inc.created_at, inc.level, firstResponse);

  return (
    <IncidentActionBoundary id={inc.incident_id} revision={`${inc.updated_at}|${comments.length}|${changes.length}`}>
      <PageHeader
        title={
          <>
            <span className="font-mono">{inc.incident_id}</span>{" "}
            <span className="text-muted-foreground">{inc.rule_title}</span>
          </>
        }
      >
        <div className="flex flex-wrap items-center gap-2">
          <LevelBadge level={inc.level} />
          <StatusBadge status={inc.status} />
          <RefreshDataButton />
          <DownloadButton href={`/api/incidents/${inc.incident_id}`} filename={`${inc.incident_id}.json`}>JSON</DownloadButton>
          <DownloadButton href={`/api/incidents/${inc.incident_id}/markdown`} filename={`${inc.incident_id}.md`}>Markdown</DownloadButton>
          <Button asChild variant="ghost" size="sm">
            <Link href="/incidents"><ArrowLeft strokeWidth={1.5} />К ленте</Link>
          </Button>
        </div>
      </PageHeader>

      {missing.length > 0 && <Alert>
        <AlertTitle>Часть данных временно недоступна</AlertTitle>
        <AlertDescription>Не удалось загрузить: {missing.join(", ")}. Карточка и действия доступны. Обновите данные, чтобы повторить загрузку.</AlertDescription>
      </Alert>}
      <div className="grid min-w-0 gap-6 xl:grid-cols-[minmax(0,1.15fr)_minmax(0,1fr)]">
        <div className="flex min-w-0 flex-col gap-6">
          {blind && (
            <Panel label="Разбор вслепую" meta="подсказки скрыты до завершения">
              <p className="text-sm text-muted-foreground">
                Инцидент попал в слепую выборку: вердикт агента и анализ модели появятся после завершения.
                Ответ при закрытии сохраняется с пометкой «вслепую» — по таким ответам проверяется качество подсказок.
              </p>
            </Panel>
          )}
          {!blind && (triageClaim || agentVerdicts.length > 0) && (
            <Panel label="Разбор агентом" meta={agentVerdicts.length ? `${fmtNum(agentVerdicts.length)} вердикт(ов) · новые первыми` : "отметка без вердикта"}>
              {agentVerdicts.length > 0 ? (
                <ol className="space-y-4">
                  {agentVerdicts.map((v) => (
                    <li key={v.session_id} className="border-l border-border pl-3">
                      <div className="mb-1 flex flex-wrap items-center gap-2 font-mono text-xs text-muted-foreground">
                        <span>{formatTs(v.created_at)}</span>
                        <span>· agent:{v.agent}</span>
                        <span className="text-foreground">· {VERDICT_RU[v.verdict] ?? v.verdict}</span>
                        <span>· уверенность {v.confidence.toFixed(1)}</span>
                        {v.human_needed === 1 && <span className="text-[var(--status-warn)]">· нужен человек</span>}
                      </div>
                      <MarkdownBody className="c-well max-h-[50vh] overflow-auto p-3 text-sm leading-relaxed break-words">{v.markdown}</MarkdownBody>
                    </li>
                  ))}
                </ol>
              ) : (
                <p className="text-sm text-muted-foreground">Отметка «вердикт принят» стоит, но текста вердикта в ARGUS нет: сессия {triageClaim?.session_id} не завершила запись.</p>
              )}
              {triageClaim && (
                <p className="mt-3 text-xs text-muted-foreground">
                  Вердикт агента — не статус инцидента: статус меняет оператор в «Отработке». Повторный запуск агента по этому инциденту не получит сессию, пока здесь не разрешён повторный разбор.
                </p>
              )}
              {canEdit && triageClaim && <div className="mt-3"><TriageReopenButton incidentId={inc.incident_id} /></div>}
            </Panel>
          )}
          {(inc.status === "closed" || inc.status === "false_positive") && (
            <Panel label="Завершение инцидента" meta={closure?.kind === "auto_close" ? "автоматика" : "оператор"}>
              {!hr.ok ? <p role="status" className="text-sm text-muted-foreground">История завершения временно недоступна.</p> : <dl className="grid gap-x-4 gap-y-2 text-sm sm:grid-cols-[9rem_1fr]">
                <dt className="text-muted-foreground">Кем</dt><dd>{closure ? closure.kind === "auto_close" ? "ARGUS (автоматически)" : closure.actor : "не зафиксировано в истории"}</dd>
                <dt className="text-muted-foreground">Когда</dt><dd>{closure ? formatTs(closure.changed_at) : "не зафиксировано в истории"}</dd>
                {closure && closureLabelText(closure) && <><dt className="text-muted-foreground">Ответ</dt><dd>{closureLabelText(closure)}</dd></>}
                <dt className="text-muted-foreground">Причина</dt><dd className="whitespace-pre-wrap">{closure?.reason || "не зафиксирована"}</dd>
              </dl>}
            </Panel>
          )}
          <Panel label={`Цепочка событий · ${fmtNum(inc.event_count)} шт.`} meta={`${formatTs(inc.first_ts)} → ${formatTs(inc.last_ts)}`}>
            <ChainTable chain={inc.chain} date={formatTs(inc.first_ts, "date")} />
            <dl className="mt-4 grid grid-cols-[auto_1fr] gap-x-6 gap-y-1.5 text-[13px]">
              <dt className="text-[var(--text-tertiary)]">субъект</dt><dd>{inc.actor_name ? <Copyable value={inc.actor_name} href={searchHref.actor(inc.actor_name)} label="Субъект" /> : "—"}</dd>
              <dt className="text-[var(--text-tertiary)]">узел</dt><dd>{inc.node ? <Copyable value={inc.node} href={searchHref.node(inc.node)} label="Узел" /> : "—"}</dd>
              <dt className="text-[var(--text-tertiary)]">источники</dt><dd className="font-mono text-[12.5px]">{inc.sources.join(", ") || "—"}</dd>
              <dt className="text-[var(--text-tertiary)]">правило</dt><dd><Copyable value={inc.rule_id} label="Правило" /> · {inc.tags.join(", ") || "без тегов"}</dd>
              <dt className="text-[var(--text-tertiary)]">ответственный</dt><dd>{inc.owner || "не назначен"}</dd>
              <dt className="text-[var(--text-tertiary)]">реакция до</dt><dd className="font-mono text-[12.5px]">{deadline ? formatTs(deadline) : "—"}</dd>
              <dt className="text-[var(--text-tertiary)]">первая реакция</dt><dd className={late === true || reactionOverdue(inc.created_at, inc.level, inc.status) ? "text-destructive" : ""}>
                {!fr.ok ? "временно недоступна" : firstResponse ? `${formatTs(firstResponse)} · ${late ? "с опозданием" : "в срок"}`
                  : inc.status === "new" ? reactionOverdue(inc.created_at, inc.level, inc.status) ? "просрочена, ожидается" : "ожидается"
                  : "не зафиксирована в журнале"}
              </dd>
              <dt className="text-[var(--text-tertiary)]">ATT&amp;CK</dt><dd>{mitre.length ? mitre.map((m) => (
                <a key={m} href={`https://attack.mitre.org/techniques/${m.replace(".", "/")}/`} target="_blank" rel="noreferrer" className="mr-2 text-[var(--ring)] hover:underline">{m}</a>
              )) : "—"}</dd>
              <dt className="text-[var(--text-tertiary)]">ПДн</dt><dd>{inc.pii === 1 ? <span className="text-[var(--status-warn)]">есть — разбор только локальной моделью</span> : "нет"}</dd>
            </dl>
          </Panel>

          {(inc.enrichment?.length ?? 0) > 0 && (
            <Panel label="Обогащение · EDR · NGFW · CMDB" meta={`${fmtNum(inc.enrichment.length)} строк`}>
              <pre className="c-well overflow-x-auto p-4 font-mono text-[12.5px] leading-[1.75]">
{inc.enrichment.join("\n")}
              </pre>
            </Panel>
          )}

          {similar.length > 0 && (
            <Panel label="Похожие закрытые инциденты · 90 дней">
              <ul className="space-y-1 font-mono text-xs">
                {similar.map((s) => (
                  <li key={s.id} className="border-l border-border pl-3">
                    <Link href={`/incidents/${s.id}`} className="text-[var(--ring)] hover:underline">{s.id}</Link>
                    {s.date && <span className="text-muted-foreground"> · {s.date}</span>}
                    {s.status && <> · {INCIDENT_STATUSES[s.status as keyof typeof INCIDENT_STATUSES] ?? s.status}</>}
                    {s.title && <> · {s.title}</>}
                    {s.note && <span className="text-muted-foreground"> · {s.note}</span>}
                  </li>
                ))}
              </ul>
            </Panel>
          )}

          {responses.length > 0 && (
            <Panel label="Реагирование · автоматика и оператор" meta={`${fmtNum(responses.length)} записей`}>
              <ResponseLog rows={responses} compact />
            </Panel>
          )}

          {canEdit && (blockable.length > 0 || activeBlocks.length > 0) && (
            <Panel label="Обратный канал · блокировка адреса" meta={respond?.error ? "движок недоступен" : `режим ${respond?.mode ?? "—"}`}>
              <div className="space-y-2">
                {blockable.filter((ip) => !activeIps.has(ip)).map((ip) => <BlockIpButton key={ip} incidentId={inc.incident_id} ip={ip} />)}
                {activeBlocks.length > 0 && (
                  <div className="mt-3 border-t border-border pt-3">
                    <div className="c-label mb-2">Активные блокировки</div>
                    <ul className="space-y-1">
                      {activeBlocks.map((b) => (
                        <li key={`${b.ip}|${b.incident}`} className="flex flex-wrap items-center gap-3 font-mono text-xs">
                          <Led color="var(--status-err)" />
                          <Copyable value={b.ip} href={searchHref.srcip(b.ip)} label="IP" />
                          <span className="text-muted-foreground">{!b.until || b.until.startsWith("0001-") ? "бессрочно" : `до ${formatTs(b.until)}`}{b.manual ? " · оператор" : ""}{b.executors?.length ? ` · ${b.executors.join(", ")}` : ""}</span>
                          <UnblockIpButton ip={b.ip} incidentId={inc.incident_id} action={unblockIpAction} />
                        </li>
                      ))}
                    </ul>
                  </div>
                )}
                {respond?.error && <p className="text-xs text-destructive">{respond.error}</p>}
              </div>
            </Panel>
          )}

          <Panel label="Отработка" meta={inc.owner ? `ответственный: ${inc.owner}` : "без ответственного"}>
            {changes.length > 0 && <div className="mb-4 space-y-2">
              <div className="c-label">История изменений {changes.length === 200 ? "// последние 200" : `// ${changes.length}`}</div>
              <ol className="space-y-1 font-mono text-xs">
                {changes.map((change) => <li key={change.event_id} className="border-l border-border pl-3">
                  {formatTs(change.changed_at)} · {change.actor} · {change.kind === "take" ? "взял в работу" : change.kind === "assign" ? "назначил" : change.kind === "auto_close" ? "закрыто автоматически" : "изменил статус"} · {INCIDENT_STATUSES[change.status] ?? change.status}{change.owner ? ` · ${change.owner}` : ""}{closureLabelText(change) ? ` · ${closureLabelText(change)}` : ""}{change.reason ? ` · причина: ${change.reason}` : ""}
                </li>)}
              </ol>
            </div>}
            {canEdit ? <IncidentStatusForm
              incidentId={inc.incident_id}
              status={inc.status}
              ops={isOpsIncident(inc.tags)}
              owner={inc.owner}
              currentUser={session.user}
              isAdmin={session.role === "admin"}
              users={users.map((u) => ({ name: u.name, role: u.role }))}
              exceptions={[
                inc.actor_name ? { field: "actor.name", value: inc.actor_name, label: "субъект" } : null,
                inc.node ? { field: "node", value: inc.node, label: "узел" } : null,
              ].filter((x): x is { field: string; value: string; label: string } => x !== null)}
            /> : <p className="text-sm text-muted-foreground">статус: <StatusBadge status={inc.status} /> · менять отработку может аналитик</p>}
          </Panel>
        </div>

        <IncidentWiki id={inc.incident_id} markdown={markdown} canEdit={canEdit} />
      </div>
    </IncidentActionBoundary>
  );
}
