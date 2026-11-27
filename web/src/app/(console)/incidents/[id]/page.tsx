import type { Metadata } from "next";
import Link from "next/link";
import { notFound } from "next/navigation";
import { CheckCheck, EyeOff, ListTree } from "lucide-react";
import { ResponseLog } from "@/components/console/response-log";
import { ChainTable } from "@/components/console/chain-table";
import { Copyable } from "@/components/console/copyable";
import { searchHref } from "@/lib/shared/search-href";
import { Ago } from "@/components/console/ago";
import { Empty, Led, PageHeader, Panel } from "@/components/console/panel";
import { FeedDay, FeedList, FeedRow } from "@/components/console/feed";
import { IncidentWiki } from "@/components/console/incident-wiki";
import { IncidentActionBoundary } from "@/components/console/incident-action-boundary";
import { LevelBadge, StatusBadge } from "@/components/console/incident-badges";
import { IncidentStatusForm, TakeForm } from "@/components/console/incident-status-form";
import { IncidentMoreMenu } from "@/components/console/incidents/incident-more-menu";
import { BlockIpButton } from "@/components/console/block-ip-button";
import { UnblockIpButton } from "@/components/console/unblock-ip-button";
import { StorageUnavailable } from "@/components/console/storage-error";
import { TONE_COLOR } from "@/components/console/tone";
import { Button } from "@/components/ui/button";
import { Alert, AlertDescription, AlertTitle } from "@/components/ui/alert";
import { TriageReopenButton } from "@/components/console/triage-reopen-button";
import { listUsers, requirePageSession } from "@/lib/auth";
import { safeQuery } from "@/lib/clickhouse";
import { unblockIpAction } from "@/lib/incident-actions";
import { ROLE_RANK } from "@/lib/shared/incidents";
import { closingEvent, incidentMarkdown } from "@/lib/shared/incident-wiki";
import { attackHref, changeVerb, formatWhen, incidentTechniques, nextAction, plainTags, plural, reactionView } from "@/lib/shared/incident-view";
import { parseSimilarLine } from "@/lib/shared/incident-lines";
import { toDtParam } from "@/lib/shared/filters";
import { fmtNum, formatTs, toDate } from "@/lib/shared/time";
import { agentVerdictsFor, incidentComments, incidentFirstResponse, incidentGet, incidentStateHistory, blockCandidatesFor, verdictGet, responseLog, respondStatus, triageVerdictClaim, INCIDENT_STATUSES } from "@/lib/argus-queries";
import { MarkdownBody } from "@/components/console/markdown-body";
import { VERDICT_RU } from "@/lib/shared/triage-verdict";
import { closureLabelText, isOpsIncident } from "@/lib/shared/closure-label";
import { attackFormOptions } from "@/lib/shared/attack";
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

  const techniques = incidentTechniques(inc.tags);
  const tags = plainTags(inc.tags);
  const blockable = blockCandidatesFor(inc);
  const closure = closingEvent(inc.status, changes);
  const markdown = incidentMarkdown(inc, verdict, changes, comments, { verdict: !vr.ok, history: !hr.ok, comments: !cr.ok, blind, console: true });
  // Активные блокировки движка — только когда есть кому их снимать и что показывать.
  const respond = canEdit ? await respondStatus() : null;
  const activeBlocks = (respond?.active ?? []).filter((b) => b.incident === inc.incident_id || blockable.includes(b.ip));
  const activeIps = new Set(activeBlocks.map((b) => b.ip));
  const similar = inc.similar.map(parseSimilarLine).filter((s): s is NonNullable<typeof s> => s !== null);
  const now = new Date();
  // Взятие в работу и есть первая реакция: время — по первому take в истории, иначе — по журналу реакции.
  const takenAt = [...changes].filter((c) => c.kind === "take").sort((a, b) => a.revision - b.revision)[0]?.changed_at ?? firstResponse;
  const reaction = !hr.ok && !fr.ok ? null : reactionView(inc, takenAt, now, (d) => `${formatWhen(d, now)} UTC`);
  const action = nextAction(inc, session.user, canEdit);
  // Журнал вокруг инцидента: кто, где, с запасом в 5 минут по краям цепочки.
  const firstMs = toDate(inc.first_ts)?.getTime();
  const lastMs = toDate(inc.last_ts)?.getTime() ?? firstMs;
  const journal = new URLSearchParams();
  if (inc.actor_name) journal.set("q", `actor:${inc.actor_name}`);
  if (inc.node) journal.set("host", inc.node);
  if (firstMs !== undefined && lastMs !== undefined) {
    journal.set("from", toDtParam(firstMs - 5 * 60_000));
    journal.set("to", toDtParam(lastMs + 5 * 60_000));
  }
  const journalHref = `/events?${journal}`;
  const sameDay = formatTs(inc.first_ts, "date") === formatTs(inc.last_ts, "date");
  const span = formatTs(inc.first_ts) === formatTs(inc.last_ts) ? `${formatTs(inc.first_ts, "time")} UTC, ${formatWhen(inc.first_ts, now).split(",")[0]}`
    : sameDay ? `${formatTs(inc.first_ts, "time")} – ${formatTs(inc.last_ts, "time")} UTC, ${formatWhen(inc.first_ts, now).split(",")[0]}`
    : `${formatWhen(inc.first_ts, now)} – ${formatWhen(inc.last_ts, now)} UTC`;
  const respondMode = respond?.error ? "движок недоступен" : respond?.mode === "ips" ? "автоблокировка включена" : respond?.mode === "simulate" ? "имитация: адреса не блокируются" : "только наблюдение";

  return (
    <IncidentActionBoundary id={inc.incident_id} revision={`${inc.updated_at}|${comments.length}|${changes.length}`}>
      <PageHeader
        back={{ href: "/incidents", label: "Инциденты" }}
        title={inc.rule_title || inc.rule_id}
        status={
          <div className="flex flex-wrap items-center gap-2">
            <LevelBadge level={inc.level} className="px-2 py-0.5 text-xs" />
            <StatusBadge status={inc.status} className="px-2 py-0.5 text-xs" />
            {blind && (
              <span className="inline-flex items-center gap-1 rounded-md border border-border px-2 py-0.5 text-xs text-muted-foreground" title="Разбор вслепую: вердикт агента и анализ модели скрыты до завершения, чтобы ответ аналитика был независимым">
                <EyeOff className="size-3.5" strokeWidth={1.5} aria-hidden />вслепую
              </span>
            )}
          </div>
        }
        subtitle={<span className="font-mono text-[13px] text-muted-foreground"><Copyable value={inc.incident_id} label="Номер инцидента" /> · <Copyable value={inc.rule_id} label="Правило" /></span>}
        actions={
          <div className="flex flex-wrap items-center gap-2">
            {action === "take" && <TakeForm incidentId={inc.incident_id} />}
            {action === "finish" && <Button asChild><Link href="#work">Завершить…</Link></Button>}
            <IncidentMoreMenu id={inc.incident_id} />
          </div>
        }
      />

      <section aria-label="Кто, где, когда" className="win p-4">
        <dl className="grid gap-x-8 gap-y-3 sm:grid-cols-2 lg:grid-cols-4">
          <Fact label="Кто">{inc.actor_name ? <Copyable value={inc.actor_name} href={searchHref.actor(inc.actor_name)} label="Субъект" /> : <span className="text-muted-foreground">не определён</span>}</Fact>
          <Fact label="Где">{inc.node ? <Copyable value={inc.node} href={searchHref.node(inc.node)} label="Узел" /> : <span className="text-muted-foreground">не определено</span>}</Fact>
          <Fact label="Когда"><span title={formatTs(inc.first_ts)}>{formatWhen(inc.first_ts, now)} UTC</span> <span className="text-muted-foreground">· <Ago ts={inc.first_ts} now={now} /></span></Fact>
          <Fact label="Источник">{inc.sources.length ? inc.sources.join(", ") : <span className="text-muted-foreground">—</span>}</Fact>
        </dl>
        <div className="mt-3 flex flex-wrap items-center gap-x-4 gap-y-1 border-t border-border pt-3 text-sm">
          {reaction ? (
            <span className="inline-flex items-center gap-2" style={{ color: reaction.tone === "muted" ? undefined : TONE_COLOR[reaction.tone] }}>
              <Led color={reaction.tone === "muted" ? "var(--text-tertiary)" : TONE_COLOR[reaction.tone]} />{reaction.text}
            </span>
          ) : <span className="text-muted-foreground">Срок реакции: нет данных</span>}
          <span className="text-muted-foreground">{inc.owner ? <>Ответственный: <span className="text-foreground">{inc.owner}</span></> : "Без ответственного"}</span>
        </div>
      </section>

      {missing.length > 0 && <Alert>
        <AlertTitle>Часть данных временно недоступна</AlertTitle>
        <AlertDescription>Не удалось загрузить: {missing.join(", ")}. Карточка и действия доступны. Обновите данные, чтобы повторить загрузку.</AlertDescription>
      </Alert>}
      <div className="grid min-w-0 gap-6 xl:grid-cols-[minmax(0,1.15fr)_minmax(0,1fr)]">
        <div className="flex min-w-0 flex-col gap-6">
          {(inc.status === "closed" || inc.status === "false_positive") && (
            <Panel label="Завершение" meta={closure?.kind === "auto_close" ? "автоматически" : "аналитик"}>
              {!hr.ok ? <p role="status" className="text-sm text-muted-foreground">История завершения временно недоступна.</p> : <dl className="grid gap-x-4 gap-y-2 text-sm sm:grid-cols-[9rem_1fr]">
                <dt className="text-muted-foreground">Кем</dt><dd>{closure ? closure.kind === "auto_close" ? "ARGUS (автоматически)" : closure.actor : "не записано в истории"}</dd>
                <dt className="text-muted-foreground">Когда</dt><dd>{closure ? <span title={formatTs(closure.changed_at)}>{formatWhen(closure.changed_at, now)} UTC</span> : "не записано в истории"}</dd>
                {closure && closureLabelText(closure) && <><dt className="text-muted-foreground">Ответ</dt><dd>{closureLabelText(closure)}</dd></>}
                <dt className="text-muted-foreground">Причина</dt><dd className="whitespace-pre-wrap">{closure?.reason || "не записана"}</dd>
              </dl>}
            </Panel>
          )}
          <Panel label="Цепочка событий" meta={`${fmtNum(inc.event_count)} ${plural(inc.event_count, ["событие", "события", "событий"])} · ${span}`}>
            {inc.chain.length > 0 ? <ChainTable chain={inc.chain} date={formatTs(inc.first_ts, "date")} /> : (
              <Empty icon={ListTree} title={`${inc.event_count > 0 ? `Событий: ${fmtNum(inc.event_count)}. ` : ""}Строки цепочки движок не сохранил`}
                hint="Сами события есть в журнале — откройте его за время инцидента."
                action={<Link href={journalHref} className="text-[13px] text-[var(--ring)] hover:underline">Открыть в журнале за {formatTs(inc.first_ts, "time")}</Link>} />
            )}
            <dl className="mt-4 grid grid-cols-[auto_1fr] gap-x-6 gap-y-1.5 text-[13px]">
              <dt className="text-[var(--text-tertiary)]">Правило</dt>
              <dd><Copyable value={inc.rule_id} label="Правило" />{tags.length > 0 && <span className="text-muted-foreground"> · {tags.join(", ")}</span>}</dd>
              <dt className="text-[var(--text-tertiary)]">ATT&amp;CK</dt>
              <dd>{techniques.length ? techniques.map((m) => (
                <a key={m} href={attackHref(m)} target="_blank" rel="noreferrer" className="mr-2 font-mono text-[12px] text-[var(--ring)] hover:underline">{m}</a>
              )) : <span className="text-muted-foreground">не указано в правиле</span>}</dd>
              <dt className="text-[var(--text-tertiary)]">Персональные данные</dt>
              <dd>{inc.pii === 1 ? <span className="text-[var(--status-warn)]">есть — разбор только локальной моделью</span> : "нет"}</dd>
            </dl>
            {inc.chain.length > 0 && <p className="mt-3 text-[13px]"><Link href={journalHref} className="text-[var(--ring)] hover:underline">Все события в журнале за время инцидента →</Link></p>}
          </Panel>

          {!blind && (triageClaim || agentVerdicts.length > 0) && (
            <Panel label="Разбор агентом" meta={agentVerdicts.length ? `${fmtNum(agentVerdicts.length)} ${plural(agentVerdicts.length, ["вердикт", "вердикта", "вердиктов"])} · новые первыми` : "отметка без текста"}>
              {agentVerdicts.length > 0 ? (
                <ol className="space-y-4">
                  {agentVerdicts.map((v) => (
                    <li key={v.session_id} className="border-l border-border pl-3">
                      <div className="mb-1 flex flex-wrap items-center gap-x-2 text-[13px] text-muted-foreground">
                        <span className="font-medium text-foreground">{VERDICT_RU[v.verdict] ?? v.verdict}</span>
                        <span>· уверенность {v.confidence.toFixed(1)}</span>
                        {v.human_needed === 1 && <span className="text-[var(--status-warn)]">· нужен человек</span>}
                        <span>· агент <span className="font-mono text-[12px]">{v.agent}</span></span>
                        <Ago ts={v.created_at} now={now} className="ml-auto text-[12px]" />
                      </div>
                      <MarkdownBody className="c-well max-h-[50vh] overflow-auto p-3 text-sm leading-relaxed break-words">{v.markdown}</MarkdownBody>
                    </li>
                  ))}
                </ol>
              ) : (
                <p className="text-sm text-muted-foreground" title={triageClaim ? `сессия ${triageClaim.session_id}` : undefined}>Агент взял инцидент в разбор, но текста вердикта нет — разбор не завершился.</p>
              )}
              {triageClaim && (
                <p className="mt-3 text-[13px] text-muted-foreground">
                  Вердикт агента — подсказка, статус меняет аналитик. Повторно агент возьмёт этот инцидент только после разрешения ниже.
                </p>
              )}
              {canEdit && triageClaim && <div className="mt-3"><TriageReopenButton incidentId={inc.incident_id} /></div>}
            </Panel>
          )}

          <Panel label="Работа по инциденту" id="work" meta={inc.owner ? `ответственный: ${inc.owner}` : "без ответственного"}>
            {changes.length > 0 && (
              <FeedList label="История изменений" className="mb-5 p-1">
                <FeedDay heading={changes.length === 200 ? "История · последние 200" : "История"}>
                  {changes.map((c) => {
                    const label = closureLabelText(c);
                    return (
                      <FeedRow key={c.event_id} icon={CheckCheck}
                        title={<><span className="font-semibold">{c.kind === "auto_close" || c.actor === "argus" ? "ARGUS" : c.actor}</span> <span className="font-normal text-[var(--fg-2)]">{changeVerb(c.kind, c.status)}{c.kind === "assign" && c.owner ? ` ${c.owner}` : ""}</span></>}
                        meta={[INCIDENT_STATUSES[c.status] ?? c.status, label, c.reason && `«${c.reason}»`]}
                        time={<Ago ts={c.changed_at} now={now} />} />
                    );
                  })}
                </FeedDay>
              </FeedList>
            )}
            {canEdit ? <IncidentStatusForm
              incidentId={inc.incident_id}
              status={inc.status}
              ops={isOpsIncident(inc.tags)}
              attack={attackFormOptions(inc.tags)}
              owner={inc.owner}
              currentUser={session.user}
              isAdmin={session.role === "admin"}
              users={users.map((u) => ({ name: u.name, role: u.role }))}
              blind={blind}
              takeInHeader={action === "take"}
              exceptions={[
                inc.actor_name ? { field: "actor.name", value: inc.actor_name, label: "субъект" } : null,
                inc.node ? { field: "node", value: inc.node, label: "узел" } : null,
              ].filter((x): x is { field: string; value: string; label: string } => x !== null)}
            /> : <p className="text-sm text-muted-foreground">Менять статус и ответственного может аналитик.</p>}
          </Panel>

          {canEdit && (blockable.length > 0 || activeBlocks.length > 0) && (
            <Panel label="Блокировка адреса" meta={respondMode}>
              <div className="space-y-2">
                {blockable.filter((ip) => !activeIps.has(ip)).map((ip) => <BlockIpButton key={ip} incidentId={inc.incident_id} ip={ip} />)}
                {activeBlocks.length > 0 && (
                  <div className="mt-3 border-t border-border pt-3">
                    <div className="c-label mb-2">Активные блокировки</div>
                    <ul className="space-y-1.5">
                      {activeBlocks.map((b) => (
                        <li key={`${b.ip}|${b.incident}`} className="flex flex-wrap items-center gap-x-3 gap-y-1 text-[13px]">
                          <Led color="var(--status-err)" />
                          <span className="min-w-0 break-all font-mono text-[12px]"><Copyable value={b.ip} href={searchHref.srcip(b.ip)} label="IP" /></span>
                          <span className="text-muted-foreground">{!b.until || b.until.startsWith("0001-") ? "бессрочно" : `до ${formatWhen(b.until, now)} UTC`}{b.manual ? " · вручную" : ""}{b.executors?.length ? ` · ${b.executors.join(", ")}` : ""}</span>
                          <UnblockIpButton ip={b.ip} incidentId={inc.incident_id} action={unblockIpAction} />
                        </li>
                      ))}
                    </ul>
                  </div>
                )}
                {respond?.error && <p className="text-[13px] text-[var(--status-warn)]">Движок реагирования недоступен — блокировка сейчас не сработает.</p>}
              </div>
            </Panel>
          )}

          {responses.length > 0 && (
            <Panel label="Реагирование" meta={`${fmtNum(responses.length)} ${plural(responses.length, ["запись", "записи", "записей"])}`}>
              <ResponseLog rows={responses} compact />
            </Panel>
          )}

          {(inc.enrichment?.length ?? 0) > 0 && (
            <Panel label="Контекст из внешних систем" meta={`${fmtNum(inc.enrichment.length)} ${plural(inc.enrichment.length, ["строка", "строки", "строк"])}`}>
              <pre className="c-well overflow-x-auto p-4 font-mono text-[12px] leading-[1.75] whitespace-pre-wrap [overflow-wrap:anywhere]">
{inc.enrichment.join("\n")}
              </pre>
            </Panel>
          )}

          {similar.length > 0 && (
            <Panel label="Похожие закрытые инциденты" meta="за 90 дней">
              <FeedList className="p-1">
                <ul className="divide-y divide-border/70">
                  {similar.map((s) => (
                    <FeedRow key={s.id} href={`/incidents/${s.id}`} title={s.title || s.id}
                      meta={[<span key="id" className="font-mono text-[12px]">{s.id}</span>, s.status && (INCIDENT_STATUSES[s.status as keyof typeof INCIDENT_STATUSES] ?? s.status), s.note]}
                      time={s.date} />
                  ))}
                </ul>
              </FeedList>
            </Panel>
          )}
        </div>

        <IncidentWiki id={inc.incident_id} markdown={markdown} canEdit={canEdit} blind={blind} />
      </div>
    </IncidentActionBoundary>
  );
}

function Fact({ label, children }: { label: string; children: React.ReactNode }) {
  return (
    <div className="min-w-0">
      <dt className="c-label">{label}</dt>
      <dd className="mt-1 min-w-0 break-words text-[15px] text-foreground">{children}</dd>
    </div>
  );
}
