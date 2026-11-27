import type { Metadata } from "next";
import Link from "next/link";
import { Bell, BellOff, SearchX } from "lucide-react";
import { ActionForm } from "@/components/console/action-form";
import { AlertsExtraFields } from "@/components/console/alerts-filters";
import { Copyable } from "@/components/console/copyable";
import { searchHref } from "@/lib/shared/search-href";
import { Pager, SortLink } from "@/components/console/pager";
import { Empty, PageHeader, Panel } from "@/components/console/panel";
import { RangePicker } from "@/components/console/range-picker";
import { SeverityBadge } from "@/components/console/severity-badge";
import { StorageUnavailable } from "@/components/console/storage-error";
import { Button } from "@/components/ui/button";
import { Badge } from "@/components/ui/badge";
import { TONE_CLASS } from "@/components/console/tone";
import { SEVERITY } from "@/lib/shared/severity";
import { cn } from "@/lib/utils";
import {
  Table,
  TableBody,
  TableCell,
  TableHead,
  TableHeader,
  TableRow,
} from "@/components/ui/table";
import { muteRuleAction } from "@/lib/actions";
import { safeQuery } from "@/lib/clickhouse";
import { agentNames, alertsList, ALERTS_MAX_PAGE, ALERTS_PAGE_SIZE, mutedRuleIds, parseAlertDir, parseAlertSort } from "@/lib/queries";
import { clampPage } from "@/lib/shared/limits";
import { RangeFilters } from "@/components/console/range-filters";
import { describeChips } from "@/lib/shared/filters";
import { ALERT_LEVEL_FIELD, alertRangeChips, parseAlertRanges } from "@/lib/shared/page-filters";
import { fmtNum, formatTs } from "@/lib/shared/time";
import { requirePageSession, ROLE_RANK } from "@/lib/auth";
import { wazuhAgentHref } from "../_shared/links";

export const dynamic = "force-dynamic";

/** Поля AlertsExtraFields (описание, агент) — уходят той же формой, что уровень и интервал. */
const ALERTS_EXTRA_KEYS = ["q", "agent"];
export const metadata: Metadata = { title: "Алерты Wazuh" };

const str = (v: unknown): string | undefined => (typeof v === "string" && v ? v : undefined);

export default async function AlertsPage({ searchParams }: PageProps<"/wazuh/alerts">) {
  const session = await requirePageSession();
  const canEdit = ROLE_RANK[session.role] >= ROLE_RANK.analyst;
  const params = await searchParams;
  // Окно (пресет или точный from/to), уровень не ниже/не выше; прежний level=N — «не ниже N».
  const ranges = parseAlertRanges(params);
  // Активный пресет — из того же разобранного окна, что уходит в SQL (range или синоним period).
  const range = ranges.time.range ?? "24h";
  const showMuted = params.muted === "1";
  const sort = parseAlertSort(params.sort);
  const dir = parseAlertDir(params.dir);
  const page = Math.min(ALERTS_MAX_PAGE, clampPage(params.page));
  const filters = {
    range,
    time: ranges.time,
    minLevel: ranges.level.min,
    maxLevel: ranges.level.max,
    agent: str(params.agent)?.slice(0, 128),
    search: str(params.q)?.slice(0, 200),
    showMuted,
    page,
    sort,
    dir,
  };

  const qs = new URLSearchParams();
  for (const [k, v] of Object.entries(params)) if (typeof v === "string" && v) qs.set(k, v);
  const href = (patch: Record<string, string | undefined>) => {
    const next = new URLSearchParams(qs);
    for (const [k, v] of Object.entries(patch)) {
      if (v) next.set(k, v);
      else next.delete(k);
    }
    const s = next.toString();
    return s ? `/wazuh/alerts?${s}` : "/wazuh/alerts";
  };

  const r = await safeQuery(() => Promise.all([alertsList(filters), agentNames(ranges.time), mutedRuleIds()]));

  return (
    <>
      <PageHeader title="Алерты Wazuh">
        <RangePicker value={range} />
      </PageHeader>

      <Panel label="Фильтры" meta="время в UTC">
        <RangeFilters
          time
          fields={[ALERT_LEVEL_FIELD]}
          legacy={["level"]}
          idPrefix="alerts"
          extra={<AlertsExtraFields agents={r.ok ? r.data[1] : []} />}
          extraKeys={ALERTS_EXTRA_KEYS}
        />
      </Panel>

      {!r.ok ? (
        <StorageUnavailable reason={r.error} />
      ) : (
        <AlertsTable
          list={r.data[0]}
          muted={r.data[2]}
          canEdit={canEdit}
          showMuted={showMuted}
          sort={sort}
          dir={dir}
          href={href}
          agentHref={(name) => wazuhAgentHref(name, qs)}
          filtersText={describeChips(alertRangeChips(ranges))}
        />
      )}
    </>
  );
}

function AlertsTable({
  list,
  muted,
  canEdit,
  showMuted,
  sort,
  dir,
  href,
  agentHref,
  filtersText,
}: {
  list: Awaited<ReturnType<typeof alertsList>>;
  muted: number[];
  canEdit: boolean;
  showMuted: boolean;
  sort: string;
  dir: "asc" | "desc";
  href: (patch: Record<string, string | undefined>) => string;
  agentHref: (name: string) => string;
  filtersText: string;
}) {
  const mutedSet = new Set(muted);
  const sortHref = (s: string, d: "asc" | "desc") => href({ sort: s === "ts" && d === "desc" ? undefined : s, dir: s === "ts" && d === "desc" ? undefined : d, page: undefined });
  return (
    <Panel
      label={`Алерты · ${fmtNum(list.total)}`}
      meta={muted.length > 0 ? `заглушено правил: ${fmtNum(muted.length)} · по ${ALERTS_PAGE_SIZE} на странице` : `по ${ALERTS_PAGE_SIZE} на странице`}
      actions={
        muted.length > 0 ? (
          <Button asChild variant="ghost" size="sm">
            <Link href={href({ muted: showMuted ? undefined : "1", page: undefined })}>
              {showMuted ? "Скрыть заглушённые" : `Показать заглушённые (${fmtNum(muted.length)})`}
            </Link>
          </Button>
        ) : undefined
      }
    >
      {list.rows.length === 0 ? (
        <Empty
          icon={SearchX}
          title="Алертов не найдено"
          hint={filtersText ? `По фильтрам: ${filtersText}. Измените фильтры или расширьте период.` : "За выбранный период алертов нет. Расширьте период или снимите фильтры."}
        />
      ) : (
      <div className="c-well overflow-x-auto p-2">
        <Table>
          <TableHeader>
            <TableRow className="border-border/60">
              <TableHead className="c-label" aria-sort={sort === "ts" ? (dir === "asc" ? "ascending" : "descending") : "none"}>
                <SortLink label="Время (UTC)" field="ts" sort={sort} dir={dir} href={sortHref} />
              </TableHead>
              <TableHead className="c-label" aria-sort={sort === "level" ? (dir === "asc" ? "ascending" : "descending") : "none"}>
                <SortLink label="Уровень" field="level" sort={sort} dir={dir} href={sortHref} />
              </TableHead>
              <TableHead className="c-label">Правило</TableHead>
              <TableHead className="c-label">Агент</TableHead>
              <TableHead className="c-label">IP / журнал</TableHead>
              {canEdit && <TableHead className="c-label text-right"><span className="sr-only">Заглушить</span></TableHead>}
            </TableRow>
          </TableHeader>
          <TableBody>
            {list.rows.map((r, i) => {
              const isMuted = mutedSet.has(r.rule_id);
              const critical = r.rule_level >= SEVERITY.alerts.critical;
              return (
                <TableRow
                  key={`${r.timestamp}|${r.rule_id}|${r.agent_name}|${r.srcip}|${i}`}
                  data-critical={critical || undefined}
                  className={cn(
                    "border-border/40",
                    critical && !isMuted && "bg-[var(--status-err)]/[0.06] shadow-[inset_2px_0_0_var(--status-err)]",
                    isMuted && "text-muted-foreground",
                  )}
                >
                  <TableCell className="font-mono text-xs whitespace-nowrap">
                    {formatTs(r.timestamp)}
                  </TableCell>
                  <TableCell>
                    <SeverityBadge level={r.rule_level} />
                  </TableCell>
                  <TableCell className="max-w-md whitespace-normal">
                    <div className={cn("text-sm", isMuted ? "text-muted-foreground" : "text-foreground")}>
                      {r.rule_description || "—"}
                      {isMuted && (
                        <Badge variant="outline" className={cn("ml-2 align-middle", TONE_CLASS.muted)}>заглушено</Badge>
                      )}
                    </div>
                    <div className="text-xs text-muted-foreground">
                      <Copyable value={String(r.rule_id)} href={searchHref.rule(r.rule_id)} label="Правило">#{r.rule_id}</Copyable>
                    </div>
                  </TableCell>
                  <TableCell className="font-mono text-xs">
                    {r.agent_name ? <Copyable value={r.agent_name} href={agentHref(r.agent_name)} label="Агент" /> : "—"}
                  </TableCell>
                  <TableCell className="font-mono text-xs">
                    {r.srcip ? (
                      <Copyable value={r.srcip} href={searchHref.srcip(r.srcip)} label="IP" />
                    ) : r.location ? (
                      <span className="block max-w-56 truncate text-muted-foreground" title={r.location}>{r.location}</span>
                    ) : (
                      "—"
                    )}
                  </TableCell>
                  {canEdit && (
                    <TableCell className="text-right">
                      <ActionForm
                        action={muteRuleAction}
                        successText={isMuted ? `Правило #${r.rule_id} снова показывается` : `Правило #${r.rule_id} заглушено: его алерты скрыты в журнале, на обзоре и в дашбордах`}
                        className="inline"
                      >
                        <input type="hidden" name="rule_id" value={r.rule_id} />
                        <input type="hidden" name="muted" value={isMuted ? "0" : "1"} />
                        <Button
                          type="submit"
                          variant="ghost"
                          size="icon"
                          title={
                            isMuted
                              ? `Включить правило #${r.rule_id} обратно`
                              : `Заглушить правило #${r.rule_id}: перестанет показываться в алертах, на обзоре и в дашбордах`
                          }
                        >
                          {isMuted ? <Bell strokeWidth={1.5} /> : <BellOff strokeWidth={1.5} />}
                          <span className="sr-only">
                            {isMuted ? "Включить правило" : "Заглушить правило"}
                          </span>
                        </Button>
                      </ActionForm>
                    </TableCell>
                  )}
                </TableRow>
              );
            })}
          </TableBody>
        </Table>
      </div>
      )}
      <Pager page={list.page} pages={list.pages} total={list.total} pageSize={list.pageSize} href={(p) => href({ page: p > 1 ? String(p) : undefined })} capped={list.total > ALERTS_MAX_PAGE * ALERTS_PAGE_SIZE} />
    </Panel>
  );
}
