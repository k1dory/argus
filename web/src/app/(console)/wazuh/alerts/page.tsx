import type { Metadata } from "next";
import Link from "next/link";
import { Bell, BellOff } from "lucide-react";
import { ActionForm } from "@/components/console/action-form";
import { AlertsFilters } from "@/components/console/alerts-filters";
import { Copyable } from "@/components/console/copyable";
import { searchHref } from "@/lib/shared/search-href";
import { Pager, SortLink } from "@/components/console/pager";
import { PageHeader, Panel } from "@/components/console/panel";
import { RangePicker } from "@/components/console/range-picker";
import { SeverityBadge } from "@/components/console/severity-badge";
import { StorageUnavailable } from "@/components/console/storage-error";
import { Button } from "@/components/ui/button";
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

export const dynamic = "force-dynamic";
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

  // Ключ фильтров — строка параметров: при навигации controlled-форма пересоздаётся с новыми значениями.
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

      {!r.ok ? (
        <StorageUnavailable reason={r.error} />
      ) : (
        <AlertsTable
          list={r.data[0]}
          agents={r.data[1]}
          muted={r.data[2]}
          canEdit={canEdit}
          showMuted={showMuted}
          sort={sort}
          dir={dir}
          href={href}
          filtersKey={qs.toString()}
          filtersText={describeChips(alertRangeChips(ranges))}
        />
      )}
    </>
  );
}

function AlertsTable({
  list,
  agents,
  muted,
  canEdit,
  showMuted,
  sort,
  dir,
  href,
  filtersKey,
  filtersText,
}: {
  list: Awaited<ReturnType<typeof alertsList>>;
  agents: string[];
  muted: number[];
  canEdit: boolean;
  showMuted: boolean;
  sort: string;
  dir: "asc" | "desc";
  href: (patch: Record<string, string | undefined>) => string;
  filtersKey: string;
  filtersText: string;
}) {
  const mutedSet = new Set(muted);
  const sortHref = (s: string, d: "asc" | "desc") => href({ sort: s === "ts" && d === "desc" ? undefined : s, dir: s === "ts" && d === "desc" ? undefined : d, page: undefined });
  return (
    <Panel
      label={`Журнал · ${fmtNum(list.total)} записей`}
      meta={muted.length > 0 ? `заглушено правил: ${fmtNum(muted.length)} · по ${ALERTS_PAGE_SIZE} на странице` : `по ${ALERTS_PAGE_SIZE} на странице`}
    >
      <div className="mb-5 flex flex-wrap items-end gap-3">
        <AlertsFilters key={filtersKey} agents={agents} />
        <RangeFilters time fields={[ALERT_LEVEL_FIELD]} legacy={["level"]} idPrefix="alerts" />
        {muted.length > 0 && (
          <Button asChild variant="secondary" size="sm" className="mb-2">
            <Link href={href({ muted: showMuted ? undefined : "1", page: undefined })}>
              {showMuted ? "Скрыть заглушённые" : `Показать заглушённые (${fmtNum(muted.length)})`}
            </Link>
          </Button>
        )}
      </div>
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
              <TableHead className="c-label">Источник</TableHead>
              {canEdit && <TableHead className="c-label text-right">Шум</TableHead>}
            </TableRow>
          </TableHeader>
          <TableBody>
            {list.rows.length === 0 && (
              <TableRow>
                <TableCell colSpan={canEdit ? 6 : 5} className="py-8 text-center font-mono text-muted-foreground">
                  Ничего не найдено{filtersText ? ` (${filtersText})` : ""} — измените фильтры или диапазон
                </TableCell>
              </TableRow>
            )}
            {list.rows.map((r, i) => {
              const isMuted = mutedSet.has(r.rule_id);
              return (
                <TableRow
                  key={`${r.timestamp}|${r.rule_id}|${r.agent_name}|${r.srcip}|${i}`}
                  className={isMuted ? "border-border/40 opacity-50" : "border-border/40"}
                >
                  <TableCell className="font-mono text-xs whitespace-nowrap">
                    {formatTs(r.timestamp)}
                  </TableCell>
                  <TableCell>
                    <SeverityBadge level={r.rule_level} />
                  </TableCell>
                  <TableCell className="max-w-md whitespace-normal">
                    <Copyable value={String(r.rule_id)} href={searchHref.rule(r.rule_id)} label="Правило" className="text-xs">#{r.rule_id}</Copyable>{" "}
                    {r.rule_description}
                  </TableCell>
                  <TableCell className="font-mono text-xs">
                    {r.agent_name ? <Copyable value={r.agent_name} href="/wazuh/agents" label="Агент" /> : "—"}
                  </TableCell>
                  <TableCell className="font-mono text-xs">
                    {r.srcip ? <Copyable value={r.srcip} href={searchHref.srcip(r.srcip)} label="IP" /> : r.location || "—"}
                  </TableCell>
                  {canEdit && (
                    <TableCell className="text-right">
                      <ActionForm
                        action={muteRuleAction}
                        successText={isMuted ? `Правило #${r.rule_id} включено обратно` : `Правило #${r.rule_id} заглушено во всех витринах`}
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
                              : `Заглушить правило #${r.rule_id} во всех витринах`
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
      <Pager page={list.page} pages={list.pages} total={list.total} pageSize={list.pageSize} href={(p) => href({ page: p > 1 ? String(p) : undefined })} capped={list.total > ALERTS_MAX_PAGE * ALERTS_PAGE_SIZE} />
    </Panel>
  );
}
