import type { Metadata } from "next";
import Link from "next/link";
import { Copyable } from "@/components/console/copyable";
import { Ago } from "@/components/console/ago";
import { Empty, PageHeader, Panel, StatTile } from "@/components/console/panel";
import { SortLink } from "@/components/console/pager";
import { RangePicker } from "@/components/console/range-picker";
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
import { safeQuery } from "@/lib/clickhouse";
import { agentsSummary } from "@/lib/queries";
import { listAgents, type WzAgent } from "@/lib/wazuh-api";
import { fmtNum } from "@/lib/shared/time";
import { requirePageSession } from "@/lib/auth";
import { RangeFilters } from "@/components/console/range-filters";
import { describeChips } from "@/lib/shared/filters";
import { AGENT_RANGE_FIELDS, agentRangeChips, parseAgentRanges } from "@/lib/shared/page-filters";
import { mergeAgents, parseAgentSort, sortAgents, type AgentRow, type AgentSort } from "../_shared/agents";
import { wazuhAgentHref } from "../_shared/links";
import { AgentStatusBadge } from "../_shared/status-badge";

export const dynamic = "force-dynamic";
export const metadata: Metadata = { title: "Агенты Wazuh" };

/** Связь давнее 10 минут — внимание; последний алерт давнее суток — тоже. */
const KEEPALIVE_STALE_MS = 10 * 60_000;
const ALERT_STALE_MS = 24 * 3600_000;
/** Список агентов из API — дополнение к сводке: долго его не ждём. */
const API_WAIT_MS = 5_000;

async function agentsFromApi(): Promise<WzAgent[] | null> {
  let timer: ReturnType<typeof setTimeout> | undefined;
  try {
    return await Promise.race([
      listAgents(),
      new Promise<never>((_, reject) => {
        timer = setTimeout(() => reject(new Error("Wazuh API: нет ответа за 5 с")), API_WAIT_MS);
      }),
    ]);
  } catch (err) {
    console.error("wazuh/agents:", err instanceof Error ? err.message : err);
    return null;
  } finally {
    clearTimeout(timer);
  }
}

export default async function AgentsPage({ searchParams }: PageProps<"/wazuh/agents">) {
  await requirePageSession();
  const sp = await searchParams;
  // Окно и уровень — какие алерты считаются; алертов/критичных — пороги итогов по агенту.
  const ranges = parseAgentRanges(sp);
  // Активный пресет — из того же разобранного окна, что уходит в SQL (range или синоним period).
  const range = ranges.time.range ?? "24h";
  const filtersText = describeChips(agentRangeChips(ranges));
  const sort = parseAgentSort(sp.sort);
  const dir: "asc" | "desc" = sp.dir === "asc" ? "asc" : "desc";
  const [r, api] = await Promise.all([
    safeQuery(() => agentsSummary(ranges.time, { level: ranges.level, alerts: ranges.alerts, critical: ranges.critical })),
    agentsFromApi(),
  ]);
  const now = new Date();

  const qs = new URLSearchParams();
  for (const [k, v] of Object.entries(sp)) if (typeof v === "string" && v) qs.set(k, v);
  const sortHref = (s: string, d: "asc" | "desc") => {
    const next = new URLSearchParams(qs);
    if (s === "status") {
      next.delete("sort");
      next.delete("dir");
    } else {
      next.set("sort", s);
      next.set("dir", d);
    }
    const q = next.toString();
    return q ? `/wazuh/agents?${q}` : "/wazuh/agents";
  };

  return (
    <>
      <PageHeader title="Агенты Wazuh">
        <div className="flex flex-wrap items-center gap-2">
          <Button asChild variant="ghost" size="sm">
            <Link href="/wazuh/manage">Управление агентами →</Link>
          </Button>
          <RangePicker value={range} />
        </div>
      </PageHeader>

      <Panel label="Фильтры" meta="время в UTC">
        <RangeFilters time fields={AGENT_RANGE_FIELDS} idPrefix="agents" />
      </Panel>

      {!r.ok ? (
        <StorageUnavailable reason={r.error} />
      ) : (
        <AgentsBody
          rows={sortAgents(mergeAgents(r.data, api, { alerts: ranges.alerts, critical: ranges.critical }), sort, dir)}
          apiOk={api !== null}
          filtersText={filtersText}
          sort={sort}
          dir={dir}
          sortHref={sortHref}
          now={now}
        />
      )}
    </>
  );
}

function AgentsBody({
  rows,
  apiOk,
  filtersText,
  sort,
  dir,
  sortHref,
  now,
}: {
  rows: AgentRow[];
  apiOk: boolean;
  filtersText: string;
  sort: AgentSort;
  dir: "asc" | "desc";
  sortHref: (s: string, d: "asc" | "desc") => string;
  now: Date;
}) {
  const offline = rows.filter((a) => a.status === "disconnected" || a.status === "never_connected").length;
  const withCritical = rows.filter((a) => a.critical > 0).length;
  const ariaSort = (f: AgentSort) => (sort === f ? (dir === "asc" ? "ascending" : "descending") : "none");
  return (
    <>
      <div className="grid grid-cols-2 gap-6 md:grid-cols-3">
        <StatTile label="Агентов" value={fmtNum(rows.length)} sub={apiOk ? "зарегистрированные и с алертами" : "только с алертами за период"} />
        <StatTile
          label="Не на связи"
          value={apiOk ? fmtNum(offline) : "—"}
          tone={!apiOk ? "muted" : offline > 0 ? "err" : "ok"}
          sub={apiOk ? "отключены или ни разу не подключались" : "статус подключения неизвестен"}
        />
        <StatTile label="С критичными алертами" value={fmtNum(withCritical)} tone={withCritical > 0 ? "err" : undefined} />
      </div>

      <Panel label={`Агенты · ${fmtNum(rows.length)}`} meta="активность — по алертам за период">
        {!apiOk && (
          <p role="status" className="mb-4 rounded-md border border-[var(--status-warn)]/40 bg-[var(--status-warn)]/10 px-3 py-2 text-[13px] text-foreground">
            Статус подключения неизвестен: менеджер Wazuh не ответил. Показаны только агенты, от которых были алерты за период, —
            замолчавших и отключённых здесь сейчас не видно.
          </p>
        )}
        {rows.length === 0 ? (
          filtersText ? (
            <Empty title="Нет агентов по фильтрам" hint={`${filtersText}. Ослабьте пороги или расширьте интервал.`} />
          ) : (
            <Empty title="Агентов нет" hint="За период не было алертов, а менеджер не вернул ни одного зарегистрированного агента." />
          )
        ) : (
          <div className="c-well overflow-x-auto p-2">
            <Table>
              <TableHeader>
                <TableRow className="border-border/60">
                  <TableHead className="c-label">Агент</TableHead>
                  <TableHead className="c-label" aria-sort={ariaSort("status")}>
                    <SortLink label="Статус" field="status" sort={sort} dir={dir} href={sortHref} />
                  </TableHead>
                  <TableHead className="c-label">Связь</TableHead>
                  <TableHead className="c-label text-right" aria-sort={ariaSort("alerts")}>
                    <SortLink label="Алертов" field="alerts" sort={sort} dir={dir} href={sortHref} />
                  </TableHead>
                  <TableHead className="c-label text-right" aria-sort={ariaSort("critical")}>
                    <SortLink label="Критичных" field="critical" sort={sort} dir={dir} href={sortHref} />
                  </TableHead>
                  <TableHead className="c-label text-right">Правил</TableHead>
                  <TableHead className="c-label" aria-sort={ariaSort("last")}>
                    <SortLink label="Последний алерт" field="last" sort={sort} dir={dir} href={sortHref} />
                  </TableHead>
                </TableRow>
              </TableHeader>
              <TableBody>
                {rows.map((a) => (
                  <TableRow key={a.name} className="border-border/40">
                    <TableCell>
                      <Copyable value={a.name} href={wazuhAgentHref(a.name)} label="Агент" className="font-medium" />
                      {(a.id || a.ip) && (
                        <div className="font-mono text-xs text-muted-foreground">{[a.id, a.ip].filter(Boolean).join(" · ")}</div>
                      )}
                    </TableCell>
                    <TableCell>
                      {a.status ? (
                        <AgentStatusBadge status={a.status} />
                      ) : (
                        <span className="text-xs text-muted-foreground" title={apiOk ? "Агента нет в списке менеджера" : "Менеджер Wazuh не ответил"}>
                          {apiOk ? "не зарегистрирован" : "неизвестно"}
                        </span>
                      )}
                    </TableCell>
                    <TableCell className="text-xs">
                      {a.keepalive ? <Ago ts={a.keepalive} now={now} staleAfterMs={KEEPALIVE_STALE_MS} /> : <span className="text-muted-foreground">—</span>}
                    </TableCell>
                    <TableCell className="text-right font-mono">
                      {a.alerts > 0 ? fmtNum(a.alerts) : <span className="text-muted-foreground">0</span>}
                    </TableCell>
                    <TableCell className="text-right font-mono">
                      {a.critical > 0 ? (
                        <span className="font-medium text-[var(--status-err)]">{fmtNum(a.critical)}</span>
                      ) : (
                        <span className="text-muted-foreground">0</span>
                      )}
                    </TableCell>
                    <TableCell className="text-right font-mono">{fmtNum(a.rules)}</TableCell>
                    <TableCell className="text-xs">
                      {a.lastAlert ? <Ago ts={a.lastAlert} now={now} staleAfterMs={ALERT_STALE_MS} /> : <span className="text-muted-foreground">нет за период</span>}
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
