import type { Metadata } from "next";
import { TacticsChart } from "@/components/console/charts";
import { Empty, PageHeader, Panel } from "@/components/console/panel";
import { RangePicker } from "@/components/console/range-picker";
import { StorageUnavailable } from "@/components/console/storage-error";
import {
  Table,
  TableBody,
  TableCell,
  TableHead,
  TableHeader,
  TableRow,
} from "@/components/ui/table";
import { safeQuery } from "@/lib/clickhouse";
import { topTactics, topTechniques } from "@/lib/queries";
import { fmtNum } from "@/lib/shared/time";
import { requirePageSession } from "@/lib/auth";
import { RangeFilters } from "@/components/console/range-filters";
import { describeChips } from "@/lib/shared/filters";
import { ALERT_LEVEL_FIELD, alertRangeChips, parseAlertRanges } from "@/lib/shared/page-filters";

export const dynamic = "force-dynamic";
export const metadata: Metadata = { title: "MITRE ATT&CK" };

export default async function MitrePage({ searchParams }: PageProps<"/wazuh/mitre">) {
  await requirePageSession();
  const sp = await searchParams;
  // Окно (пресет или from/to) и уровень правила: техники считаются только по алертам в пороге.
  const ranges = parseAlertRanges(sp);
  // Активный пресет — из того же разобранного окна, что уходит в SQL (range или синоним period).
  const range = ranges.time.range ?? "24h";
  const filtersText = describeChips(alertRangeChips(ranges));
  const r = await safeQuery(() => Promise.all([topTactics(ranges.time, 14, ranges.level), topTechniques(ranges.time, 20, ranges.level)]));

  return (
    <>
      <PageHeader title="MITRE ATT&CK">
        <RangePicker value={range} />
      </PageHeader>
      <RangeFilters time fields={[ALERT_LEVEL_FIELD]} idPrefix="mitre" />
      {!r.ok ? <StorageUnavailable reason={r.error} /> : <MitreBody tactics={r.data[0]} techniques={r.data[1]} empty={filtersText ? `Нет данных по фильтрам: ${filtersText}` : "Нет данных за период"} />}
    </>
  );
}

function MitreBody({ tactics, techniques, empty }: { tactics: Awaited<ReturnType<typeof topTactics>>; techniques: Awaited<ReturnType<typeof topTechniques>>; empty: string }) {
  const maxCount = techniques[0]?.count ?? 0;
  return (
    <>
      <Panel label="Тактики · покрытие алертами">
        {tactics.length > 0 ? <TacticsChart tactics={tactics} /> : <Empty>{empty}</Empty>}
      </Panel>

      <Panel label={`Техники · топ ${fmtNum(techniques.length)}`} meta="attack.mitre.org">
        {techniques.length === 0 ? (
          <Empty>{empty}</Empty>
        ) : (
          <div className="c-well overflow-x-auto p-2">
            <Table>
              <TableHeader>
                <TableRow className="border-border/60">
                  <TableHead className="c-label">ID</TableHead>
                  <TableHead className="c-label">Техника</TableHead>
                  <TableHead className="c-label text-right">Алертов</TableHead>
                  <TableHead className="c-label w-48">Доля</TableHead>
                </TableRow>
              </TableHeader>
              <TableBody>
                {techniques.map((t) => {
                  const pct = Math.round((100 * t.count) / (maxCount || 1));
                  return (
                    <TableRow key={`${t.id}|${t.technique}`} className="border-border/40">
                      <TableCell className="font-mono text-xs">
                        <a
                          href={`https://attack.mitre.org/techniques/${t.id.replace(".", "/")}/`}
                          target="_blank"
                          rel="noreferrer"
                          className="text-[var(--ring)] hover:underline"
                        >
                          {t.id}
                        </a>
                      </TableCell>
                      <TableCell className="text-sm whitespace-normal">{t.technique || "—"}</TableCell>
                      <TableCell className="text-right font-mono text-xs">{fmtNum(t.count)}</TableCell>
                      <TableCell>
                        {/* Величина — hairline-линейка в ch-треке, ширина от данных */}
                        <span
                          role="img"
                          aria-label={`${pct} % от максимума`}
                          className="inline-block h-px w-full max-w-44 align-middle"
                        >
                          <span
                            className="block h-px bg-[var(--ring)]"
                            style={{ width: `${Math.max(4, pct)}%` }}
                          />
                        </span>
                      </TableCell>
                    </TableRow>
                  );
                })}
              </TableBody>
            </Table>
          </div>
        )}
      </Panel>
    </>
  );
}
