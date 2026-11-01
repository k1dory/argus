import type { Metadata } from "next";
import Link from "next/link";
import { Led, PageHeader, Panel, StatTile } from "@/components/console/panel";
import { LevelBadge } from "@/components/console/incident-badges";
import { StorageUnavailable } from "@/components/console/storage-error";
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
import { ROLE_RANK } from "@/lib/shared/incidents";
import { engineRules, rulesFalsePositives } from "@/lib/argus-queries";
import { fmtNum, formatAgo, formatTs } from "@/lib/shared/time";
import { RangeFilters } from "@/components/console/range-filters";
import { describeChips, inOrdinal, INCIDENT_LEVELS, inRange } from "@/lib/shared/filters";
import { parseRuleRanges, RULE_RANGE_FIELDS, ruleRangeChips } from "@/lib/shared/page-filters";

export const dynamic = "force-dynamic";
export const metadata: Metadata = { title: "Правила корреляции" };

export default async function RulesPage({ searchParams }: PageProps<"/rules">) {
  const session = await requirePageSession();
  // Правила приходят с движка целиком (HTTP без фильтров) — пороги применяются здесь, в памяти.
  // Окна времени у списка нет: правило не событие, статистика ложных — всегда за 30 дней.
  const ranges = parseRuleRanges(await searchParams);
  const filtersText = describeChips(ruleRangeChips(ranges));
  // Правила — с движка (HTTP), статистика ложных — из ClickHouse: падение одного не гасит другое.
  const [engine, fpRes] = await Promise.all([engineRules(), safeQuery(() => rulesFalsePositives())]);
  const { rules, health, error } = engine;
  const fp = fpRes.data ?? {};
  const now = new Date();
  const lastRun = typeof health?.last_run === "string" ? health.last_run : null;
  const fpPct = (id: string): number => (fp[id]?.total ? (100 * fp[id].false_positive) / fp[id].total : 0);
  const shown = rules.filter((r) => inOrdinal(r.Level, ranges.level, INCIDENT_LEVELS) && inRange(fp[r.ID]?.total ?? 0, ranges.incidents) && inRange(fpPct(r.ID), ranges.fp));

  return (
    <>
      <PageHeader title="Правила корреляции">
        <span className="flex items-center gap-4">
          <span className="c-label">rules/*.yml в git · ни одного правила через веб-форму</span>
          {ROLE_RANK[session.role] >= ROLE_RANK.analyst && (
            <Link href="/rules/agreement" className="text-sm text-[var(--ring)] hover:underline">Согласие с агентом</Link>
          )}
        </span>
      </PageHeader>

      {error ? (
        <Panel label="Движок · недоступен" meta="engine">
          <p className="flex items-center gap-2 text-sm text-foreground"><Led color="var(--status-err)" />Движок корреляции не ответил.</p>
          <p className="mt-2 text-sm text-muted-foreground">Проверьте ENGINE_URL и сервис engine в compose; текст ошибки — в журнале контейнера web.</p>
        </Panel>
      ) : (
        <>
          <div className="grid grid-cols-2 gap-6 md:grid-cols-4">
            <StatTile label="Правил загружено" value={fmtNum(rules.length)} />
            <StatTile label="С порогом" value={fmtNum(rules.filter((r) => r.Threshold).length)} />
            <StatTile label="Инцидентов создано" value={fmtNum(Number(health?.incidents_created ?? 0))} />
            <StatTile
              label="Последний цикл"
              value={lastRun ? formatTs(lastRun, "datetime") : "—"}
              hint={lastRun ? `${formatTs(lastRun)} · ${formatAgo(lastRun, now)}` : "движок ещё не сообщил о цикле"}
              led={health ? "var(--status-ok)" : "var(--status-err)"}
            />
          </div>

          {fpRes.error && <StorageUnavailable reason={fpRes.error} label="Статистика ложных недоступна" />}

          <Panel label={shown.length === rules.length ? "Загруженные правила" : `Загруженные правила · ${fmtNum(shown.length)} из ${fmtNum(rules.length)}`} meta="argus rules test — прогон на записанном трафике">
            <div className="mb-4"><RangeFilters fields={RULE_RANGE_FIELDS} idPrefix="rules" /></div>
            <div className="c-well overflow-x-auto p-2">
              <Table>
                <TableHeader>
                  <TableRow className="border-border/60">
                    <TableHead className="c-label">ID</TableHead>
                    <TableHead className="c-label">Правило</TableHead>
                    <TableHead className="c-label">Уровень</TableHead>
                    <TableHead className="c-label">ATT&amp;CK</TableHead>
                    <TableHead className="c-label">Порог</TableHead>
                    <TableHead className="c-label">Профиль аналитика</TableHead>
                    <TableHead className="c-label text-right">Инц. / ложных, 30 д</TableHead>
                    <TableHead className="c-label">Файл</TableHead>
                  </TableRow>
                </TableHeader>
                <TableBody>
                  {rules.length === 0 && (
                    <TableRow><TableCell colSpan={8} className="py-8 text-center font-mono text-muted-foreground">Движок не загрузил ни одного правила — проверьте каталог rules/.</TableCell></TableRow>
                  )}
                  {rules.length > 0 && shown.length === 0 && (
                    <TableRow><TableCell colSpan={8} className="py-8 text-center font-mono text-muted-foreground">Нет правил по фильтрам: {filtersText} — ослабьте пороги.</TableCell></TableRow>
                  )}
                  {shown.map((r) => (
                    <TableRow key={r.ID} className="border-border/40">
                      <TableCell className="font-mono text-xs">{r.ID}</TableCell>
                      <TableCell className="text-sm whitespace-normal">{r.Title}</TableCell>
                      <TableCell><LevelBadge level={r.Level} /></TableCell>
                      <TableCell className="font-mono text-xs">{r.Tags.filter((t) => t.startsWith("attack.t")).map((t) => t.replace("attack.", "").toUpperCase()).join(", ") || "—"}</TableCell>
                      <TableCell className="font-mono text-xs">{r.Threshold ? <span className="flex items-center gap-2"><Led color="var(--ring)" />окно</span> : "по событию"}</TableCell>
                      <TableCell className="font-mono text-xs">{r.Profile || "по умолчанию"}</TableCell>
                      <TableCell className="text-right font-mono text-xs">
                        {fp[r.ID] ? (
                          <>
                            {fmtNum(fp[r.ID].total)} / <span className={fp[r.ID].false_positive > 0 ? "text-[var(--status-warn)]" : ""}>{fmtNum(fp[r.ID].false_positive)}</span>
                            {fp[r.ID].total > 0 && <span className="text-muted-foreground"> · {Math.round((100 * fp[r.ID].false_positive) / fp[r.ID].total)} %</span>}
                          </>
                        ) : "—"}
                      </TableCell>
                      <TableCell className="font-mono text-xs text-muted-foreground">{r.File}</TableCell>
                    </TableRow>
                  ))}
                </TableBody>
              </Table>
            </div>
          </Panel>
        </>
      )}
    </>
  );
}
