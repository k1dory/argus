import type { Metadata } from "next";
import Link from "next/link";
import { Scale } from "lucide-react";
import { Empty, PageHeader, Panel, StatTile } from "@/components/console/panel";
import { LevelBadge } from "@/components/console/incident-badges";
import { StorageUnavailable } from "@/components/console/storage-error";
import { ServiceUnavailable } from "@/components/console/service-unavailable";
import { Button } from "@/components/ui/button";
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
import { engineRules, rulesFalsePositives, type EngineRule } from "@/lib/argus-queries";
import { fmtNum, formatAgo, formatTs, toDate } from "@/lib/shared/time";
import { RangeFilters } from "@/components/console/range-filters";
import { describeChips, inOrdinal, INCIDENT_LEVELS, inRange } from "@/lib/shared/filters";
import { parseRuleRanges, RULE_RANGE_FIELDS, ruleRangeChips } from "@/lib/shared/page-filters";
import { attackTechnique } from "@/lib/shared/attack";
import { fpShare, isNoisy, NOISY_MIN_N, sortByNoise } from "@/lib/shared/rules-noise";
import { cn } from "@/lib/utils";

export const dynamic = "force-dynamic";
export const metadata: Metadata = { title: "Правила корреляции" };

/** Цикл движка старше этого — плитка «Последний цикл» в тоне внимания. */
const STALE_RUN_MS = 5 * 60_000;

const techniques = (tags: string[]) => tags.filter((t) => t.startsWith("attack.t")).map((t) => t.replace("attack.", "").toUpperCase());

export default async function RulesPage({ searchParams }: PageProps<"/rules">) {
  const session = await requirePageSession();
  // Правила приходят с движка целиком (HTTP без фильтров) — пороги применяются здесь, в памяти.
  // Окна времени у списка нет: правило не событие, статистика ложных — всегда за 30 дней.
  const ranges = parseRuleRanges(await searchParams);
  const filtersText = describeChips(ruleRangeChips(ranges));
  // Правила — с движка (HTTP), статистика ложных — из ClickHouse: падение одного не гасит другое.
  const [engine, fpRes] = await Promise.all([engineRules(), safeQuery(() => rulesFalsePositives())]);
  const { health, error } = engine;
  const fp = fpRes.data ?? {};
  const now = new Date();
  const lastRun = typeof health?.last_run === "string" ? health.last_run : null;
  const lastRunDate = toDate(lastRun);
  const runStale = lastRunDate ? now.getTime() - lastRunDate.getTime() > STALE_RUN_MS : true;
  // Движок не ответил — строки из статистики ClickHouse: название и уровень из последнего инцидента,
  // остальное движок знает один, там «—».
  const fromStats = Boolean(error);
  const rules: EngineRule[] = fromStats
    ? Object.values(fp).map((s) => ({ ID: s.rule_id, Title: s.title ?? "", Level: s.level ?? "", File: "", Tags: [], Threshold: false, Profile: "" }))
    : engine.rules;
  const fpPct = (id: string): number => 100 * fpShare(fp[id]);
  const shown = sortByNoise(
    rules.filter((r) => inOrdinal(r.Level, ranges.level, INCIDENT_LEVELS) && inRange(fp[r.ID]?.total ?? 0, ranges.incidents) && inRange(fpPct(r.ID), ranges.fp)),
    (r) => r.ID,
    fp,
  );
  const showProfile = !fromStats && rules.some((r) => r.Profile);
  const noisy = shown.filter((r) => isNoisy(fp[r.ID])).length;

  return (
    <>
      <PageHeader
        title="Правила корреляции"
        subtitle={<>Правила редактируются в git (<span className="font-mono text-[14px]">rules/*.yml</span>) и проходят тесты перед выкаткой; здесь — просмотр и статистика срабатываний.</>}
        actions={ROLE_RANK[session.role] >= ROLE_RANK.analyst ? (
          <Button asChild variant="secondary" size="sm">
            <Link href="/rules/agreement"><Scale strokeWidth={1.5} />Согласие с агентом</Link>
          </Button>
        ) : undefined}
      />

      {error ? (
        <ServiceUnavailable
          service="engine"
          reason={error}
          what="список правил"
          consequence={fpRes.ok
            ? "Новые инциденты сейчас не создаются. Ниже — правила, по которым были инциденты за 30 дней, со статистикой ложных; уровень порога и файлы покажутся, когда движок ответит."
            : undefined}
        />
      ) : (
        <div className="grid grid-cols-2 gap-6 lg:grid-cols-4">
          <StatTile label="Правил загружено" value={fmtNum(rules.length)} />
          <StatTile label="С порогом" value={fmtNum(rules.filter((r) => r.Threshold).length)} sub="срабатывают по числу событий в окне" />
          <StatTile label="Инцидентов создано" value={fmtNum(Number(health?.incidents_created ?? 0))} sub="с последнего запуска движка" />
          <StatTile
            label="Последний цикл"
            size="sm"
            value={lastRun ? formatAgo(lastRun, now) : "—"}
            sub={lastRun ? formatTs(lastRun) : "движок ещё не сообщил о цикле"}
            tone={!health ? "err" : runStale ? "warn" : "ok"}
          />
        </div>
      )}

      {fpRes.error && <StorageUnavailable reason={fpRes.error} label="Статистика ложных недоступна" what="статистику ложных срабатываний" />}

      {!(error && !fpRes.ok) && (
        <Panel
          label={fromStats ? "Правила с инцидентами за 30 дней" : "Загруженные правила"}
          meta={[
            shown.length === rules.length ? `${fmtNum(rules.length)} шт.` : `${fmtNum(shown.length)} из ${fmtNum(rules.length)}`,
            noisy > 0 ? `шумных ${fmtNum(noisy)}` : null,
            "сначала шумные",
          ].filter(Boolean).join(" · ")}
        >
          <div className="mb-4"><RangeFilters fields={RULE_RANGE_FIELDS} idPrefix="rules" /></div>
          {rules.length === 0 ? (
            fromStats
              ? <Empty title="За 30 дней инцидентов не было" hint="Список правил покажется, когда движок корреляции ответит." />
              : <Empty title="Движок не загрузил ни одного правила" hint="Правила лежат в каталоге rules/ репозитория; после выкатки они появятся здесь." />
          ) : shown.length === 0 ? (
            <Empty title="Нет правил по фильтрам" hint={`${filtersText} — ослабьте пороги.`} />
          ) : (
            <div className="c-well overflow-x-auto p-2">
              <Table>
                <TableHeader>
                  <TableRow className="border-border/60">
                    <TableHead className="c-label">Правило</TableHead>
                    <TableHead className="c-label">Уровень</TableHead>
                    <TableHead className="c-label">ATT&amp;CK</TableHead>
                    <TableHead className="c-label">Порог</TableHead>
                    {showProfile && <TableHead className="c-label">Профиль аналитика</TableHead>}
                    <TableHead className="c-label text-right">Инцидентов, 30 дн.</TableHead>
                    <TableHead className="c-label text-right">Ложных</TableHead>
                  </TableRow>
                </TableHeader>
                <TableBody>
                  {shown.map((r) => {
                    const s = fp[r.ID];
                    const hot = isNoisy(s);
                    const tech = techniques(r.Tags);
                    return (
                      <TableRow key={r.ID} className="border-border/40" title={r.File ? `файл: ${r.File}` : undefined}>
                        <TableCell className="min-w-[16rem] whitespace-normal">
                          <span className="block text-sm text-foreground">{r.Title || r.ID}</span>
                          <span className="font-mono text-[12px] text-muted-foreground">{r.ID}</span>
                        </TableCell>
                        <TableCell>{r.Level ? <LevelBadge level={r.Level} /> : <span className="text-muted-foreground">—</span>}</TableCell>
                        <TableCell className="font-mono text-xs">
                          {fromStats ? <span className="text-muted-foreground">—</span> : tech.length === 0 ? <span className="text-muted-foreground">нет</span> : (
                            <span className="flex flex-wrap gap-x-2">
                              {tech.map((t) => <abbr key={t} title={attackTechnique(t)?.name ?? t} className="no-underline">{t}</abbr>)}
                            </span>
                          )}
                        </TableCell>
                        <TableCell className="text-[13px] text-muted-foreground whitespace-nowrap">{fromStats ? "—" : r.Threshold ? "окно" : "по событию"}</TableCell>
                        {showProfile && <TableCell className="text-[13px]">{r.Profile || <span className="text-muted-foreground">по умолчанию</span>}</TableCell>}
                        <TableCell className="text-right font-mono text-sm tabular-nums">
                          {fpRes.error ? <span className="text-muted-foreground">—</span> : s?.total ? (
                            <Link href={`/incidents?q=${encodeURIComponent(r.ID)}`} className="text-[var(--ring)] hover:underline" title="Инциденты этого правила">{fmtNum(s.total)}</Link>
                          ) : <span className="text-muted-foreground">0</span>}
                        </TableCell>
                        <TableCell className="text-right font-mono text-sm tabular-nums whitespace-nowrap">
                          {s?.total ? (
                            <span title={hot ? `не меньше половины при ${NOISY_MIN_N}+ инцидентах — кандидат на тюнинг` : undefined}>
                              <span className={cn(hot && "font-medium text-[var(--status-warn)]", !hot && s.false_positive === 0 && "text-muted-foreground")}>{Math.round(fpPct(r.ID))} %</span>
                              <span className="text-muted-foreground"> · {fmtNum(s.false_positive)}</span>
                            </span>
                          ) : <span className="text-muted-foreground">—</span>}
                        </TableCell>
                      </TableRow>
                    );
                  })}
                </TableBody>
              </Table>
              <p className="px-2 pt-3 text-[12px] text-muted-foreground">
                Жёлтым — правила, где ложных не меньше половины при {NOISY_MIN_N} и более инцидентах. Число инцидентов ведёт к их списку.
              </p>
            </div>
          )}
        </Panel>
      )}
    </>
  );
}
