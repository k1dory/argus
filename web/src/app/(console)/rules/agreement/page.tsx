import type { Metadata } from "next";
import Link from "next/link";
import { Empty, PageHeader, Panel, StatTile } from "@/components/console/panel";
import { StorageUnavailable } from "@/components/console/storage-error";
import { FilterTabs } from "@/components/console/filter-tabs";
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from "@/components/ui/table";
import { safeQuery } from "@/lib/clickhouse";
import { agreementMetrics, requireAgreementAccess } from "@/lib/blind-metrics";
import { AGREEMENT_WINDOWS, LOW_DATA_N, parseAgreementWindow, type AgreementRule, type AgreementWindow, type Share } from "@/lib/shared/blind-metrics";
import { splitForTuning } from "@/lib/shared/agreement-view";
import { fmtNum } from "@/lib/shared/time";
import { cn } from "@/lib/utils";

export const dynamic = "force-dynamic";
export const metadata: Metadata = { title: "Согласие с агентом" };

const pct = (x: number) => `${Math.round(x * 100)} %`;
const lowData = (s: Share) => (s.low_data ? "мало данных" : undefined);
const ofN = (s: Share) => `${fmtNum(s.k)} из ${fmtNum(s.n)}`;
const range = (s: Share) => (s.ci ? `с вероятностью 95 % настоящая доля — от ${pct(s.ci.low)} до ${pct(s.ci.high)}` : undefined);

/** Ячейка доли: одна строка «50 % 1 из 2»; интервал — в подсказке; при малой выборке — приглушённо. */
function ShareCell({ s, warnAt }: { s: Share; warnAt?: number }) {
  if (s.n === 0) return <span className="text-muted-foreground">—</span>;
  const hot = warnAt !== undefined && !s.low_data && (s.share ?? 0) >= warnAt;
  return (
    <span className="whitespace-nowrap" title={range(s)}>
      <span className={cn("font-mono tabular-nums", s.low_data ? "text-muted-foreground" : hot ? "font-medium text-[var(--status-warn)]" : "text-foreground")}>{pct(s.share ?? 0)}</span>
      <span className="ml-2 text-[12px] text-muted-foreground">{ofN(s)}</span>
    </span>
  );
}

function RulesTable({ rows }: { rows: AgreementRule[] }) {
  return (
    <div className="c-well overflow-x-auto p-2">
      <Table>
        <TableHeader>
          <TableRow className="border-border/60">
            <TableHead className="c-label">Правило</TableHead>
            <TableHead className="c-label text-right">Ответов</TableHead>
            <TableHead className="c-label">Ложных</TableHead>
            <TableHead className="c-label">Совпало (вслепую)</TableHead>
            <TableHead className="c-label">Совпало (видели подсказку)</TableHead>
            <TableHead className="c-label text-right">Агент не решил</TableHead>
          </TableRow>
        </TableHeader>
        <TableBody>
          {rows.map((r) => (
            <TableRow key={r.rule_id} className="border-border/40">
              <TableCell className="min-w-[14rem] whitespace-normal">
                <Link href={`/incidents?q=${encodeURIComponent(r.rule_id)}`} className="block text-sm text-foreground hover:text-[var(--ring)] hover:underline" title="Инциденты этого правила">
                  {r.rule_title || r.rule_id}
                </Link>
                <span className="font-mono text-[12px] text-muted-foreground">{r.rule_id}</span>
              </TableCell>
              <TableCell className="text-right font-mono text-sm tabular-nums">{fmtNum(r.labeled)}</TableCell>
              <TableCell className="text-sm"><ShareCell s={r.false_positive} warnAt={0.5} /></TableCell>
              <TableCell className="text-sm"><ShareCell s={r.blind.agreement} /></TableCell>
              <TableCell className="text-sm"><ShareCell s={r.sighted.agreement} /></TableCell>
              <TableCell className="text-right font-mono text-sm tabular-nums">
                {fmtNum(r.blind.undetermined + r.blind.no_verdict + r.sighted.undetermined + r.sighted.no_verdict)}
              </TableCell>
            </TableRow>
          ))}
        </TableBody>
      </Table>
    </div>
  );
}

const windowTabs = () =>
  (Object.keys(AGREEMENT_WINDOWS) as AgreementWindow[]).map((key) => ({ key, label: AGREEMENT_WINDOWS[key].label, href: `/rules/agreement?window=${key}` }));

export default async function AgreementPage({ searchParams }: PageProps<"/rules/agreement">) {
  await requireAgreementAccess();
  const sp = await searchParams;
  const window = parseAgreementWindow(typeof sp.window === "string" ? sp.window : undefined) ?? "30d";
  const res = await safeQuery(() => agreementMetrics(window));
  const groups = res.ok ? splitForTuning(res.data.rules) : { enough: [], lowData: [] };
  const t = res.ok ? res.data.total : null;

  return (
    <>
      <PageHeader
        back={{ href: "/rules", label: "Правила корреляции" }}
        title="Согласие с агентом"
        subtitle="Насколько вердикты агента совпадают с решениями людей и какие правила чаще всего ложно срабатывают."
        actions={<FilterTabs label="Период" items={windowTabs()} current={window} />}
      />

      {!res.ok || !t ? (
        <StorageUnavailable reason={res.ok ? "" : res.error} what="метрики согласия" />
      ) : (
        <>
          <div className="grid grid-cols-2 gap-6 lg:grid-cols-4">
            <StatTile label="Ответов людей" value={fmtNum(t.labeled)} sub={`завершённые инциденты за ${AGREEMENT_WINDOWS[window].label}`} />
            <StatTile label="Совпало (вслепую)" value={t.blind.agreement.n ? pct(t.blind.agreement.share ?? 0) : "—"}
              sub={t.blind.agreement.n ? ofN(t.blind.agreement) : "сравнивать не с чем"} hint={range(t.blind.agreement)}
              note={lowData(t.blind.agreement)} />
            <StatTile label="Совпало (видели подсказку)" value={t.sighted.agreement.n ? pct(t.sighted.agreement.share ?? 0) : "—"}
              sub={t.sighted.agreement.n ? `${ofN(t.sighted.agreement)} · может быть завышено` : "сравнивать не с чем"} hint={range(t.sighted.agreement)}
              note={lowData(t.sighted.agreement)} />
            <StatTile label="Ложных срабатываний" value={t.labeled ? pct(t.false_positive.share ?? 0) : "—"}
              sub={`${fmtNum(t.false_positive.k)} из ${fmtNum(t.labeled)}`} hint={range(t.false_positive)}
              tone={!t.false_positive.low_data && (t.false_positive.share ?? 0) >= 0.5 ? "warn" : undefined}
              note={lowData(t.false_positive)} />
          </div>

          <Panel
            label="По правилам"
            meta={`сверху — чаще всего ложные с учётом объёма выборки · серым — меньше ${LOW_DATA_N} ответов`}
          >
            {res.data.rules.length === 0 ? (
              <Empty title={`За ${AGREEMENT_WINDOWS[window].label} нет завершённых инцидентов с ответом человека`} hint="Доли появятся, когда аналитики закроют первые инциденты." />
            ) : (
              <div className="space-y-4">
                {groups.enough.length > 0 ? <RulesTable rows={groups.enough} /> : (
                  <Empty>Ни у одного правила пока нет {LOW_DATA_N} ответов — выводы делать рано; правила с малой выборкой — ниже.</Empty>
                )}
                {groups.lowData.length > 0 && (
                  <details className="group" open={groups.enough.length === 0}>
                    <summary className="flex cursor-pointer items-center gap-2 py-1 text-sm text-muted-foreground hover:text-foreground">
                      <span aria-hidden className="inline-block transition-transform group-open:rotate-90">›</span>
                      <span className="c-label">Мало данных (меньше {LOW_DATA_N} ответов)</span>
                      <span className="font-mono text-[12px] tabular-nums">{fmtNum(groups.lowData.length)}</span>
                    </summary>
                    <div className="mt-2"><RulesTable rows={groups.lowData} /></div>
                  </details>
                )}
                <p className="text-[12px] leading-relaxed text-muted-foreground">
                  «Вслепую» — человек решал, не видя подсказки агента. «Видели подсказку» — видел, поэтому совпадение может быть завышено.
                  «Агент не решил» — агент не вынес вердикта до закрытия. Наведите на долю, чтобы увидеть диапазон.
                </p>
              </div>
            )}
          </Panel>

          <details className="group text-[13px] text-muted-foreground">
            <summary className="inline-flex cursor-pointer items-center gap-1.5 hover:text-foreground">
              <span aria-hidden className="inline-block transition-transform group-open:rotate-90">›</span>
              Как считается
            </summary>
            <div className="mt-3 max-w-[80ch] space-y-2 border-l border-[var(--border-strong)] pl-3 leading-relaxed">
              <p>Учитываются инциденты, завершённые за {AGREEMENT_WINDOWS[window].label}, с ответом человека. Открытые инциденты не учитываются.</p>
              <p>Вердикт агента сравнивается с решением человека: «вредоносная активность», «легитимно, разрешено» или «ложное срабатывание». Берётся последний вердикт агента до закрытия.</p>
              <p>Ответы DevOps (правила <span className="font-mono">ops.*</span>) входят в долю ложных, но не в совпадение с агентом.</p>
              <p>Порядок правил — по нижней границе диапазона, в котором с вероятностью 95 % лежит настоящая доля ложных: правило с 1 ложным из 2 не обгоняет правило с 3 из 7. При меньше чем {LOW_DATA_N} ответах диапазон слишком широк — такие правила собраны отдельно.</p>
              <p>Те же данные в JSON: <span className="font-mono">GET /api/incidents/agreement?window={window}</span>.</p>
            </div>
          </details>
        </>
      )}
    </>
  );
}
