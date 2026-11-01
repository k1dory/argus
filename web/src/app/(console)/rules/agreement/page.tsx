import type { Metadata } from "next";
import Link from "next/link";
import { PageHeader, Panel, StatTile } from "@/components/console/panel";
import { StorageUnavailable } from "@/components/console/storage-error";
import { Button } from "@/components/ui/button";
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from "@/components/ui/table";
import { safeQuery } from "@/lib/clickhouse";
import { agreementMetrics, requireAgreementAccess } from "@/lib/blind-metrics";
import { AGREEMENT_WINDOWS, LOW_DATA_N, parseAgreementWindow, type AgreementWindow, type Share } from "@/lib/shared/blind-metrics";
import { fmtNum } from "@/lib/shared/time";

export const dynamic = "force-dynamic";
export const metadata: Metadata = { title: "Согласие с агентом" };

const pct = (x: number) => `${Math.round(x * 100)} %`;
const lowData = (s: Share) => (s.low_data ? "мало данных" : undefined);

/** Доля, интервал Уилсона и пометка «мало данных» при n < LOW_DATA_N. */
function ShareCell({ s }: { s: Share }) {
  if (s.n === 0) return <span className="text-muted-foreground">—</span>;
  return (
    <span className="whitespace-nowrap">
      <span className={s.low_data ? "text-muted-foreground" : undefined}>{pct(s.share ?? 0)}</span>
      <span className="text-muted-foreground"> · {fmtNum(s.k)}/{fmtNum(s.n)}</span>
      {s.ci && <span className="block text-[11px] text-muted-foreground">95 %: {pct(s.ci.low)}–{pct(s.ci.high)}</span>}
      {s.low_data && <span className="block text-[11px] text-[var(--status-warn)]">мало данных</span>}
    </span>
  );
}

function WindowLinks({ current }: { current: AgreementWindow }) {
  return (
    <div className="flex gap-2" role="group" aria-label="Окно метрик">
      {(Object.keys(AGREEMENT_WINDOWS) as AgreementWindow[]).map((key) => (
        <Button key={key} asChild variant="secondary" size="sm" aria-pressed={current === key}>
          <Link href={`/rules/agreement?window=${key}`}>{AGREEMENT_WINDOWS[key].label}</Link>
        </Button>
      ))}
    </div>
  );
}

export default async function AgreementPage({ searchParams }: PageProps<"/rules/agreement">) {
  await requireAgreementAccess();
  const sp = await searchParams;
  const window = parseAgreementWindow(typeof sp.window === "string" ? sp.window : undefined) ?? "30d";
  const res = await safeQuery(() => agreementMetrics(window));

  return (
    <>
      <PageHeader
        title="Согласие с агентом"
        subtitle={`Завершённые за ${AGREEMENT_WINDOWS[window].label} инциденты с ответом человека: совпал ли вердикт агента с ответом и как часто правило ложно срабатывает. Слепой разбор — человек не видел подсказку агента; у неслепого согласие может быть завышено. Открытые инциденты не учитываются.`}
      >
        <WindowLinks current={window} />
      </PageHeader>

      {!res.ok ? (
        <StorageUnavailable reason={res.error} />
      ) : (
        <>
          <div className="grid grid-cols-2 gap-6 md:grid-cols-4">
            <StatTile label="Ответов людей" value={fmtNum(res.data.total.labeled)} />
            <StatTile label="Согласие · слепые" value={res.data.total.blind.agreement.n ? pct(res.data.total.blind.agreement.share ?? 0) : "—"}
              hint={`${fmtNum(res.data.total.blind.agreement.k)} из ${fmtNum(res.data.total.blind.agreement.n)} сравнимых`}
              note={lowData(res.data.total.blind.agreement)} />
            <StatTile label="Согласие · неслепые" value={res.data.total.sighted.agreement.n ? pct(res.data.total.sighted.agreement.share ?? 0) : "—"}
              hint={`${fmtNum(res.data.total.sighted.agreement.k)} из ${fmtNum(res.data.total.sighted.agreement.n)} сравнимых`}
              note={lowData(res.data.total.sighted.agreement)} />
            <StatTile label="Ложных срабатываний" value={res.data.total.labeled ? pct(res.data.total.false_positive.share ?? 0) : "—"}
              hint={`${fmtNum(res.data.total.false_positive.k)} из ${fmtNum(res.data.total.labeled)}`}
              note={lowData(res.data.total.false_positive)} />
          </div>

          <Panel label="По правилам" meta={`сверху — кандидаты на тюнинг (доля ложных); при n < ${LOW_DATA_N} — «мало данных»`}>
            {res.data.rules.length === 0 ? (
              <p className="text-sm text-muted-foreground">За {AGREEMENT_WINDOWS[window].label} нет завершённых инцидентов с ответом человека.</p>
            ) : (
              <div className="c-well overflow-x-auto p-2">
                <Table>
                  <TableHeader>
                    <TableRow className="border-border/60">
                      <TableHead className="c-label">Правило</TableHead>
                      <TableHead className="c-label text-right">n</TableHead>
                      <TableHead className="c-label">Ложных</TableHead>
                      <TableHead className="c-label">Согласие · слепые</TableHead>
                      <TableHead className="c-label">Согласие · неслепые</TableHead>
                      <TableHead className="c-label text-right" title="агент ответил undetermined или вердикта до закрытия не было">Без сравнения</TableHead>
                    </TableRow>
                  </TableHeader>
                  <TableBody>
                    {res.data.rules.map((r) => (
                      <TableRow key={r.rule_id} className="border-border/40">
                        <TableCell className="text-xs">
                          <span className="block">{r.rule_title || r.rule_id}</span>
                          <span className="font-mono text-[11px] text-muted-foreground">{r.rule_id}</span>
                        </TableCell>
                        <TableCell className="text-right font-mono text-xs">{fmtNum(r.labeled)}</TableCell>
                        <TableCell className="font-mono text-xs"><ShareCell s={r.false_positive} /></TableCell>
                        <TableCell className="font-mono text-xs"><ShareCell s={r.blind.agreement} /></TableCell>
                        <TableCell className="font-mono text-xs"><ShareCell s={r.sighted.agreement} /></TableCell>
                        <TableCell className="text-right font-mono text-xs">
                          {fmtNum(r.blind.undetermined + r.blind.no_verdict + r.sighted.undetermined + r.sighted.no_verdict)}
                        </TableCell>
                      </TableRow>
                    ))}
                  </TableBody>
                </Table>
              </div>
            )}
          </Panel>
          <p className="text-xs text-muted-foreground">
            Сопоставление: true_positive — «вредоносная активность», benign_true_positive — «легитимно, разрешено», false_positive — «ложное срабатывание». Берётся последний вердикт агента до закрытия. Ответы DevOps (правила ops.*) входят в долю ложных (причина «ложное срабатывание»), в согласие с агентом — нет. Интервал — Уилсона, 95 %. JSON — <span className="font-mono">GET /api/incidents/agreement?window={window}</span>.
          </p>
        </>
      )}
    </>
  );
}
