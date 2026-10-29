import type { Metadata } from "next";
import Link from "next/link";
import { Copyable } from "@/components/console/copyable";
import { searchHref } from "@/lib/shared/search-href";
import { Led, PageHeader, Panel, StatTile } from "@/components/console/panel";
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
import { requirePageSession } from "@/lib/auth";
import { safeQuery } from "@/lib/clickhouse";
import { eventsRecent, sourcesHealth } from "@/lib/argus-queries";
import { SOURCE_ALIVE_LABELS } from "@/lib/shared/labels";
import { describeThreshold, formatRhythm, RHYTHM_WINDOW_DAYS } from "@/lib/shared/source-health";
import { fmtNum, formatAgo, formatTs } from "@/lib/shared/time";

export const dynamic = "force-dynamic";
export const metadata: Metadata = { title: "Источники" };

export default async function SourcesPage({ searchParams }: PageProps<"/sources">) {
  await requirePageSession();
  const ingestBase = (process.env.INGEST_PUBLIC_URL || `https://${process.env.CONSOLE_HOST || "localhost"}:8089`).replace(/\/$/, "");
  const params = await searchParams;
  const source = typeof params.source === "string" ? params.source.slice(0, 200) : undefined;
  const r = await safeQuery(() => Promise.all([sourcesHealth(), eventsRecent(source)]));

  return (
    <>
      <PageHeader title="Источники">
        <span className="c-label">коллектор · syslog 5514 · netflow 2055 · webhooks HTTPS</span>
      </PageHeader>
      {!r.ok ? <StorageUnavailable reason={r.error} /> : <SourcesBody health={r.data[0]} events={r.data[1]} source={source} ingestBase={ingestBase} />}
    </>
  );
}

function SourcesBody({ health, events, source, ingestBase }: { health: Awaited<ReturnType<typeof sourcesHealth>>; events: Awaited<ReturnType<typeof eventsRecent>>; source?: string; ingestBase: string }) {
  const alive = health.filter((h) => h.alive === 1).length;
  const eps = health.reduce((a, h) => a + h.eps_60s, 0);
  const classes = new Set(health.map((h) => h.source_class));
  const now = new Date();

  return (
    <>
      <div className="grid grid-cols-2 gap-6 md:grid-cols-4">
        <StatTile label={`Источников за ${RHYTHM_WINDOW_DAYS} сут`} value={fmtNum(health.length)} />
        <StatTile label="Живы (по ритму)" value={`${fmtNum(alive)} / ${fmtNum(health.length)}`} led={health.length === 0 ? "var(--status-warn)" : alive === health.length ? "var(--status-ok)" : "var(--status-warn)"} />
        <StatTile label="EPS за 60 с" value={fmtNum(eps)} />
        <StatTile label="Классов" value={fmtNum(classes.size)} />
      </div>

      <Panel label={`Коллекторы · источники за ${RHYTHM_WINDOW_DAYS} суток, счётчики за час`} meta={source ? "клик по источнику — фильтр ленты ниже" : undefined}>
        {health.length === 0 ? (
          <div className="space-y-2">
            <p className="text-sm text-muted-foreground">За последние {RHYTHM_WINDOW_DAYS} суток событий нет.</p>
            <p className="text-sm text-muted-foreground">
              Направьте syslog/CEF на <span className="font-mono">:5514</span>, NetFlow на <span className="font-mono">:2055</span>, вебхуки на <span className="font-mono">{ingestBase}/ingest/&lt;тип&gt;</span> с заголовком <span className="font-mono">X-Argus-Token: …</span> — или прогоните записанный трафик командой <span className="font-mono">make replay</span>.
            </p>
          </div>
        ) : (
          <div className="c-well overflow-x-auto p-2">
            <Table>
              <TableHeader>
                <TableRow className="border-border/60">
                  <TableHead className="c-label">Источник</TableHead>
                  <TableHead className="c-label">Класс</TableHead>
                  <TableHead className="c-label text-right">За час</TableHead>
                  <TableHead className="c-label text-right">EPS/60 с</TableHead>
                  <TableHead className="c-label text-right">ПДн, %</TableHead>
                  <TableHead className="c-label">Последний приём (UTC)</TableHead>
                  <TableHead className="c-label">Ритм за {RHYTHM_WINDOW_DAYS} сут</TableHead>
                  <TableHead className="c-label">Статус</TableHead>
                </TableRow>
              </TableHeader>
              <TableBody>
                {health.map((h) => {
                  const active = h.source === source;
                  return (
                    <TableRow key={h.source} className={active ? "border-border/40 bg-[var(--muted)]" : "border-border/40"} aria-current={active ? "true" : undefined}>
                      <TableCell className="font-mono text-xs">
                        <span className="flex items-center gap-2">
                          {active && <span className="text-[var(--ring)]" aria-hidden>▸</span>}
                          <Copyable value={h.source} href={`/sources?source=${encodeURIComponent(h.source)}`} label="Источник" />
                        </span>
                      </TableCell>
                      <TableCell className="font-mono text-xs">{h.source_class}</TableCell>
                      <TableCell className="text-right font-mono text-xs">{fmtNum(h.events_1h)}</TableCell>
                      <TableCell className="text-right font-mono text-xs">{fmtNum(h.eps_60s)}</TableCell>
                      <TableCell className="text-right font-mono text-xs">{h.pii_share > 0 ? <span className="text-[var(--status-warn)]">{fmtNum(h.pii_share, 1)} %</span> : "0 %"}</TableCell>
                      <TableCell className="font-mono text-xs whitespace-nowrap" title={formatAgo(h.last_ts, now)}>{formatTs(h.last_ts)}</TableCell>
                      <TableCell className="font-mono text-xs whitespace-nowrap" title={`${fmtNum(h.events_window)} событий за ${RHYTHM_WINDOW_DAYS} суток; ритм — типичный разрыв между активными минутами`}>{formatRhythm(h.rhythm_sec)}</TableCell>
                      <TableCell>
                        <span className="flex items-center gap-2 font-mono text-xs" title={describeThreshold(h.silence_threshold_sec, h.silent_for_sec)}>
                          <Led color={h.alive ? "var(--status-ok)" : "var(--status-err)"} />
                          {h.alive ? SOURCE_ALIVE_LABELS.alive : SOURCE_ALIVE_LABELS.silent}
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

      <Panel
        label={source ? `События · ${source}` : "События · последние по всем источникам"}
        meta={
          source ? (
            <Button asChild variant="ghost" size="xs"><Link href="/sources">сбросить фильтр</Link></Button>
          ) : (
            "единая схема: субъект · объект · действие · узел"
          )
        }
      >
        {events.length === 0 ? (
          <p className="text-sm text-muted-foreground">
            {source ? `За 24 часа новых поступлений от «${source}» нет.` : "За 24 часа новых поступлений нет."}
          </p>
        ) : (
          <div className="c-well overflow-x-auto p-2">
            <Table>
              <TableHeader>
                <TableRow className="border-border/60">
                  <TableHead className="c-label">Поступило (UTC)</TableHead>
                  <TableHead className="c-label">Время события (UTC)</TableHead>
                  <TableHead className="c-label">Источник</TableHead>
                  <TableHead className="c-label">Действие</TableHead>
                  <TableHead className="c-label">Субъект</TableHead>
                  <TableHead className="c-label">Объект / назначение</TableHead>
                  <TableHead className="c-label">Узел</TableHead>
                  <TableHead className="c-label text-right">Серьёзность</TableHead>
                </TableRow>
              </TableHeader>
              <TableBody>
                {events.map((e, i) => (
                  <TableRow key={`${e.ts}|${e.source}|${e.action}|${e.actor_name}|${i}`} className="border-border/40">
                    <TableCell className="font-mono text-xs whitespace-nowrap">{formatTs(e.received_at)}</TableCell>
                    <TableCell className="font-mono text-xs whitespace-nowrap">{formatTs(e.ts)}</TableCell>
                    <TableCell className="font-mono text-xs"><Copyable value={e.source} href={searchHref.source(e.source)} label="Источник" /></TableCell>
                    <TableCell className="font-mono text-xs">{e.action}<span className="text-muted-foreground"> · {e.outcome}</span></TableCell>
                    <TableCell className="font-mono text-xs">{e.pii === 1 ? <span title="ПДн">[ПДн] </span> : null}{e.actor_name ? <Copyable value={e.actor_name} href={searchHref.actor(e.actor_name)} label="Субъект" /> : "—"}</TableCell>
                    <TableCell className="max-w-md truncate font-mono text-xs">
                      {e.object ? <Copyable value={e.object} label="Объект" /> : e.dst_ip ? <Copyable value={`${e.dst_ip}:${e.dst_port}`} label="Назначение" /> : e.src_ip ? <Copyable value={e.src_ip} href={searchHref.eventSrc(e.src_ip)} label="IP" /> : "—"}
                    </TableCell>
                    <TableCell className="font-mono text-xs">{e.node ? <Copyable value={e.node} href={searchHref.node(e.node)} label="Узел" /> : "—"}</TableCell>
                    <TableCell className="text-right font-mono text-xs">{e.severity}</TableCell>
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
