// Слияние результата проекции events с heartbeat проверяем через production
// sourcesHealthReport и HTTP-ответы ClickHouse. Сам SQL ритма проверяется отдельно
// на живом сервере в sources-rhythm-ch.test.ts.
import { test, type TestContext } from "node:test";
import assert from "node:assert/strict";
import { sourcesHealthReport, STALE_SOURCES_LIMIT } from "../src/lib/argus-queries";

type Stale = { source: string; source_class: string; last_ts: string; last_sec: number; stale_total: string };
type Heartbeat = { source: string; events_window: string; gap_q: number | null; last_sec: number; now_sec: number };
const now = Math.floor(Date.now() / 1000);
const source = (n: number) => `dead.${String(n).padStart(5, "0")}`;
const stale = (name: string, ago = 7200, total = 1): Stale => ({
  source: name, source_class: "system", last_sec: now - ago,
  last_ts: new Date((now - ago) * 1000).toISOString().slice(0, 19).replace("T", " "), stale_total: String(total),
});
const heartbeat = (name: string, ago = 7200): Heartbeat => ({ source: name, events_window: "10", gap_q: null, last_sec: now - ago, now_sec: now });

function database(t: TestContext, projection: Stale[], heartbeats: Heartbeat[], omittedWithHeartbeat: Stale[] = []) {
  t.mock.method(globalThis, "fetch", async (_url: unknown, options?: RequestInit) => {
    const sql = String(options?.body);
    let rows: unknown[];
    if (sql.includes("FROM collector_health_log")) rows = heartbeats;
    else if (sql.includes("AS events_1h")) rows = [];
    else if (sql.includes("AS stale_total")) rows = projection;
    // Если исправление уточняет, какие heartbeat уже учтены в stale_total,
    // fixture возвращает их настоящие строки events, не добавляя heartbeat-only.
    else if (sql.includes("FROM events") && /source\s+IN\b/i.test(sql)) rows = omittedWithHeartbeat;
    else throw new Error(`неожиданный запрос фикстуры: ${sql}`);
    return new Response(rows.map((r) => JSON.stringify(r)).join("\n"));
  });
}

test("sources: прямой writer без heartbeat остаётся молчащим после часа", async (t) => {
  database(t, [stale("argus.system", 3 * 3600)], []);
  const report = await sourcesHealthReport();
  assert.equal(report.omitted, 0);
  assert.equal(report.sources.length, 1);
  const s = report.sources[0];
  assert.equal(s.source, "argus.system");
  assert.equal(s.source_class, "system");
  assert.equal(s.events_1h, 0);
  assert.equal(s.alive, 0);
  assert.equal(s.rhythm_sec, null);
  assert.ok(s.silent_for_sec >= 3 * 3600);
});

test("sources: omitted учитывает heartbeat-only старше границы заполненного списка", async (t) => {
  const limit = STALE_SOURCES_LIMIT;
  database(t, Array.from({ length: limit }, (_, i) => stale(source(i), 7200, limit + 1)), [heartbeat("heartbeat.only", 3 * 3600)]);
  const report = await sourcesHealthReport();
  assert.equal(report.sources.length, limit);
  assert.equal(report.sources.some((s) => s.source === "heartbeat.only"), false, "старый источник не вытесняет более новый");
  assert.equal(report.omitted, 2, "один источник за LIMIT проекции + один heartbeat-only; старый heartbeat тоже входит в итог");
});

test("sources: heartbeat источника за LIMIT проекции не увеличивает omitted второй раз", async (t) => {
  const limit = STALE_SOURCES_LIMIT;
  const omitted = stale(source(limit), 7200, limit + 1);
  database(t, Array.from({ length: limit }, (_, i) => stale(source(i), 7200, limit + 1)), [heartbeat(omitted.source)], [omitted]);
  const report = await sourcesHealthReport();
  assert.deepEqual(report.sources.map((s) => s.source), Array.from({ length: limit }, (_, i) => source(i)));
  assert.equal(report.omitted, 1, "одно имя учитывается один раз даже при равном времени cutoff");
});

test("sources: heartbeat-only младше границы входит в список и вытесняет последнюю строку", async (t) => {
  const limit = STALE_SOURCES_LIMIT;
  database(t, Array.from({ length: limit }, (_, i) => stale(source(i), 7200, limit + 1)), [heartbeat("heartbeat.newer", 90 * 60)]);
  const report = await sourcesHealthReport();
  assert.equal(report.sources.length, limit);
  assert.equal(report.sources[0].source, "heartbeat.newer");
  assert.equal(report.sources[0].last_ts, stale("unused", 90 * 60).last_ts);
  assert.equal(report.omitted, 2);
});
