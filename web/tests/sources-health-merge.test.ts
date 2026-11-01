// Слияние результата проекции events с heartbeat проверяем через production
// sourcesHealthReport и HTTP-ответы ClickHouse. Сам SQL ритма проверяется отдельно
// на живом сервере в sources-rhythm-ch.test.ts.
import { test, type TestContext } from "node:test";
import assert from "node:assert/strict";
import { sourcesHealthReport, STALE_SOURCES_LIMIT } from "../src/lib/argus-queries";

type Stale = { source: string; source_class: string; last_ts: string; last_sec: number; stale_total: string; now_sec: number | string };
type Heartbeat = { source: string; events_window: string; gap_q: number | null; last_sec: number; now_sec: number };
type Hour = Omit<Stale, "stale_total"> & { events_1h: string; eps_60s: string; pii_share: number };
const now = Math.floor(Date.now() / 1000);
const source = (n: number) => `dead.${String(n).padStart(5, "0")}`;
const stale = (name: string, ago = 7200, total = 1): Stale => ({
  source: name, source_class: "system", last_sec: now - ago, now_sec: now,
  last_ts: new Date((now - ago) * 1000).toISOString().slice(0, 19).replace("T", " "), stale_total: String(total),
});
const heartbeat = (name: string, ago = 7200): Heartbeat => ({ source: name, events_window: "10", gap_q: null, last_sec: now - ago, now_sec: now });
const hourly = (name: string, ago = 30): Hour => {
  const { source, source_class, last_ts, last_sec, now_sec } = stale(name, ago);
  return { source, source_class, last_ts, last_sec, now_sec, events_1h: "10", eps_60s: "1", pii_share: 0 };
};

function database(t: TestContext, projection: Stale[], heartbeats: Heartbeat[], omittedWithHeartbeat: Stale[] = [], hour: Hour[] = []) {
  const calls = { hour: 0, rhythm: 0, projection: 0, lookup: 0 };
  t.mock.method(globalThis, "fetch", async (_url: unknown, options?: RequestInit) => {
    const sql = String(options?.body);
    let rows: unknown[];
    if (sql.includes("FROM collector_health_log")) {
      calls.rhythm++;
      rows = heartbeats;
    } else if (sql.includes("AS events_1h")) {
      calls.hour++;
      rows = hour;
    } else if (sql.includes("AS stale_total")) {
      calls.projection++;
      assert.match(sql, /toUnixTimestamp\(now\(\)\)\s+AS\s+now_sec\b/i, "основная проекция запрашивает время ClickHouse");
      rows = projection;
    }
    // Если исправление уточняет, какие heartbeat уже учтены в stale_total,
    // fixture возвращает их настоящие строки events, не добавляя heartbeat-only.
    else if (sql.includes("FROM events") && /source\s+IN\b/i.test(sql)) {
      calls.lookup++;
      assert.match(sql, /toUnixTimestamp\(now\(\)\)\s+AS\s+now_sec\b/i, "точечная проекция запрашивает время ClickHouse");
      rows = omittedWithHeartbeat;
    }
    else throw new Error(`неожиданный запрос фикстуры: ${sql}`);
    return new Response(rows.map((r) => JSON.stringify(r)).join("\n"));
  });
  return calls;
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

test("sources: молчание прямого writer считается по часам ClickHouse, а не Node", async (t) => {
  for (const skew of [-86400, 86400]) {
    for (const chNow of [now, String(now)]) {
      await t.test(`Node сдвинут на ${skew} с, now_sec: ${typeof chNow}`, async (t) => {
        t.mock.method(Date, "now", () => (now + skew) * 1000);
        database(t, [{ ...stale("argus.system"), now_sec: chNow }], []);
        const { sources, omitted } = await sourcesHealthReport();
        assert.equal(sources.length, 1);
        assert.equal(omitted, 0);
        assert.equal(sources[0].silent_for_sec, 7200, "рассинхрон Node и ClickHouse не попадает в silent_for_sec");
        assert.equal(sources[0].alive, 0, "отстающие часы Node не оживляют молчащий writer");
      });
    }
  }
});

test("sources: часы основной проекции сохраняются в смеси с часовым запросом и heartbeat-only", async (t) => {
  t.mock.method(Date, "now", () => (now - 86400) * 1000);
  const direct = { ...stale("argus.system"), now_sec: now + 10 };
  const hb = { ...heartbeat("heartbeat.only", 5400), gap_q: 3600 };
  const calls = database(t, [direct], [hb], [], [hourly("active.writer")]);

  const { sources, omitted } = await sourcesHealthReport();
  assert.deepEqual(calls, { hour: 1, rhythm: 1, projection: 1, lookup: 0 });
  assert.equal(omitted, 0);
  assert.deepEqual(sources.map((s) => [s.source, s.silent_for_sec, s.alive]), [
    ["active.writer", 30, 1],
    ["heartbeat.only", 5400, 1],
    ["argus.system", 7210, 0],
  ], "время другого запроса не заменяет now_sec прямого writer");
});

test("sources: основной и точечный ответы проекции обходятся без часов Node", async (t) => {
  t.mock.method(Date, "now", () => (now - 86400) * 1000);
  const limit = STALE_SOURCES_LIMIT;
  // Между снимками проекции и часового запроса первый источник возобновился.
  // Он освобождает место среди молчащих для строки за LIMIT, пришедшей из lookup.
  const lookup = stale(source(limit), 7200, limit + 1);
  const projection = Array.from({ length: limit }, (_, i) => stale(source(i), 7200, limit + 1));
  const calls = database(t, projection, [heartbeat(lookup.source)], [lookup], [hourly(source(0))]);

  const { sources, omitted } = await sourcesHealthReport();
  assert.deepEqual(calls, { hour: 1, rhythm: 1, projection: 1, lookup: 1 });
  assert.equal(sources.length, limit + 1);
  assert.equal(omitted, 0, "возобновившийся источник и строка lookup не считаются дважды");
  assert.equal(sources[0].source, source(0));
  assert.equal(sources[0].silent_for_sec, 30);
  assert.equal(sources[0].alive, 1);
  const found = sources.find((s) => s.source === lookup.source);
  assert.ok(found, "строка точечного запроса вошла в выдачу");
  assert.equal(found.last_ts, lookup.last_ts);
  assert.ok(sources.some((s) => s.source === source(1)), "выдача содержит и основной ответ");
  for (const s of sources.slice(1)) {
    assert.equal(s.silent_for_sec, 7200, s.source);
    assert.equal(s.alive, 0, s.source);
  }
});

test("sources: пустые ответы не создают источники из локального времени", async (t) => {
  t.mock.method(Date, "now", () => (now + 86400) * 1000);
  const calls = database(t, [], []);
  assert.deepEqual(await sourcesHealthReport(), { sources: [], omitted: 0 });
  assert.deepEqual(calls, { hour: 1, rhythm: 1, projection: 1, lookup: 0 });
});
