// Проверка миграционного окна 0031: часть parts ещё без p_source_last, новые
// parts уже с проекцией. sourcesHealthReport должен уйти на heartbeat, а не
// сканировать старые events. План и счётчики снимаются с production SQL.
import { after, before, test } from "node:test";
import assert from "node:assert/strict";
import { randomBytes } from "node:crypto";
import { ch, liveSkip as skip, migrationStatements, serializeLiveFile } from "./_ch-live";

serializeLiveFile({ before, after });

/* eslint-disable @typescript-eslint/no-require-imports -- окружение установлено _ch-live */
const queries = () => require("../src/lib/argus-queries") as typeof import("../src/lib/argus-queries");
/* eslint-enable @typescript-eslint/no-require-imports */

type Measurement = {
  phase: string; sql: string; params: Record<string, string>; status: number;
  readRows: number | null; summary: unknown; error: string;
};

test("sourcesHealthReport: частичная p_source_last не разрешает скан старых events", { skip }, async (t) => {
  const db = `argus_projection_test_${randomBytes(6).toString("hex")}`;
  const oldSource = "old.direct", newSource = "new.direct", heartbeat = "heartbeat.only";
  const measurements: Measurement[] = [];
  let phase = "setup", database = "default", created = false, stopped = false;
  const nativeFetch = globalThis.fetch;
  t.mock.method(globalThis, "fetch", async (input: URL | string | Request, init?: RequestInit) => {
    const url = new URL(input instanceof Request ? input.url : String(input));
    // Только изоляция БД и завершённая статистика в HTTP-заголовке. SQL,
    // настройки оптимизатора и ответы сервера не подменяются.
    url.searchParams.set("database", database);
    url.searchParams.set("wait_end_of_query", "1");
    const requestPhase = phase;
    const response = await nativeFetch(url, init);
    const raw = response.headers.get("X-ClickHouse-Summary");
    const summary = raw ? JSON.parse(raw) as Record<string, unknown> : null;
    measurements.push({
      phase: requestPhase, sql: String(init?.body ?? ""), status: response.status,
      params: Object.fromEntries([...url.searchParams].filter(([k]) => k.startsWith("param_")).map(([k, v]) => [k.slice(6), v])),
      readRows: summary?.read_rows === undefined ? null : Number(summary.read_rows), summary,
      error: response.ok ? "" : (await response.clone().text()).slice(0, 2000),
    });
    return response;
  });

  const fixtureDDL = (file: string, pattern: RegExp) => {
    const stmt = migrationStatements(file).find((sql) => pattern.test(sql));
    assert.ok(stmt, `DDL фикстуры берётся из ${file}`);
    return stmt.replaceAll("argus.", `${db}.`);
  };
  const eventReads = (name: string) => measurements.filter((m) => m.phase === name && /^\s*SELECT\b/i.test(m.sql) && /\bFROM\s+events\b/i.test(m.sql));
  const rowsRead = (reads: Measurement[]) => reads.reduce((sum, m) => {
    if (m.readRows === null) {
      // Ошибка оптимизатора до чтения может не иметь Summary. Прочие ошибки
      // без статистики не считаем доказательством дешёвого запроса.
      assert.match(m.error, /PROJECTION_NOT_USED/, `нет счётчика read_rows: ${JSON.stringify(m)}`);
      return sum;
    }
    assert.ok(Number.isFinite(m.readRows) && m.readRows >= 0);
    return sum + m.readRows;
  }, 0);

  try {
    await ch().chCommand(`CREATE DATABASE ${db}`);
    created = true;
    database = db;
    await ch().chCommand(fixtureDDL("0005_events_incidents.sql", /^CREATE TABLE IF NOT EXISTS argus\.events\b/));
    await ch().chCommand(fixtureDDL("0008_collector_health_log.sql", /^CREATE TABLE IF NOT EXISTS argus\.collector_health_log\b/));
    await ch().chCommand(fixtureDDL("0028_events_received_at_index.sql", /ADD INDEX IF NOT EXISTS idx_received_at/));
    await ch().chCommand(`SYSTEM STOP MERGES ${db}.events`);
    stopped = true;
    await ch().chCommand(`INSERT INTO events (ts, received_at, source, source_class)
      SELECT now64(3) - INTERVAL 2 HOUR + toIntervalMillisecond(number), now() - INTERVAL 2 HOUR, {source:String}, 'system'
      FROM numbers(65536)`, { source: oldSource });

    phase = "baseline";
    // Физическое чтение старых 65536 строк до ADD PROJECTION. Сравнение с
    // baseline всей смешанной таблицы было бы слабее: новый part мог бы
    // ускориться, скрыв полный скан старого.
    await ch().chQuery("SELECT sum(toUInt64(received_at)) AS checksum FROM events SETTINGS optimize_use_projections = 0");
    const baseline = rowsRead(eventReads("baseline"));
    assert.equal(baseline, 65536, "baseline должен измерять полный старый part, а не метаданные count()");

    phase = "setup";
    // Именно ADD из миграции; MATERIALIZE пока не выполняется.
    await ch().chCommand(fixtureDDL("0031_events_source_last_projection.sql", /ADD PROJECTION IF NOT EXISTS p_source_last/));
    await ch().chCommand(`INSERT INTO events (ts, received_at, source, source_class)
      SELECT now64(3) - INTERVAL 90 MINUTE + toIntervalMillisecond(number), now() - INTERVAL 90 MINUTE, {source:String}, 'system'
      FROM numbers(8192)`, { source: newSource });
    await ch().chCommand("INSERT INTO collector_health_log (source, listener, seen_at, events_1m) VALUES ({source:String}, 'http', now() - INTERVAL 3 HOUR, 1)", { source: heartbeat });
    const parts = await ch().chQuery<{ name: string; rows: string | number; projections: string[] }>(
      "SELECT name, rows, projections FROM system.parts WHERE database = {db:String} AND table = 'events' AND active ORDER BY name", { db });
    assert.equal(parts.filter((p) => !p.projections.includes("p_source_last")).reduce((sum, p) => sum + Number(p.rows), 0), 65536);
    assert.equal(parts.filter((p) => p.projections.includes("p_source_last")).reduce((sum, p) => sum + Number(p.rows), 0), 8192);

    phase = "mixed";
    const report = await queries().sourcesHealthReport();
    const reads = eventReads("mixed");
    assert.ok(reads.length > 0, "замеряются запросы настоящего sourcesHealthReport");
    phase = "explain";
    const plans: string[] = [];
    for (const request of reads.filter((r) => /force_optimize_projection\s*=\s*1/.test(r.sql))) {
      // Текущий chQuery задаёт default_format в URL; если клиент начнёт
      // добавлять FORMAT в SQL, он не должен стать частью объясняемого SELECT.
      const select = request.sql.trim().replace(/\s+FORMAT\s+JSONEachRow\s*;?$/i, "").replace(/;$/, "");
      try {
        const rows = await ch().chQuery<{ explain: string }>(`EXPLAIN indexes = 1 ${select}`, request.params);
        plans.push(rows.map((r) => r.explain).join("\n"));
      } catch (error) {
        // Разрешён только тот же отказ оптимизатора, который вернул сам
        // production SELECT. Синтаксическая ошибка probe должна ронять тест.
        const originalCode = /Code:\s*(\d+)/.exec(request.error)?.[1];
        if (!request.error.includes("PROJECTION_NOT_USED") || !(error instanceof ch().ClickHouseError) || error.code !== Number(originalCode)) throw error;
        plans.push(`EXPLAIN rejected: ${error instanceof Error ? error.message : String(error)}`);
      }
    }
    t.diagnostic(JSON.stringify({ db, baseline, parts, sources: report.sources.map((s) => s.source), reads, plans }));
    await t.test("чтение старых событий не маскируется использованием проекции только нового part", () => {
      assert.ok(rowsRead(reads) < baseline, `ожидалось чтение меньше ${baseline} старых строк; read_rows=${rowsRead(reads)}; EXPLAIN:\n${plans.join("\n\n")}`);
    });
    await t.test("до полной материализации сохраняется документированный fallback на heartbeat", () => {
      assert.deepEqual(report.sources.map((s) => s.source), [heartbeat]);
      assert.equal(report.omitted, 0);
    });

    // Положительный контроль: после MATERIALIZE тот же production SQL должен
    // вернуть обоих прямых писателей, читая агрегаты вместо старого part.
    phase = "materialize";
    await ch().chCommand(`SYSTEM START MERGES ${db}.events`);
    stopped = false;
    await ch().chCommand(`ALTER TABLE ${db}.events MATERIALIZE PROJECTION p_source_last SETTINGS mutations_sync = 2`);
    phase = "complete";
    const complete = await queries().sourcesHealthReport();
    await t.test("полная проекция: писатели events видны и чтение меньше baseline", () => {
      assert.deepEqual(complete.sources.map((s) => s.source).sort(), [heartbeat, oldSource, newSource].sort());
      assert.equal(complete.omitted, 0);
      assert.ok(rowsRead(eventReads("complete")) < baseline);
    });
  } finally {
    phase = "cleanup";
    try {
      if (stopped) await ch().chCommand(`SYSTEM START MERGES ${db}.events`);
    } finally {
      database = "default";
      if (created) await ch().chCommand(`DROP DATABASE ${db} SYNC`);
    }
  }
});
