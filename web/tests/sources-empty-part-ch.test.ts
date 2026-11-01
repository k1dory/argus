// DELETE может оставить активный пустой part без файлов проекции. Он не должен
// скрывать прямых писателей, если все непустые parts полностью материализованы.
import { after, before, test } from "node:test";
import assert from "node:assert/strict";
import { randomBytes } from "node:crypto";
import { ch, liveSkip as skip, migrationStatements, serializeLiveFile } from "./_ch-live";

serializeLiveFile({ before, after });

/* eslint-disable @typescript-eslint/no-require-imports -- окружение установлено _ch-live */
const queries = () => require("../src/lib/argus-queries") as typeof import("../src/lib/argus-queries");
/* eslint-enable @typescript-eslint/no-require-imports */

test("sourcesHealthReport: пустой active part после DELETE не скрывает готовую проекцию", { skip }, async (t) => {
  const db = `argus_empty_part_test_${randomBytes(6).toString("hex")}`;
  let database = "default", created = false, stopped = false;
  const nativeFetch = globalThis.fetch;
  t.mock.method(globalThis, "fetch", async (input: URL | string | Request, init?: RequestInit) => {
    const url = new URL(input instanceof Request ? input.url : String(input));
    url.searchParams.set("database", database);
    return nativeFetch(url, init);
  });
  const ddl = (file: string, pattern: RegExp) => {
    const sql = migrationStatements(file).find((statement) => pattern.test(statement));
    assert.ok(sql, `DDL фикстуры берётся из ${file}`);
    return sql.replaceAll("argus.", `${db}.`);
  };

  try {
    await ch().chCommand(`CREATE DATABASE ${db}`);
    created = true;
    database = db;
    await ch().chCommand(ddl("0005_events_incidents.sql", /^CREATE TABLE IF NOT EXISTS argus\.events\b/));
    await ch().chCommand(ddl("0008_collector_health_log.sql", /^CREATE TABLE IF NOT EXISTS argus\.collector_health_log\b/));
    await ch().chCommand(ddl("0028_events_received_at_index.sql", /ADD INDEX IF NOT EXISTS idx_received_at/));
    await ch().chCommand(ddl("0031_events_source_last_projection.sql", /ADD PROJECTION IF NOT EXISTS p_source_last/));
    await ch().chCommand(`INSERT INTO events (ts, received_at, source, source_class)
      SELECT now64(3) - INTERVAL 2 HOUR, now() - INTERVAL 2 HOUR, 'removed.fixture', 'system' FROM numbers(20)`);
    await ch().chCommand("ALTER TABLE events DELETE WHERE source = 'removed.fixture' SETTINGS mutations_sync = 2");
    // Завершённая MATERIALIZE исключает гонку с фоновым построением проекции.
    await ch().chCommand("ALTER TABLE events MATERIALIZE PROJECTION p_source_last SETTINGS mutations_sync = 2");
    await ch().chCommand(`SYSTEM STOP MERGES ${db}.events`);
    stopped = true;
    await ch().chCommand(`INSERT INTO events (ts, received_at, source, source_class)
      SELECT now64(3) - INTERVAL 3 HOUR, now() - INTERVAL 3 HOUR, 'direct.writer', 'system' FROM numbers(20)`);

    const parts = await ch().chQuery<{ name: string; rows: string | number; projections: string[] }>(
      "SELECT name, rows, projections FROM system.parts WHERE database = currentDatabase() AND table = 'events' AND active ORDER BY name");
    const mutations = await ch().chQuery<{ is_done: number; parts_to_do: string | number; latest_fail_reason: string }>(
      "SELECT is_done, parts_to_do, latest_fail_reason FROM system.mutations WHERE database = currentDatabase() AND table = 'events'");
    t.diagnostic(JSON.stringify({ parts, mutations }));
    assert.ok(parts.some((part) => Number(part.rows) === 0 && !part.projections.includes("p_source_last")),
      "фикстура должна содержать пустой активный part без проекции");
    assert.ok(parts.filter((part) => Number(part.rows) > 0).every((part) => part.projections.includes("p_source_last")),
      "все непустые parts имеют готовую проекцию");
    assert.ok(mutations.every((mutation) => mutation.is_done === 1 && Number(mutation.parts_to_do) === 0 && !mutation.latest_fail_reason),
      "ожидание фоновой мутации не может исправить сценарий: все мутации завершены");

    // Сам ClickHouse может использовать проекцию при пустом part. Проверка
    // готовности приложения не должна отвергать такое состояние хранилища.
    const projected = await ch().chQuery<{ source: string }>(
      "SELECT source, any(source_class), max(received_at) FROM events GROUP BY source SETTINGS force_optimize_projection = 1");
    assert.deepEqual(projected.map((row) => row.source), ["direct.writer"]);

    const report = await queries().sourcesHealthReport();
    assert.deepEqual(report.sources.map((row) => row.source), ["direct.writer"],
      "готовый прямой writer должен оставаться виден без heartbeat, несмотря на пустой part");
    assert.equal(report.sources[0].alive, 0);
    assert.equal(report.sources[0].source_class, "system");
    assert.equal(report.omitted, 0);
  } finally {
    try {
      if (stopped) await ch().chCommand(`SYSTEM START MERGES ${db}.events`);
    } finally {
      database = "default";
      if (created) await ch().chCommand(`DROP DATABASE ${db} SYNC`);
    }
  }
});
