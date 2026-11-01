// PR #13: since допускает до девяти знаков после точки. Включительная
// граница не должна округляться вниз до миллисекунд и возвращать более
// ранние метки. Настоящий incidentLabels и ClickHouse, отдельная fixture-БД.
import { after, before, test } from "node:test";
import assert from "node:assert/strict";
import { randomBytes } from "node:crypto";
import { ch, liveSkip as skip, migrationStatements, serializeLiveFile } from "./_ch-live";

serializeLiveFile({ before, after });

/* eslint-disable @typescript-eslint/no-require-imports -- _ch-live задаёт окружение соединения */
const queries = () => require("../src/lib/argus-queries") as typeof import("../src/lib/argus-queries");
/* eslint-enable @typescript-eslint/no-require-imports */

test("incidentLabels: точность since не расширяет период выгрузки назад", { skip }, async (t) => {
  const db = `argus_labels_since_${randomBytes(6).toString("hex")}`;
  const id = "INC-410000004";
  let database = "default";
  let created = false;
  const nativeFetch = globalThis.fetch;
  // Только выбор БД: SQL, его параметры и ответ сервера не подменяются.
  t.mock.method(globalThis, "fetch", async (input: URL | string | Request, init?: RequestInit) => {
    const url = new URL(input instanceof Request ? input.url : String(input));
    url.searchParams.set("database", database);
    return nativeFetch(url, init);
  });
  const fixtureDDL = (file: string, pattern: RegExp) => {
    const stmt = migrationStatements(file).find((sql) => pattern.test(sql));
    assert.ok(stmt, `DDL берётся из production миграции ${file}`);
    return stmt.replaceAll("argus.", `${db}.`);
  };
  try {
    await ch().chCommand(`CREATE DATABASE ${db}`);
    created = true;
    database = db;
    await ch().chCommand(fixtureDDL("0005_events_incidents.sql", /^CREATE TABLE IF NOT EXISTS argus\.incidents\b/));
    await ch().chCommand(fixtureDDL("0014_incident_state_events.sql", /^CREATE TABLE IF NOT EXISTS argus\.incident_state_events\b/));
    await ch().chCommand(fixtureDDL("0016_incident_closure_reason.sql", /^ALTER TABLE argus\.incident_state_events\b/));
    await ch().chCommand(fixtureDDL("0033_incident_labels.sql", /^ALTER TABLE argus\.incident_state_events\b/));
    await ch().chCommand(`INSERT INTO incidents
      (incident_id, created_at, updated_at, rule_id, rule_title, level, tags, status, first_ts, last_ts)
      VALUES ({id:String}, now(), now(), 'fixture-since', 'Since fixture', 'high', [], 'new', now64(3), now64(3))`, { id });
    await ch().chCommand(`INSERT INTO incident_state_events
      (event_id, incident_id, revision, changed_at, actor, kind, status, owner, reason,
       disposition, escalate, severity_correct, blind, labeled_by_human)
      SELECT generateUUIDv4(), {id:String}, number + 1,
        toDateTime64('2099-01-01 00:00:00.123', 3, 'UTC') + toIntervalMillisecond(number),
        'analyst', 'status', 'closed', 'analyst', 'independent observation',
        'benign_authorized', false, true, true, true FROM numbers(2)`, { id });

    const timestamps = async (since: string) => (await queries().incidentLabels(since, 10)).map((row) => row.changed_at);
    assert.deepEqual(await timestamps("2099-01-01T00:00:00.123000000Z"), [
      "2099-01-01 00:00:00.123", "2099-01-01 00:00:00.124",
    ], "положительный контроль: точное равенство включительно, обе метки существуют");

    for (const since of ["2099-01-01T00:00:00.1231Z", "2099-01-01T00:00:00.123000001Z"]) {
      await t.test(since, async () => {
        assert.deepEqual(await timestamps(since), ["2099-01-01 00:00:00.124"],
          "метка .123 находится раньше since и не должна попасть в выгрузку");
      });
    }
  } finally {
    database = "default";
    if (created) await ch().chCommand(`DROP DATABASE ${db} SYNC`);
  }
});
