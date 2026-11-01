// OpenAPI /api/incidents/labels: при truncated продолжить с последнего changed_at.
// Две метки одной миллисекунды не должны делать следующую строку недостижимой.
// Настоящий incidentLabels в отдельной БД; SQL и ответы ClickHouse не подменены.
import { after, before, test } from "node:test";
import assert from "node:assert/strict";
import { randomBytes } from "node:crypto";
import { ch, liveSkip as skip, migrationStatements, serializeLiveFile } from "./_ch-live";

serializeLiveFile({ before, after });

/* eslint-disable @typescript-eslint/no-require-imports -- окружение соединения установлено _ch-live */
const queries = () => require("../src/lib/argus-queries") as typeof import("../src/lib/argus-queries");
/* eslint-enable @typescript-eslint/no-require-imports */

test("incidentLabels: продолжение с last.changed_at достигает следующей метки при равном времени", { skip }, async (t) => {
  const db = `argus_labels_page_${randomBytes(6).toString("hex")}`;
  const since = "2099-01-01 00:00:00.123";
  const ids = ["INC-410000001", "INC-410000002"];
  let database = "default", created = false;
  const nativeFetch = globalThis.fetch;
  t.mock.method(globalThis, "fetch", async (input: URL | string | Request, init?: RequestInit) => {
    const url = new URL(input instanceof Request ? input.url : String(input));
    // Только выбор отдельной fixture-БД. Сам production запрос исполняется сервером.
    url.searchParams.set("database", database);
    return nativeFetch(url, init);
  });
  const fixtureDDL = (file: string, pattern: RegExp) => {
    const stmt = migrationStatements(file).find((sql) => pattern.test(sql));
    assert.ok(stmt, `DDL должен браться из production миграции ${file}`);
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
      SELECT concat('INC-', toString(410000001 + number)), now(), now(), 'fixture-labels-page', 'Labels page fixture',
        'high', ['attack.t1110'], 'new', now64(3), now64(3) FROM numbers(2)`);
    await ch().chCommand(`INSERT INTO incident_state_events
      (event_id, incident_id, revision, changed_at, actor, kind, status, owner, reason,
       disposition, escalate, severity_correct, blind, labeled_by_human)
      SELECT generateUUIDv4(), concat('INC-', toString(410000001 + number)), 1,
        parseDateTime64BestEffort({since:String}, 3, 'UTC'), 'analyst', 'status', 'closed', 'analyst',
        concat('independent label ', toString(number)), 'benign_authorized', false, true, true, true
      FROM numbers(2)`, { since });

    // Положительный контроль: обе человеческие метки существуют и читаются
    // тем же запросом; различает их incident_id, а не время или посторонняя БД.
    const complete = await queries().incidentLabels(since, 10);
    assert.deepEqual(complete.map((row) => row.incident_id), ids);
    assert.ok(complete.every((row) => row.changed_at === since && row.rule_id === "fixture-labels-page"));

    const pages: { since: string; ids: string[]; changedAt: string[] }[] = [];
    const seen = new Set<string>();
    let from = since;
    // Только документированные since/limit. Передаём changed_at ровно из
    // предыдущего ответа, напрямую в function: API-regex не маскирует SQL-сбой.
    for (let attempt = 0; attempt < 3; attempt++) {
      const page = await queries().incidentLabels(from, 1);
      assert.equal(page.length, 1, "допустимый limit=1 соблюдается");
      pages.push({ since: from, ids: page.map((row) => row.incident_id), changedAt: page.map((row) => row.changed_at) });
      for (const row of page) seen.add(row.incident_id);
      if (seen.size === ids.length) break;
      from = page.at(-1)!.changed_at;
    }
    t.diagnostic(JSON.stringify({ complete: complete.map((row) => row.incident_id), limit: 1, pages }));
    assert.deepEqual([...seen].sort(), ids,
      "продолжение с last.changed_at повторяет первую метку; сдвиг времени вперёд потеряет вторую метку той же миллисекунды");
  } finally {
    database = "default";
    if (created) await ch().chCommand(`DROP DATABASE ${db} SYNC`);
  }
});
