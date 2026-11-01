// Регрессии listPersons на отдельной временной БД ClickHouse 24.8.
// Никакого SQL-эмулятора: счётчики сравниваются с независимыми GROUP BY.
// Запуск: npm test с ARGUS_TEST_CLICKHOUSE_URL изолированного тестового сервера.
import { after, before, test, type TestContext } from "node:test";
import assert from "node:assert/strict";
import { randomBytes } from "node:crypto";
import { ch, liveSkip as skip, serializeLiveFile } from "./_ch-live";
import { chTs } from "../src/lib/shared/log-query";
import { parseIdentitiesDoc } from "../src/lib/shared/actors";
import { PR74_NOW, PR74_WINDOW, fixtureAlias, importDocument, longIncidentQueryFixture, type ActivityFixture } from "./_actors-pr74-fixtures";

serializeLiveFile({ before, after });

/* eslint-disable @typescript-eslint/no-require-imports -- _ch-live задаёт env до загрузки клиента */
const actors = () => require("../src/lib/actors") as typeof import("../src/lib/actors");
/* eslint-enable @typescript-eslint/no-require-imports */

async function withDatabase(t: TestContext, run: () => Promise<void>) {
  const db = `argus_pr74_activity_${randomBytes(6).toString("hex")}`;
  let database = "default", created = false;
  const nativeFetch = globalThis.fetch;
  t.mock.method(globalThis, "fetch", (input: URL | string | Request, init?: RequestInit) => {
    const url = new URL(input instanceof Request ? input.url : String(input));
    url.searchParams.set("database", database);
    url.searchParams.set("max_threads", "1");
    url.searchParams.set("max_block_size", "512");
    url.searchParams.set("max_memory_usage", String(256 * 1024 * 1024));
    url.searchParams.set("max_execution_time", "10");
    // max_result_rows/result_overflow_mode остаются ровно из listPersons.
    return nativeFetch(url, { ...init, signal: AbortSignal.timeout(15_000) });
  });
  try {
    created = true;
    await ch().chCommand(`CREATE DATABASE ${db}`);
    database = db;
    // Только колонки, читаемые listPersons, с теми же типами. Memory убирает
    // TTL/фоновые слияния из теста HTTP и агрегации; реальные данные не нужны.
    await ch().chCommand(`CREATE TABLE identities (person_id String, display String, kind LowCardinality(String),
      team String, note String, updated_at DateTime64(3, 'UTC'), deleted UInt8) ENGINE = Memory`);
    await ch().chCommand(`CREATE TABLE identity_aliases (person_id String, alias_kind LowCardinality(String),
      alias_value String, valid_from DateTime64(3, 'UTC'), valid_to Nullable(DateTime64(3, 'UTC')),
      source LowCardinality(String), confidence Float32, note String, updated_at DateTime64(3, 'UTC'), deleted UInt8) ENGINE = Memory`);
    await ch().chCommand(`CREATE TABLE events (ts DateTime64(3, 'UTC'), actor_name String,
      src_ip String, node String) ENGINE = Memory`);
    await ch().chCommand(`CREATE TABLE incidents_current (actor_name String,
      first_ts DateTime64(3, 'UTC'), created_at DateTime('UTC')) ENGINE = Memory`);
    await run();
  } finally {
    database = "default";
    if (created) await ch().chCommand(`DROP DATABASE IF EXISTS ${db} SYNC`);
  }
}

async function insertFixture(fixture: ActivityFixture) {
  assert.equal(parseIdentitiesDoc(importDocument(fixture)).ok, true);
  const json = (rows: object[]) => rows.map((r) => JSON.stringify(r)).join("\n");
  const version = { updated_at: chTs(PR74_NOW - 1000), deleted: 0 };
  await ch().chCommand(`INSERT INTO identities FORMAT JSONEachRow\n${json(fixture.map((p) => ({
    person_id: p.id, display: p.id, kind: "person", team: "", note: "", ...version,
  })))}`);
  await ch().chCommand(`INSERT INTO identity_aliases FORMAT JSONEachRow\n${json(fixture.flatMap((p) => p.aliases.map((a) => ({
    person_id: p.id, alias_kind: a.kind, alias_value: a.value, valid_from: a.valid_from,
    valid_to: a.valid_to, source: a.source, confidence: a.confidence, note: a.note, ...version,
  }))))}`);
}

test("PR #74: GROUP BY hits не обрезает активность при >20000 сочетаний классов", { skip, timeout: 60_000 }, async (t) => {
  await withDatabase(t, async () => {
    const width = 300;
    const fixture: ActivityFixture = Array.from({ length: width }, (_, i) => [
      { id: `actor-${i}`, aliases: [fixtureAlias(`actor-${i}`, "uid", `actor-${i}`)] },
      { id: `host-${i}`, aliases: [fixtureAlias(`host-${i}`, "host", `host-${i}`)] },
    ]).flat();
    await insertFixture(fixture);
    // 600 персон, 600 алиасов, 90000 событий и 90000 разных hits=[uid,host].
    // Старый GROUP BY p возвращал 600 строк. На каждую персону приходится 300.
    await ch().chCommand(`INSERT INTO events (ts, actor_name, node)
      SELECT parseDateTime64BestEffort({start:String}, 3, 'UTC') + toIntervalMillisecond(number),
        concat('actor-', toString(intDiv(number, {width:UInt64}))),
        concat('host-', toString(number % {width:UInt64})) FROM numbers({n:UInt64})`,
      { start: chTs(PR74_WINDOW.fromMs + 3600_000), width, n: width * width });
    type Reference = { id: string; n: string | number; last_ts: string };
    const expected = new Map<string, Reference>();
    for (const column of ["actor_name", "node"] as const) {
      const rows = await ch().chQuery<Reference>(`SELECT ${column} AS id, count() AS n,
        toString(max(ts)) AS last_ts FROM events GROUP BY ${column}`);
      assert.equal(rows.length, width);
      for (const row of rows) {
        assert.equal(Number(row.n), width, "контрольная агрегация видит все события");
        expected.set(row.id, row);
      }
    }
    const list = await actors().listPersons("7d", PR74_NOW);
    assert.equal(list.length, width * 2);
    assert.equal(list.reduce((n, p) => n + p.events, 0), 2 * width * width,
      "HTTP 200 с частичным GROUP BY hits нельзя выдавать за полные счётчики");
    for (const person of list) {
      const reference = expected.get(person.person_id);
      assert.ok(reference);
      assert.deepEqual({ n: person.events, last_ts: person.last_ts },
        { n: Number(reference.n), last_ts: reference.last_ts }, person.person_id);
    }
  });
});

test("PR #74: 100 персон по 8 uid читаются, когда SQL инцидентов длиннее 128 КиБ", { skip, timeout: 60_000 }, async (t) => {
  await withDatabase(t, async () => {
    await insertFixture(longIncidentQueryFixture());
    const list = await actors().listPersons("7d", PR74_NOW);
    assert.equal(list.length, 100);
    assert.ok(list.every((p) => p.aliases === 8 && p.events === 0 && p.incidents === 0 && p.last_ts === null));
  });
});
