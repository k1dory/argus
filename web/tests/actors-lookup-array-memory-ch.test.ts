// PR #22: a fixed-size SQL string must not trade max_query_size failures for
// an events x fx x ci expansion inside nested arrayExists. Run the production
// query in a disposable database, with a small server-side memory ceiling.
import { after, before, test } from "node:test";
import assert from "node:assert/strict";
import { randomBytes } from "node:crypto";
import { ch, liveSkip as skip, migrationStatements, serializeLiveFile } from "./_ch-live";
import { chTs } from "../src/lib/shared/log-query";

serializeLiveFile({ before, after });

/* eslint-disable @typescript-eslint/no-require-imports -- _ch-live configures the connection first */
const actors = () => require("../src/lib/actors") as typeof import("../src/lib/actors");
/* eslint-enable @typescript-eslint/no-require-imports */

test("PR #22: overlapping owner intervals do not multiply lookup memory by ci x fx", { skip }, async (t) => {
  const run = randomBytes(6).toString("hex");
  const db = `argus_lookup_memory_${run}`;
  const owner = `pr22-memory-${run}`;
  const lower = `lookup-memory-${run}`;
  const mixed = lower.toUpperCase();
  const source = `lookup.memory.${run}`;
  const node = `neutral-node-${run}`;
  const now = Date.now();
  const eventCount = 1024;
  const intervalCount = 128;
  const memoryLimit = 128 * 1024 * 1024;
  let database = "default", created = false;

  const nativeFetch = globalThis.fetch;
  t.mock.method(globalThis, "fetch", async (input: URL | string | Request, init?: RequestInit) => {
    const url = new URL(input instanceof Request ? input.url : String(input));
    // Only routing and resource settings change. SQL, bound values and server
    // responses remain real. Do not require a multi-GB allocation to regress.
    url.searchParams.set("database", database);
    url.searchParams.set("max_memory_usage", String(memoryLimit));
    url.searchParams.set("max_threads", "1");
    url.searchParams.set("max_block_size", String(eventCount));
    url.searchParams.set("max_execution_time", "10");
    return nativeFetch(url, init);
  });

  const createTable = async (file: string, table: string) => {
    const statement = migrationStatements(file).find((sql) => sql.startsWith(`CREATE TABLE IF NOT EXISTS argus.${table}\n`));
    assert.ok(statement, `${table} must use the production schema from ${file}`);
    await ch().chCommand(statement.replaceAll("argus.", `${db}.`));
  };
  const addIntervals = async (kind: "login" | "uid", start: number, count: number) => {
    // Explicit, distinct valid_from values are different full alias keys;
    // background ReplacingMergeTree merges cannot collapse these intervals.
    // All intervals cover every event and belong to the SAME confirmed owner.
    await ch().chCommand(`INSERT INTO identity_aliases
      (person_id, alias_kind, alias_value, valid_from, valid_to, source, confidence, note, updated_at, deleted)
      SELECT {owner:String}, {kind:String}, {value:String},
        parseDateTime64BestEffort({base:String}, 3, 'UTC') + toIntervalMillisecond(number),
        NULL, 'fixture', 0.5, '', parseDateTime64BestEffort({updated:String}, 3, 'UTC'), 0
      FROM numbers({start:UInt64}, {count:UInt64})`, {
      owner, kind, value: kind === "login" ? lower : mixed,
      base: chTs(now - 2 * 3600_000), updated: chTs(now - 1000), start, count,
    });
  };
  const expectAllEvents = async () => {
    const seen = await actors().aliasSightings(lower, "24h", now);
    assert.equal(seen.kind, "actor");
    assert.deepEqual(seen.rows.map((row) => ({
      source: row.source, who: row.who, where: row.where, events: row.events,
    })), [{ source, who: mixed, where: node, events: eventCount }],
    "adding confirmed intervals of the same owner must retain every event within the same memory budget");
  };

  try {
    await ch().chCommand(`CREATE DATABASE ${db}`);
    created = true;
    database = db;
    await createTable("0005_events_incidents.sql", "events");
    await createTable("0026_identities.sql", "identities");
    await createTable("0026_identities.sql", "identity_aliases");
    await actors().upsertIdentities([{
      person_id: owner, display: owner, kind: "person", team: "fixture", note: "", aliases: [],
    }], "fixture");
    await ch().chCommand(`INSERT INTO events (ts, source, source_class, action, actor_name, node)
      SELECT parseDateTime64BestEffort({base:String}, 3, 'UTC') + toIntervalMillisecond(number),
        {source:String}, 'identity', 'auth.login', {mixed:String}, {node:String}
      FROM numbers({count:UInt64})`, {
      base: chTs(now - 3600_000), source, mixed, node, count: eventCount,
    });

    await addIntervals("login", 0, 1);
    await addIntervals("uid", 0, 1);
    await expectAllEvents();

    await addIntervals("login", 1, intervalCount - 1);
    await expectAllEvents(); // Control: a larger ci alone still fits the budget.

    await addIntervals("uid", 1, intervalCount - 1);
    const counts = await ch().chQuery<{ alias_kind: string; n: string | number }>(
      "SELECT alias_kind, count() AS n FROM identity_aliases GROUP BY alias_kind ORDER BY alias_kind");
    assert.deepEqual(counts.map((row) => [row.alias_kind, Number(row.n)]),
      [["login", intervalCount], ["uid", intervalCount]]);
    const resolved = await actors().resolveAlias(mixed, now - 3600_000);
    assert.equal(resolved.status, "resolved");
    assert.deepEqual(resolved.matches.map((match) => match.person_id), [owner]);

    // Only 256 alias rows and 1024 events, but eager nested-array evaluation
    // expands 1024 * 128 * 128 = 16,777,216 tuple elements. An early failure at
    // the 128 MiB ceiling is a regression, not an expected exception to swallow.
    await expectAllEvents();
  } finally {
    database = "default";
    if (created) await ch().chCommand(`DROP DATABASE ${db} SYNC`);
  }
});
