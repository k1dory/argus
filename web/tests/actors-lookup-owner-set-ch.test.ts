// PR #22 re-review: exercise the owner-set predicate and the merged #10
// prefilter together. Expected event sets are explicit; production SQL and
// ClickHouse responses are never replaced by an emulation of hasAll.
import { after, before, test } from "node:test";
import assert from "node:assert/strict";
import { randomBytes } from "node:crypto";
import { ch, liveSkip as skip, migrationStatements, serializeLiveFile } from "./_ch-live";
import { chTs } from "../src/lib/shared/log-query";

serializeLiveFile({ before, after });

/* eslint-disable @typescript-eslint/no-require-imports -- _ch-live configures the connection first */
const actors = () => require("../src/lib/actors") as typeof import("../src/lib/actors");
/* eslint-enable @typescript-eslint/no-require-imports */

test("PR #22: owner sets preserve event boundaries and the actor-key prefilter", { skip }, async (t) => {
  const run = randomBytes(6).toString("hex");
  const db = `argus_lookup_owner_set_${run}`;
  const now = Date.now();
  const from = now - 86_400_000;
  const at = now - 3600_000;
  const neutral = `neutral-${run}`;
  let database = "default", created = false;
  const nativeFetch = globalThis.fetch;
  t.mock.method(globalThis, "fetch", async (input: URL | string | Request, init?: RequestInit) => {
    const url = new URL(input instanceof Request ? input.url : String(input));
    url.searchParams.set("database", database);
    url.searchParams.set("max_threads", "1");
    url.searchParams.set("max_memory_usage", String(128 * 1024 * 1024));
    url.searchParams.set("max_execution_time", "10");
    if (typeof init?.body === "string" && /\bFROM events\b/.test(init.body)) {
      // New parts contain the real 0032 index. Removing/bypassing the #10
      // prefilter must fail as well as returning an incorrect event set.
      url.searchParams.set("force_data_skipping_indices", "idx_actor_keys");
    }
    return nativeFetch(url, init);
  });

  type Spelling = "lower" | "upper" | "mixed";
  type Entry = {
    owner: string; kind: "login" | "email" | "uid" | "sid" | "peer";
    spelling?: Spelling; from?: number; to?: number | null;
    confidence?: number; deleted?: 0 | 1;
  };
  const spellings = (tag: string) => {
    const lower = `lookup-${tag}-${run}@example.test`;
    return { lower, upper: lower.toUpperCase(), mixed: `Lookup${lower.slice(6)}` };
  };
  const insert = async (table: "events" | "identity_aliases", rows: object[]) => {
    if (rows.length) await ch().chCommand(`INSERT INTO ${table} FORMAT JSONEachRow\n${rows.map((row) => JSON.stringify(row)).join("\n")}`);
  };
  const addAliases = async (names: Record<Spelling, string>, entries: Entry[]) => {
    await insert("identity_aliases", entries.map((entry) => ({
      person_id: `owner-${run}-${entry.owner}`, alias_kind: entry.kind,
      alias_value: names[entry.spelling ?? (entry.kind === "login" || entry.kind === "email" ? "lower" : "upper")],
      valid_from: chTs(entry.from ?? from), valid_to: entry.to == null ? null : chTs(entry.to),
      source: "fixture", confidence: entry.confidence ?? 0.5, note: "",
      updated_at: chTs(now - 1000), deleted: entry.deleted ?? 0,
    })));
  };
  const event = (source: string, actor_name: string, action = "auth.login", ts = at, node = neutral, src_ip = "192.0.2.17") =>
    ({ ts: chTs(ts), source, source_class: "identity", action, actor_name, node, src_ip });

  try {
    await ch().chCommand(`CREATE DATABASE ${db}`);
    created = true;
    database = db;
    for (const [file, table] of [["0005_events_incidents.sql", "events"], ["0026_identities.sql", "identity_aliases"]]) {
      const statement = migrationStatements(file).find((sql) => sql.startsWith(`CREATE TABLE IF NOT EXISTS argus.${table}\n`));
      assert.ok(statement, `production schema for ${table}`);
      await ch().chCommand(statement.replaceAll("argus.", `${db}.`));
    }
    const index = migrationStatements("0032_events_actor_keys_index.sql").find((sql) => sql.startsWith("ALTER TABLE argus.events ADD INDEX"));
    assert.ok(index, "production actor-key index");
    await ch().chCommand(index.replaceAll("argus.", `${db}.`));

    const all: Spelling[] = ["lower", "upper", "mixed"];
    const cases: { name: string; aliases: Entry[]; want: Spelling[] }[] = [
      { name: "both-empty", aliases: [], want: ["lower"] },
      { name: "empty-ci", aliases: [{ owner: "b", kind: "uid" }], want: ["lower"] },
      { name: "empty-fx", aliases: [{ owner: "a", kind: "login" }], want: all },
      { name: "ci-empty-at-event", aliases: [{ owner: "a", kind: "login", to: at }], want: ["lower"] },
      { name: "held-ci", aliases: [{ owner: "a", kind: "login", confidence: 0.49 }], want: ["lower"] },
      { name: "foreign-among-duplicates", aliases: [
        { owner: "a", kind: "login" }, { owner: "a", kind: "email" },
        { owner: "a", kind: "uid" }, { owner: "a", kind: "peer" }, { owner: "b", kind: "sid" },
      ], want: ["lower", "mixed"] },
      { name: "all-owners-present", aliases: [
        { owner: "a", kind: "login" }, { owner: "b", kind: "email" },
        { owner: "a", kind: "uid" }, { owner: "a", kind: "peer" }, { owner: "b", kind: "sid" },
      ], want: all },
      { name: "foreign-other-spelling", aliases: [
        { owner: "a", kind: "login" }, { owner: "b", kind: "uid", spelling: "mixed" },
      ], want: ["lower", "upper"] },
      { name: "held-foreign-owner", aliases: [
        { owner: "a", kind: "login" }, { owner: "b", kind: "uid", confidence: 0.49 },
      ], want: all },
      { name: "deleted-foreign-owner", aliases: [
        { owner: "a", kind: "login" }, { owner: "b", kind: "sid", deleted: 1 },
      ], want: all },
    ];
    for (const scenario of cases) {
      await t.test(scenario.name, async () => {
        const names = spellings(scenario.name);
        const source = `lookup.owner-set.${run}.${scenario.name}`;
        await addAliases(names, scenario.aliases);
        await insert("events", [
          // Two physical events per spelling must stay two, regardless of
          // repeated owners or the number of overlapping alias kinds.
          ...Object.values(names).flatMap((name) => [event(source, name), event(source, name, "auth.login", at + 1)]),
          event(source, neutral, "host.match", at, names.upper),
          event(source, neutral, "src-only.decoy", at, neutral, names.lower),
        ]);
        const seen = await actors().aliasSightings(names.lower, "24h", now);
        assert.equal(seen.kind, "actor");
        assert.ok(seen.rows.every((row) => row.source === source));
        const project = (row: (typeof seen.rows)[number]) => [row.action, row.who, row.where, row.events];
        assert.deepEqual(seen.rows.map(project).sort(), [
          ...scenario.want.map((name) => ["auth.login", names[name], neutral, 2]),
          ["host.match", neutral, names.upper, 1],
        ].sort(), "the index may admit a src_ip candidate, but only the full predicate may return it");
      });
    }

    await t.test("half-open owner handoff, gaps and lookup-window endpoints", async () => {
      const names = spellings("timeline");
      const source = `lookup.owner-set.${run}.timeline`;
      await addAliases(names, [
        { owner: "a", kind: "login", from: at - 4, to: at },
        { owner: "b", kind: "email", from: at + 1, to: at + 4 },
        { owner: "a", kind: "uid", from: at - 3, to: at },
        { owner: "b", kind: "sid", from: at, to: at + 5 },
        { owner: "c", kind: "peer", from: at + 2, to: at + 3 },
      ]);
      await insert("events", [
        ...[-5, -4, -3, -1, 0, 1, 2, 3, 4, 5].map((offset) => event(source, names.upper, `point.${offset}`, at + offset)),
        event(source, names.lower, "window.before", from - 1),
        event(source, names.lower, "window.from", from),
        event(source, names.lower, "window.to", now),
        // Matching node remains an independent reason to show a sighting,
        // including while actor_name has a foreign confirmed exact owner.
        event(source, names.upper, "host.foreign-actor", at + 2, names.upper),
      ]);
      const seen = await actors().aliasSightings(names.lower, "24h", now);
      assert.ok(seen.rows.every((row) => row.source === source && row.events === 1));
      assert.deepEqual(seen.rows.map((row) => row.action).sort(), [
        "point.-4", "point.-3", "point.-1", "point.1", "point.3", "window.from", "host.foreign-actor",
      ].sort(), "from is inclusive, to is exclusive, and an owner's past/future login does not cover a gap");
    });

    await t.test("formatted phone keeps the canonical prefilter key without ci/fx", async () => {
      const digits = String(parseInt(run, 16) % 10_000_000).padStart(7, "0");
      const canonical = `+1555${digits}`;
      const formatted = `+1 (555) ${digits.slice(0, 3)}-${digits.slice(3)}`;
      const source = `lookup.owner-set.${run}.phone`;
      await insert("events", [event(source, canonical), event(source, neutral, "src-only.decoy", at, neutral, canonical)]);
      const seen = await actors().aliasSightings(formatted, "24h", now);
      assert.deepEqual(seen.rows.map((row) => [row.source, row.who, row.events]), [[source, canonical, 1]]);
    });
  } finally {
    database = "default";
    if (created) await ch().chCommand(`DROP DATABASE ${db} SYNC`);
  }
});
