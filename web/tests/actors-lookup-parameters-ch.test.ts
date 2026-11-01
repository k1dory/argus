// PR #17: query-looking input must stay a literal in both the event predicate
// and the new alias exclusion subquery. Execute the actual ClickHouse queries.
import { after, before, test } from "node:test";
import assert from "node:assert/strict";
import { randomBytes } from "node:crypto";
import { applyAllMigrations, ch, liveSkip as skip, serializeLiveFile } from "./_ch-live";
import { chTs } from "../src/lib/shared/log-query";
import type { PersonInput } from "../src/lib/shared/actors";

serializeLiveFile({ before, after });

/* eslint-disable @typescript-eslint/no-require-imports -- _ch-live sets the connection before actors loads */
const actors = () => require("../src/lib/actors") as typeof import("../src/lib/actors");
/* eslint-enable @typescript-eslint/no-require-imports */

test("lookup: SQL syntax, HTTP delimiters and escapes in a value remain literal", { skip }, async (t) => {
  await applyAllMigrations();
  const run = randomBytes(6).toString("hex");
  const prefix = `lookup-param-${run}-`;
  const source = `lookup.parameter.${run}`;
  const now = Date.now();
  const ts = chTs(now - 3600_000);
  const values = [
    `Lookup-${run}' OR 1 = 1 --`,
    `Lookup-${run}\\' OR 1 = 1 --`,
    `Lookup-${run}'); SELECT 1; --`,
    `Lookup-${run}&param_v=decoy&max_result_rows=0`,
    `Lookup-${run}{v:String}\\N`,
    `Lookup-${run}\\logs\\auth\tline\nend`,
  ];
  const persons: PersonInput[] = values.map((value, i) => ({
    person_id: `${prefix}${i}`, display: "Parameter fixture", kind: "person", team: "fixture", note: "",
    aliases: [{ kind: "uid", value, valid_from: chTs(now - 86400_000), valid_to: null, confidence: 1, note: "" }],
  }));

  try {
    await actors().upsertIdentities(persons, "fixture");
    // A constant-true predicate must be caught even on an otherwise empty DB.
    const events = [...values, `decoy-${run}`].map((actor_name) => ({
      ts, source, source_class: "identity", action: "auth.login", actor_name, node: `neutral-node-${run}`,
    }));
    await ch().chCommand(`INSERT INTO events FORMAT JSONEachRow\n${events.map((e) => JSON.stringify(e)).join("\n")}`);

    for (const [i, value] of values.entries()) {
      await t.test(JSON.stringify(value), async () => {
        const resolution = await actors().resolveAlias(value, now);
        assert.equal(resolution.status, "resolved");
        assert.deepEqual(resolution.matches.map((m) => m.person_id), [`${prefix}${i}`]);
        const history = await actors().aliasHistory(value);
        assert.deepEqual(history.map((a) => [a.person_id, a.value]), [[`${prefix}${i}`, value]]);
        const seen = await actors().aliasSightings(value, "24h", now);
        assert.equal(seen.kind, "actor");
        assert.deepEqual(seen.rows.map((r) => [r.source, r.who, r.events]), [[source, value, 1]],
          "the value must neither alter SQL/HTTP parameters nor select the decoy");
      });
    }
  } finally {
    await ch().chCommand("ALTER TABLE events DELETE WHERE source = {source:String} SETTINGS mutations_sync = 1", { source });
    for (const table of ["identity_aliases", "identities"]) {
      await ch().chCommand(`ALTER TABLE ${table} DELETE WHERE startsWith(person_id, {prefix:String}) SETTINGS mutations_sync = 1`, { prefix });
    }
  }
});
