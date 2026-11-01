// uid/sid/peer are case-sensitive identifiers. Owner/history and sightings
// must agree even when another person's identifier differs only in case.
// Use the real ClickHouse query; a fetch mock cannot validate this predicate.
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

test("lookup: uid/sid/peer must not mix identifiers that differ only in case", { skip }, async (t) => {
  await applyAllMigrations();
  const run = randomBytes(6).toString("hex");
  const prefix = `lookup-case-${run}-`;
  const source = `lookup.case.${run}`;
  const now = Date.now();
  const ts = chTs(now - 3600_000);
  const scenarios = (["uid", "sid", "peer"] as const).map((kind) => ({
    kind, upper: `CaseKey-${kind}-${run}`, lower: `casekey-${kind}-${run}`,
    owner: `${prefix}${kind}-upper`, other: `${prefix}${kind}-lower`,
  }));
  const persons: PersonInput[] = scenarios.flatMap(({ kind, upper, lower, owner, other }) =>
    [[owner, upper], [other, lower]].map(([person_id, value]) => ({
      person_id, display: person_id, kind: "person" as const, team: "fixture", note: "",
      aliases: [{ kind, value, valid_from: chTs(now - 86400_000), valid_to: null, confidence: 1, note: "" }],
    })),
  );
  try {
    await actors().upsertIdentities(persons, "fixture");
    for (const { upper, lower } of scenarios) {
      for (const actor of [upper, lower]) {
        await ch().chCommand(`INSERT INTO events (ts, source, source_class, action, actor_name, node)
          VALUES (parseDateTime64BestEffort({ts:String}, 3, 'UTC'), {source:String}, 'identity', 'auth.login', {actor:String}, 'case-fixture-node')`,
        { ts, source, actor });
      }
    }
    for (const { kind, upper, owner, other } of scenarios) {
      await t.test(kind, async () => {
        const resolution = await actors().resolveAlias(upper, now);
        assert.equal(resolution.status, "resolved");
        assert.deepEqual(resolution.matches.map((m) => m.person_id), [owner], "owner lookup is case-sensitive");
        const history = await actors().aliasHistory(upper);
        assert.deepEqual(history.map((a) => a.person_id), [owner], "history excludes the other identifier");
        const seen = await actors().aliasSightings(upper, "24h", now);
        assert.equal(seen.kind, "actor");
        assert.deepEqual(seen.rows.map((r) => r.who), [upper],
          `${kind}: sightings must not include events belonging to ${other}`);
        assert.equal(seen.rows[0].source, source);
        assert.equal(seen.rows[0].events, 1);
      });
    }
  } finally {
    await ch().chCommand("ALTER TABLE events DELETE WHERE source = {source:String} SETTINGS mutations_sync = 1", { source });
    for (const table of ["identity_aliases", "identities"]) {
      await ch().chCommand(`ALTER TABLE ${table} DELETE WHERE startsWith(person_id, {prefix:String}) SETTINGS mutations_sync = 1`, { prefix });
    }
  }
});
