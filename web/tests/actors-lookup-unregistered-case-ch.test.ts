// PR #17: exclusion of known aliases must not make uid/sid/peer matching
// depend on whether every other spelling has been imported into the directory.
// Run production SQL against ClickHouse; do not emulate NOT IN in a fetch mock.
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

test("lookup: an unregistered case variant must not join a uid/sid/peer owner's events", { skip }, async (t) => {
  await applyAllMigrations();
  const run = randomBytes(6).toString("hex");
  const prefix = `lookup-gap-${run}-`;
  const source = `lookup.case-gap.${run}`;
  const now = Date.now();
  const ts = chTs(now - 3600_000);
  const scenarios = (["uid", "sid", "peer"] as const).map((kind) => ({
    kind,
    upper: `CaseKey-${kind}-${run}`,
    lower: `casekey-${kind}-${run}`,
    unregistered: `cAsEkEy-${kind}-${run}`,
    owner: `${prefix}${kind}-upper`,
    other: `${prefix}${kind}-lower`,
  }));
  const persons: PersonInput[] = scenarios.flatMap(({ kind, upper, lower, owner, other }) =>
    [[owner, upper], [other, lower]].map(([person_id, value]) => ({
      person_id, display: person_id, kind: "person" as const, team: "fixture", note: "",
      aliases: [{ kind, value, valid_from: chTs(now - 86400_000), valid_to: null, confidence: 1, note: "" }],
    })),
  );

  try {
    await actors().upsertIdentities(persons, "fixture");
    const events = scenarios.flatMap(({ upper, lower, unregistered }) =>
      [upper, lower, unregistered].map((actor_name) => ({
        ts, source, source_class: "identity", action: "auth.login", actor_name,
        // No host match can account for the extra event.
        node: `neutral-node-${run}`,
      })),
    );
    await ch().chCommand(`INSERT INTO events FORMAT JSONEachRow\n${events.map((e) => JSON.stringify(e)).join("\n")}`);

    for (const { kind, upper, lower, unregistered, owner, other } of scenarios) {
      for (const [value, personId] of [[upper, owner], [lower, other]]) {
        await t.test(`${kind}: ${value}`, async () => {
          const resolution = await actors().resolveAlias(value, now);
          assert.equal(resolution.status, "resolved");
          assert.deepEqual(resolution.matches.map((m) => m.person_id), [personId]);
          const history = await actors().aliasHistory(value);
          assert.deepEqual(history.map((a) => a.person_id), [personId]);
          assert.equal((await actors().resolveAlias(unregistered, now)).status, "unbound",
            "the third spelling has no login/email or case-sensitive alias");

          const seen = await actors().aliasSightings(value, "24h", now);
          assert.equal(seen.kind, "actor");
          assert.deepEqual(seen.rows.map((r) => r.who), [value],
            `${kind}: ${unregistered} is a different identifier even without a directory entry`);
          assert.equal(seen.rows[0].source, source);
          assert.equal(seen.rows[0].events, 1);
        });
      }
    }
  } finally {
    await ch().chCommand("ALTER TABLE events DELETE WHERE source = {source:String} SETTINGS mutations_sync = 1", { source });
    for (const table of ["identity_aliases", "identities"]) {
      await ch().chCommand(`ALTER TABLE ${table} DELETE WHERE startsWith(person_id, {prefix:String}) SETTINGS mutations_sync = 1`, { prefix });
    }
  }
});
