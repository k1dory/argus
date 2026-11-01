// PR #17 controls: registration must use the latest deleted flag per full
// identity_aliases key, regardless of INSERT order or background merges.
import { after, before, test } from "node:test";
import assert from "node:assert/strict";
import { randomBytes } from "node:crypto";
import { applyAllMigrations, ch, liveSkip as skip, serializeLiveFile } from "./_ch-live";
import { chTs } from "../src/lib/shared/log-query";

serializeLiveFile({ before, after });

/* eslint-disable @typescript-eslint/no-require-imports -- _ch-live configures ClickHouse before actors loads */
const actors = () => require("../src/lib/actors") as typeof import("../src/lib/actors");
/* eslint-enable @typescript-eslint/no-require-imports */

test("PR #17: case-fold registration follows tombstones and restorations per alias key", { skip }, async (t) => {
  await applyAllMigrations();
  const run = randomBytes(6).toString("hex");
  const prefix = `pr17-version-${run}-`;
  const source = `lookup.registration-version.${run}`;
  const now = Date.now();
  const hour = 3600_000;
  const validFrom = chTs(now - 24 * hour);

  try {
    for (const kind of ["login", "email"] as const) {
      await t.test(kind, async (caseTest) => {
        const value = `caseversion-${kind}-${run}${kind === "email" ? "@example.test" : ""}`;
        const names = [value, value.toUpperCase(), `Caseversion${value.slice("caseversion".length)}`];
        const personId = `${prefix}${kind}`;
        await actors().upsertIdentities([{
          person_id: personId, display: personId, kind: "person", team: "fixture", note: "", aliases: [],
        }], "fixture");
        const rows = names.map((actor_name) => ({
          ts: chTs(now - hour), source, source_class: "identity", action: "auth.login", actor_name,
          node: `neutral-node-${run}`,
        }));
        await ch().chCommand(`INSERT INTO events FORMAT JSONEachRow\n${rows.map((r) => JSON.stringify(r)).join("\n")}`);

        const version = async (revision: number, deleted: 0 | 1, patch: Record<string, string> = {}) => {
          const row = {
            person_id: personId, alias_kind: kind, alias_value: value,
            valid_from: validFrom, valid_to: null, source: "fixture", confidence: 1, note: "",
            // Explicit, distinct versions keep the test independent of clock
            // resolution, insert order and ReplacingMergeTree merge timing.
            updated_at: chTs(now - 20_000 + revision * 1000), deleted, ...patch,
          };
          await ch().chCommand(`INSERT INTO identity_aliases FORMAT JSONEachRow\n${JSON.stringify(row)}`);
        };
        const expectNames = async (expected: string[]) => {
          const seen = await actors().aliasSightings(value, "24h", now);
          assert.equal(seen.kind, "actor");
          assert.ok(seen.rows.every((r) => r.source === source && r.events === 1));
          assert.deepEqual(seen.rows.map((r) => r.who).sort(), [...expected].sort());
        };

        await caseTest.test("unregistered value is exact", async () => {
          await expectNames([value]);
        });
        await caseTest.test("live login/email enables case folding", async () => {
          await version(1, 0);
          await expectNames(names);
        });
        await caseTest.test("latest tombstone disables case folding", async () => {
          await version(2, 1);
          await expectNames([value]);
        });
        await caseTest.test("a late INSERT of an old live version cannot resurrect registration", async () => {
          await version(0, 0);
          await expectNames([value]);
        });
        await caseTest.test("a newer live version restores registration", async () => {
          await version(3, 0);
          await expectNames(names);
        });
        await caseTest.test("a different person's tombstone does not remove the live alias", async () => {
          await version(4, 1, { person_id: `${personId}-other` });
          await expectNames(names);
        });
        await caseTest.test("a different interval's tombstone does not remove the live alias", async () => {
          await version(5, 1, { valid_from: chTs(now - 12 * hour) });
          await expectNames(names);
        });
        await caseTest.test("a different alias kind's tombstone does not remove the live alias", async () => {
          await version(6, 1, { alias_kind: "uid" });
          await expectNames(names);
        });
      });
    }
  } finally {
    await ch().chCommand("ALTER TABLE events DELETE WHERE source = {source:String} SETTINGS mutations_sync = 1", { source });
    for (const table of ["identity_aliases", "identities"]) {
      await ch().chCommand(`ALTER TABLE ${table} DELETE WHERE startsWith(person_id, {prefix:String}) SETTINGS mutations_sync = 1`, { prefix });
    }
  }
});
