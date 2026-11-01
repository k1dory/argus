// PR #22: a small lookup must keep working when the same value has thousands
// of closed alias intervals outside its window. Run the real SQL on CI's CH.
import { after, before, test } from "node:test";
import assert from "node:assert/strict";
import { randomBytes } from "node:crypto";
import { applyAllMigrations, ch, liveSkip as skip, serializeLiveFile } from "./_ch-live";
import { chTs } from "../src/lib/shared/log-query";

serializeLiveFile({ before, after });

/* eslint-disable @typescript-eslint/no-require-imports -- _ch-live configures ClickHouse before actors loads */
const actors = () => require("../src/lib/actors") as typeof import("../src/lib/actors");
/* eslint-enable @typescript-eslint/no-require-imports */

test("PR #22: closed alias history cannot make recent sightings exceed ClickHouse query limits", { skip }, async (t) => {
  await applyAllMigrations();
  const run = randomBytes(6).toString("hex");
  const prefix = `pr22-budget-${run}-`;
  const source = `lookup.history-budget.${run}`;
  const now = Date.now();
  const day = 86_400_000;

  try {
    for (const historyKind of ["login", "uid"] as const) {
      await t.test(historyKind, async () => {
        const lower = `budget-${historyKind}-${run}`;
        const mixed = lower.toUpperCase();
        const owner = `${prefix}${historyKind}-a`;
        const other = `${prefix}${historyKind}-b`;
        await actors().upsertIdentities([{
          person_id: owner, display: owner, kind: "person", team: "fixture", note: "",
          aliases: [{ kind: "login", value: lower, valid_from: chTs(now - day), valid_to: null, confidence: 1, note: "" }],
        }, {
          person_id: other, display: other, kind: "person", team: "fixture", note: "", aliases: [],
        }], "fixture");
        await ch().chCommand(`INSERT INTO events FORMAT JSONEachRow\n${JSON.stringify({
          ts: chTs(now - 3600_000), source, source_class: "identity", action: "auth.login",
          actor_name: mixed, node: `neutral-node-${run}`,
        })}`);
        const expectEvent = async () => {
          const seen = await actors().aliasSightings(lower, "24h", now);
          assert.deepEqual(seen.rows.map((row) => [row.source, row.who, row.events]), [[source, mixed, 1]],
            "history outside the selected day cannot break a lookup with one current alias and one event");
        };
        await expectEvent();

        // Well below SEARCH_SETTINGS.max_result_rows. Every interval has a
        // distinct full key, is confirmed, and ended more than six days ago.
        const rows = Array.from({ length: 4096 }, (_, i) => ({
          person_id: historyKind === "login" ? owner : other,
          alias_kind: historyKind, alias_value: historyKind === "login" ? lower : mixed,
          valid_from: chTs(now - 7 * day + i * 2000),
          valid_to: chTs(now - 7 * day + i * 2000 + 1000),
          source: "fixture", confidence: 1, note: "",
          updated_at: chTs(now - 1000), deleted: 0,
        }));
        await ch().chCommand(`INSERT INTO identity_aliases FORMAT JSONEachRow\n${rows.map((row) => JSON.stringify(row)).join("\n")}`);
        await expectEvent();
      });
    }
  } finally {
    await ch().chCommand("ALTER TABLE events DELETE WHERE source = {source:String} SETTINGS mutations_sync = 1", { source });
    for (const table of ["identity_aliases", "identities"]) {
      await ch().chCommand(`ALTER TABLE ${table} DELETE WHERE startsWith(person_id, {prefix:String}) SETTINGS mutations_sync = 1`, { prefix });
    }
  }
});
