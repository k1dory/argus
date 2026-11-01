// PR #22: being a past/future owner of a login must not exempt a person's
// uid/sid/peer from the foreign-identifier guard at another event timestamp.
// Exercise production SQL; the expected event set is not a SQL mock.
import { after, before, test } from "node:test";
import assert from "node:assert/strict";
import { randomBytes } from "node:crypto";
import { applyAllMigrations, ch, liveSkip as skip, serializeLiveFile } from "./_ch-live";
import { chTs } from "../src/lib/shared/log-query";
import type { AliasInput, PersonInput } from "../src/lib/shared/actors";

serializeLiveFile({ before, after });

/* eslint-disable @typescript-eslint/no-require-imports -- _ch-live configures ClickHouse before actors loads */
const actors = () => require("../src/lib/actors") as typeof import("../src/lib/actors");
/* eslint-enable @typescript-eslint/no-require-imports */

test("PR #22: foreign exact aliases are exempt only while their owner has an active login/email", { skip }, async (t) => {
  await applyAllMigrations();
  const run = randomBytes(6).toString("hex");
  const prefix = `pr22-owner-${run}-`;
  const source = `lookup.owner-interval.${run}`;
  const node = `neutral-node-${run}`;
  const now = Date.now();
  const hour = 3600_000;
  const eventAt = now - 4 * hour;
  const dayStart = now - 24 * hour;
  type Interval = { from: number; to: number | null };
  const cases: { name: string; intervals: Interval[]; ownAtEvent: boolean }[] = [
    { name: "expired-at-event", intervals: [{ from: dayStart, to: eventAt }], ownAtEvent: false },
    { name: "future-in-window", intervals: [{ from: eventAt + 1, to: null }], ownAtEvent: false },
    { name: "future-outside", intervals: [{ from: now + hour, to: null }], ownAtEvent: false },
    // Both intervals overlap the lookup window, but neither covers this event.
    { name: "gap", intervals: [{ from: dayStart, to: eventAt - 1 }, { from: eventAt + 1, to: null }], ownAtEvent: false },
    { name: "active-at-start", intervals: [{ from: eventAt, to: null }], ownAtEvent: true },
    { name: "active-before-end", intervals: [{ from: dayStart, to: eventAt + 1 }], ownAtEvent: true },
  ];
  const person = (person_id: string, aliases: AliasInput[]): PersonInput => ({
    person_id, display: person_id, kind: "person", team: "fixture", note: "", aliases,
  });

  try {
    for (const kind of ["login", "email"] as const) {
      for (const exactKind of ["uid", "sid", "peer"] as const) {
        for (const scenario of cases) {
          await t.test(`${kind}/${exactKind}: ${scenario.name}`, async (caseTest) => {
            const tag = `${kind}-${exactKind}-${scenario.name}`;
            const lower = `casekey-${tag}-${run}${kind === "email" ? "@example.test" : ""}`;
            const mixed = `CaseKey${lower.slice("casekey".length)}`;
            const third = `cAsEkEy${lower.slice("casekey".length)}`;
            const owner = `${prefix}${tag}-a`;
            const other = `${prefix}${tag}-b`;
            const fields = { valid_from: chTs(dayStart), valid_to: null, confidence: 0.5, note: "" };
            await actors().upsertIdentities([
              person(owner, [{ ...fields, kind, value: lower }]),
              person(other, [{ ...fields, kind: exactKind, value: mixed }]),
            ], "fixture");
            const events = [lower, mixed, third].map((actor_name) => ({
              ts: chTs(eventAt), source, source_class: "identity", action: "auth.login", actor_name, node,
            }));
            await ch().chCommand(`INSERT INTO events FORMAT JSONEachRow\n${events.map((row) => JSON.stringify(row)).join("\n")}`);

            const expectNames = async (expected: string[]) => {
              const seen = await actors().aliasSightings(lower, "24h", now);
              assert.equal(seen.kind, "actor");
              assert.ok(seen.rows.every((row) => row.source === source && row.where === node && row.events === 1));
              assert.deepEqual(seen.rows.map((row) => row.who).sort(), [...expected].sort(),
                "an exact alias is foreign unless its owner also has a confirmed login/email at the event timestamp");
            };
            const version = async (revision: number, confidence: number, deleted: 0 | 1) => {
              const rows = scenario.intervals.map(({ from, to }) => ({
                person_id: other, alias_kind: kind, alias_value: lower,
                valid_from: chTs(from), valid_to: to === null ? null : chTs(to),
                source: "event:qa.owner-interval", confidence,
                note: confidence < 0.5 ? "policy:hold:fixture" : "policy:confirmed:fixture",
                // Explicit versions avoid ties in now64(3) and do not depend on merges.
                updated_at: chTs(now - 10_000 + revision * 1000), deleted,
              }));
              await ch().chCommand(`INSERT INTO identity_aliases FORMAT JSONEachRow\n${rows.map((row) => JSON.stringify(row)).join("\n")}`);
            };

            await caseTest.test("control: a foreign exact alias is excluded", async () => {
              await expectNames([lower, third]);
            });
            await version(1, 0.3, 0);
            await caseTest.test("control: a held login does not confer ownership", async () => {
              await expectNames([lower, third]);
            });
            await version(2, 0.5, 0);
            await caseTest.test("confirmation must still respect the owner's interval", async () => {
              const resolved = await actors().resolveAlias(lower, eventAt);
              assert.equal(resolved.status, scenario.ownAtEvent ? "ambiguous" : "resolved");
              assert.deepEqual(resolved.matches.map((m) => m.person_id).sort(),
                (scenario.ownAtEvent ? [owner, other] : [owner]).sort());
              await expectNames(scenario.ownAtEvent ? [lower, mixed, third] : [lower, third]);
            });
            await version(3, 0.5, 1);
            await caseTest.test("control: the latest tombstone removes the ownership exemption", async () => {
              await expectNames([lower, third]);
            });
            await version(0, 1, 0);
            await caseTest.test("control: a late old version cannot restore the exemption", async () => {
              await expectNames([lower, third]);
            });
          });
        }
      }
    }
  } finally {
    await ch().chCommand("ALTER TABLE events DELETE WHERE source = {source:String} SETTINGS mutations_sync = 1", { source });
    for (const table of ["identity_aliases", "identities"]) {
      await ch().chCommand(`ALTER TABLE ${table} DELETE WHERE startsWith(person_id, {prefix:String}) SETTINGS mutations_sync = 1`, { prefix });
    }
  }
});
