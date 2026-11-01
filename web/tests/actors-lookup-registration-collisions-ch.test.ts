// PR #17 re-review: the existence of any login/email is a global case-fold
// switch. It must not mix another person's live uid/sid/peer into a lookup,
// including when the login/email itself is held or outside the event interval.
// These are regression assertions against production SQL, not a SQL mock.
import { after, before, test } from "node:test";
import assert from "node:assert/strict";
import { randomBytes } from "node:crypto";
import { applyAllMigrations, ch, liveSkip as skip, serializeLiveFile } from "./_ch-live";
import { chTs } from "../src/lib/shared/log-query";
import type { AliasInput, AliasKind, PersonInput } from "../src/lib/shared/actors";

serializeLiveFile({ before, after });

/* eslint-disable @typescript-eslint/no-require-imports -- _ch-live configures ClickHouse before actors loads */
const actors = () => require("../src/lib/actors") as typeof import("../src/lib/actors");
/* eslint-enable @typescript-eslint/no-require-imports */

test("PR #17: a login/email registration must not merge foreign case-sensitive identifiers", { skip }, async (t) => {
  await applyAllMigrations();
  const run = randomBytes(6).toString("hex");
  const prefix = `pr17-register-${run}-`;
  const source = `lookup.registration-collision.${run}`;
  const now = Date.now();
  const hour = 3600_000;
  const eventAt = now - hour;
  const node = `neutral-node-${run}`;

  const alias = (kind: AliasKind, value: string, patch: Partial<AliasInput> = {}): AliasInput => ({
    kind, value, valid_from: chTs(now - 24 * hour), valid_to: null, confidence: 1, note: "", ...patch,
  });
  const person = (tag: string, aliases: AliasInput[]): PersonInput => ({
    person_id: `${prefix}${tag}`, display: tag, kind: "person", team: "fixture", note: "", aliases,
  });
  const insertEvents = async (names: string[]) => {
    const rows = names.map((actor_name) => ({
      ts: chTs(eventAt), source, source_class: "identity", action: "auth.login", actor_name, node,
    }));
    await ch().chCommand(`INSERT INTO events FORMAT JSONEachRow\n${rows.map((r) => JSON.stringify(r)).join("\n")}`);
  };
  const expectOwner = async (value: string, personId: string) => {
    for (const at of [eventAt, now]) {
      const resolution = await actors().resolveAlias(value, at);
      assert.equal(resolution.status, "resolved");
      assert.deepEqual(resolution.matches.map((m) => m.person_id), [personId]);
    }
  };
  const expectNames = async (value: string, names: string[], message: string) => {
    const seen = await actors().aliasSightings(value, "24h", now);
    assert.equal(seen.kind, "actor");
    assert.ok(seen.rows.every((r) => r.source === source && r.where === node && r.events === 1));
    assert.deepEqual(seen.rows.map((r) => r.who).sort(), [...names].sort(), message);
  };

  try {
    for (const kind of ["login", "email"] as const) {
      for (const exactKind of ["uid", "sid", "peer"] as const) {
        await t.test(`known collision: active ${kind} versus a foreign ${exactKind}`, async () => {
          const tag = `${kind}-${exactKind}-active`;
          const lower = `casekey-${tag}-${run}${kind === "email" ? "@example.test" : ""}`;
          const upper = `CaseKey${lower.slice("casekey".length)}`;
          const third = `cAsEkEy${lower.slice("casekey".length)}`;
          const owner = person(`${tag}-a`, [alias(kind, lower)]);
          const other = person(`${tag}-b`, [alias(exactKind, upper)]);

          await actors().upsertIdentities([owner], "fixture");
          await insertEvents([lower, upper, third]);
          await expectNames(lower, [lower, upper, third],
            "control: a registered login/email still finds its case variants without a foreign exact alias");

          await actors().upsertIdentities([other], "fixture");
          await expectOwner(lower, owner.person_id);
          assert.deepEqual((await actors().aliasHistory(lower)).map((a) => [a.person_id, a.kind]),
            [[owner.person_id, kind]], "the lookup gives no indication of the foreign exact alias");
          const foreign = await actors().resolveAlias(upper, eventAt);
          assert.equal(foreign.status, "ambiguous");
          assert.deepEqual(foreign.matches.map((m) => m.person_id).sort(),
            [owner.person_id, other.person_id].sort(), "the extra event has another confirmed candidate owner");

          await expectNames(lower, [lower, third],
            "a lookup with one reported owner must not silently include a case variant with a confirmed foreign owner");
        });

        for (const state of ["held", "expired", "future"] as const) {
          await t.test(`${exactKind}: ${state} ${kind} must not enable case folding`, async (caseTest) => {
            const tag = `${kind}-${exactKind}-${state}`;
            const lower = `casekey-${tag}-${run}${kind === "email" ? "@example.test" : ""}`;
            const upper = `CaseKey${lower.slice("casekey".length)}`;
            const third = `cAsEkEy${lower.slice("casekey".length)}`;
            const owner = person(`${tag}-a`, [alias(exactKind, upper)]);
            const other = person(`${tag}-b`, [alias(exactKind, lower)]);
            const inactive = person(`${tag}-c`, [alias(kind, lower, state === "held"
              ? { confidence: 0.3, note: "policy:hold:sources" }
              : state === "expired"
                // The interval overlaps the lookup window, but not the event.
                ? { valid_to: chTs(now - 2 * hour) }
                : { valid_from: chTs(now + hour) })]);

            await actors().upsertIdentities([owner, other], "fixture");
            await insertEvents([upper, lower, third]);
            await expectNames(upper, [upper], "control: exact lookup before login/email registration");
            await expectNames(lower, [lower], "control: the lower-case exact identifier is independent");

            await actors().upsertIdentities([inactive], "event:qa.untrusted");
            await expectOwner(upper, owner.person_id);
            await expectOwner(lower, other.person_id);
            assert.equal((await actors().resolveAlias(third, eventAt)).status, "unbound",
              "the held/out-of-interval alias cannot resolve the unregistered third spelling");
            const history = await actors().aliasHistory(upper);
            assert.ok(history.some((a) => a.person_id === inactive.person_id && a.held === (state === "held")),
              "the inactive registration is present in history, not missing from the fixture");

            for (const value of [upper, lower]) {
              await caseTest.test(value, async () => {
                await expectNames(value, [value],
                  `${state} ${kind} must not add another person's exact identifier or an unbound spelling`);
              });
            }
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
