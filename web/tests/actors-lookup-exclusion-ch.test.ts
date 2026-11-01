// PR #17: the case-sensitive exclusion must not hide valid login/email sightings.
// Exercise production SQL on ClickHouse, using the same lock and runner as the
// existing lookup tests. No SQL predicate or query result is mocked here.
import { after, before, test } from "node:test";
import assert from "node:assert/strict";
import { randomBytes } from "node:crypto";
import { applyAllMigrations, ch, liveSkip as skip, serializeLiveFile } from "./_ch-live";
import { chTs } from "../src/lib/shared/log-query";
import type { AliasInput, AliasKind, PersonInput } from "../src/lib/shared/actors";

serializeLiveFile({ before, after });

/* eslint-disable @typescript-eslint/no-require-imports -- _ch-live sets the connection before actors loads */
const actors = () => require("../src/lib/actors") as typeof import("../src/lib/actors");
/* eslint-enable @typescript-eslint/no-require-imports */

test("PR #17: case-sensitive lookup and legitimate login/email events", { skip }, async (t) => {
  await applyAllMigrations();
  const run = randomBytes(6).toString("hex");
  const prefix = `pr17-exclude-${run}-`;
  const source = `lookup.exclusion.${run}`;
  const now = Date.now();
  const hour = 3600_000;
  const eventAt = now - hour;
  const ts = chTs(eventAt);
  const node = `unrelated-node-${run}`;

  const alias = (kind: AliasKind, value: string, patch: Partial<AliasInput> = {}): AliasInput => ({
    kind, value, valid_from: chTs(now - 24 * hour), valid_to: null, confidence: 1, note: "", ...patch,
  });
  const person = (tag: string, aliases: AliasInput[]): PersonInput => ({
    person_id: `${prefix}${tag}`, display: tag, kind: "person", team: "fixture", note: "", aliases,
  });

  async function insertEvent(who: string, atNode = node) {
    await ch().chCommand(`INSERT INTO events (ts, source, source_class, action, actor_name, node)
      VALUES (parseDateTime64BestEffort({ts:String}, 3, 'UTC'), {source:String}, 'identity', 'auth.login', {who:String}, {node:String})`,
    { ts, source, who, node: atNode });
  }

  async function expectOwner(value: string, owner: string, at = now) {
    const resolution = await actors().resolveAlias(value, at);
    assert.equal(resolution.status, "resolved");
    assert.deepEqual(resolution.matches.map((m) => m.person_id), [owner]);
  }

  async function expectEvent(value: string, who: string, message: string, atNode = node) {
    const seen = await actors().aliasSightings(value, "24h", now);
    assert.equal(seen.kind, "actor");
    assert.deepEqual(seen.rows.map((r) => ({ source: r.source, who: r.who, where: r.where, events: r.events })),
      [{ source, who, where: atNode, events: 1 }], message);
  }

  try {
    // Finding 1: a second alias of the SAME owner is not a foreign identifier.
    for (const kind of ["uid", "sid", "peer"] as const) {
      for (const insensitiveKind of ["login", "email"] as const) {
        await t.test(`own alias: ${insensitiveKind} plus ${kind} must preserve the owner's event`, async () => {
          const tag = `own-${insensitiveKind}-${kind}`;
          const mixed = `Alice-${tag}-${run}${insensitiveKind === "email" ? "@Example.Test" : ""}`;
          const lower = mixed.toLowerCase();
          const owner = person(tag, [alias(insensitiveKind, lower)]);
          await actors().upsertIdentities([owner], "fixture");
          await insertEvent(mixed);
          await expectEvent(lower, mixed, "baseline: case-insensitive alias finds the event");

          await actors().bindAlias(owner, alias(kind, mixed), "fixture", false);
          await expectOwner(lower, owner.person_id);
          await expectOwner(mixed, owner.person_id);
          await expectEvent(mixed, mixed, "control: the exact spelling still finds the event");
          await expectEvent(lower, mixed,
            "adding the same person's case-sensitive alias must not remove their login/email event");
        });
      }
    }

    // Finding 2: policy:hold records must not affect event matching, including
    // negatively by excluding an event which a confirmed login/email matches.
    for (const kind of ["uid", "sid", "peer"] as const) {
      for (const insensitiveKind of ["login", "email"] as const) {
        await t.test(`held alias: untrusted ${kind} cannot hide a confirmed ${insensitiveKind} event`, async () => {
          const tag = `held-${insensitiveKind}-${kind}`;
          const mixed = `Alice-${tag}-${run}${insensitiveKind === "email" ? "@Example.Test" : ""}`;
          const lower = mixed.toLowerCase();
          const owner = person(tag, [alias(insensitiveKind, lower)]);
          await actors().upsertIdentities([owner], "fixture");
          await insertEvent(mixed);
          await expectEvent(lower, mixed, "baseline: confirmed login/email finds the event");

          const held = person(`${tag}-other`, [alias(kind, mixed, {
            confidence: 0.3, note: "policy:hold:sources",
          })]);
          await actors().upsertIdentities([held], "event:qa.untrusted");
          await expectOwner(mixed, owner.person_id, eventAt);
          const history = await actors().aliasHistory(mixed);
          assert.ok(history.some((a) => a.person_id === held.person_id && a.held),
            "fixture: the foreign alias is visible in history but is held");
          await expectEvent(lower, mixed,
            "an alias held by identity policy must not censor a confirmed login/email event");
        });
      }
    }

    // Finding 3: validity must be checked at the event timestamp. Both test
    // intervals overlap the 24h window, so a window-overlap check is insufficient.
    for (const kind of ["uid", "sid", "peer"] as const) {
      for (const state of ["expired", "not-yet-valid"] as const) {
        await t.test(`alias interval: ${state} ${kind} cannot hide a later/earlier login event`, async () => {
          const tag = `time-${state}-${kind}`;
          const mixed = `Alice-${tag}-${run}`;
          const lower = mixed.toLowerCase();
          const owner = person(tag, [alias("login", lower)]);
          await actors().upsertIdentities([owner], "fixture");
          await insertEvent(mixed);
          await expectEvent(lower, mixed, "baseline: the active login finds the event");

          const outside = person(`${tag}-other`, [alias(kind, mixed, state === "expired"
            ? { valid_to: chTs(now - 2 * hour) }
            : { valid_from: chTs(now - hour / 2) })]);
          await actors().upsertIdentities([outside], "fixture");
          await expectOwner(mixed, owner.person_id, eventAt);
          const history = await actors().aliasHistory(mixed);
          assert.ok(history.some((a) => a.person_id === outside.person_id && !a.held),
            "fixture: the foreign alias exists and is confirmed, but does not cover the event time");
          await expectEvent(lower, mixed,
            "an alias outside the event's validity interval must not remove a valid login event");
        });
      }
    }

    // Finding 4: the PR still treats an unregistered spelling as a login/email
    // match, even when the searched value resolves only to uid/sid/peer.
    for (const kind of ["uid", "sid", "peer"] as const) {
      await t.test(`unregistered case variant: ${kind} must remain exact without an exhaustive directory`, async (caseTest) => {
        const mixed = `CaseGap-${kind}-${run}`;
        const lower = mixed.toLowerCase();
        const unregistered = `cASEgAP-${kind}-${run}`;
        const owners = [person(`gap-${kind}-mixed`, [alias(kind, mixed)]), person(`gap-${kind}-lower`, [alias(kind, lower)])];
        await actors().upsertIdentities(owners, "fixture");
        await insertEvent(mixed);
        await insertEvent(lower);
        await expectEvent(mixed, mixed, "baseline: a registered foreign spelling is excluded");
        await expectEvent(lower, lower, "baseline: exclusion also works in the other direction");

        await insertEvent(unregistered);
        assert.equal((await actors().resolveAlias(unregistered, now)).status, "unbound");
        assert.deepEqual(await actors().aliasHistory(unregistered), []);
        await expectOwner(mixed, owners[0].person_id);
        await expectOwner(lower, owners[1].person_id);
        for (const value of [mixed, lower]) {
          await caseTest.test(value, async () => {
            await expectEvent(value, value,
              "case-sensitive identifiers must not acquire an unrelated event just because its spelling is absent from identity_aliases");
          });
        }
      });
    }

    // Controls: repairing the false negatives must preserve the PR's guarantee
    // for two confirmed foreign identifiers, including a third query spelling.
    for (const kind of ["uid", "sid", "peer"] as const) {
      await t.test(`control: ${kind} excludes the other owner's identifier for all query spellings`, async () => {
        const upper = `CaseKey-${kind}-${run}`;
        const lower = upper.toLowerCase();
        const third = `cASEkEY-${kind}-${run}`;
        const owners = [person(`case-${kind}-upper`, [alias(kind, upper)]), person(`case-${kind}-lower`, [alias(kind, lower)])];
        await actors().upsertIdentities(owners, "fixture");
        await insertEvent(upper);
        await insertEvent(lower);
        await expectOwner(upper, owners[0].person_id);
        await expectOwner(lower, owners[1].person_id);
        await expectEvent(upper, upper, "the other owner's lower-case identifier is excluded");
        await expectEvent(lower, lower, "the other owner's mixed-case identifier is excluded");
        assert.equal((await actors().resolveAlias(third, now)).status, "unbound");
        assert.deepEqual((await actors().aliasSightings(third, "24h", now)).rows, [],
          "a third spelling must not bypass exclusion of either registered identifier");
      });
    }

    await t.test("control: host still matches node when actor_name is in the exclusion set", async () => {
      const host = `Host-${run}.Example.Test`;
      const owner = person("host", [alias("host", host.toLowerCase())]);
      await actors().upsertIdentities([owner, person("host-uid", [alias("uid", host)])], "fixture");
      await insertEvent(host, host);
      await expectOwner(host.toLowerCase(), owner.person_id);
      await expectEvent(host.toLowerCase(), host, "the host branch continues to match node without case", host);
    });

    await t.test("control: formatted phone still matches canonical actor_name in the exclusion set", async () => {
      const digits = String(parseInt(run, 16) % 10_000_000).padStart(7, "0");
      const phone = `+1555${digits}`;
      const formatted = `+1 (555) ${digits.slice(0, 3)}-${digits.slice(3)}`;
      const owner = person("phone", [alias("phone", phone)]);
      await actors().upsertIdentities([owner, person("phone-uid", [alias("uid", phone)])], "fixture");
      await insertEvent(phone);
      await expectOwner(formatted, owner.person_id);
      await expectEvent(formatted, phone, "phone canonicalization must remain independent of the case guard");
    });

    await t.test("control: SQL-shaped lookup values remain literal parameters", async () => {
      for (const suffix of ["' OR 1=1 --", "\\' OR 1=1 --", "' ) UNION ALL SELECT 1 --", "{v:String}"]) {
        const value = `pr17-param-${run}-${suffix}`;
        await insertEvent(value);
        await expectEvent(value, value, "SQL-looking input must retrieve only the literal actor, without widening the query");
      }
    });
  } finally {
    await ch().chCommand("ALTER TABLE events DELETE WHERE source = {source:String} SETTINGS mutations_sync = 1", { source });
    for (const table of ["identity_aliases", "identities"]) {
      await ch().chCommand(`ALTER TABLE ${table} DELETE WHERE startsWith(person_id, {prefix:String}) SETTINGS mutations_sync = 1`, { prefix });
    }
  }
});
