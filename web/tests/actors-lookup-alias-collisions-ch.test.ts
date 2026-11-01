// PR #17: a case-sensitive alias must not suppress events already matched
// by the resolved person's login/email, including aliases of that same person.
import { after, before, test } from "node:test";
import assert from "node:assert/strict";
import { randomBytes } from "node:crypto";
import { applyAllMigrations, ch, liveSkip as skip, serializeLiveFile } from "./_ch-live";
import { chTs } from "../src/lib/shared/log-query";
import type { AliasInput, PersonInput } from "../src/lib/shared/actors";

serializeLiveFile({ before, after });

/* eslint-disable @typescript-eslint/no-require-imports -- _ch-live sets the connection before actors loads */
const actors = () => require("../src/lib/actors") as typeof import("../src/lib/actors");
/* eslint-enable @typescript-eslint/no-require-imports */

test("lookup: login/email retain their events in the presence of case-sensitive aliases", { skip }, async (t) => {
  await applyAllMigrations();
  const run = randomBytes(6).toString("hex");
  const prefix = `lookup-collision-${run}-`;
  const source = `lookup.alias-collision.${run}`;
  const now = Date.now();
  const ts = chTs(now - 3600_000);
  const day = 86400_000;
  type State = "same-person" | "held" | "expired" | "future";
  const cases: { kind: "login" | "email"; exactKind: "uid" | "sid" | "peer"; state: State }[] = [];
  for (const kind of ["login", "email"] as const) {
    for (const exactKind of ["uid", "sid", "peer"] as const) {
      cases.push({ kind, exactKind, state: "same-person" });
    }
    for (const state of ["held", "expired", "future"] as const) {
      cases.push({ kind, exactKind: "uid", state });
    }
  }
  const scenarios = cases.map((c, i) => {
    const stem = `lookup.${run}.${i}`;
    const value = c.kind === "email" ? `${stem}@example.test` : stem;
    return { ...c, value, names: [value, value.toUpperCase(), `L${value.slice(1)}`], owner: `${prefix}${i}`, other: `${prefix}${i}-other` };
  });
  const person = (person_id: string, aliases: AliasInput[]): PersonInput => ({
    person_id, display: person_id, kind: "person", team: "fixture", note: "", aliases,
  });
  const persons: PersonInput[] = scenarios.flatMap(({ kind, exactKind, state, value, owner, other }) => {
    const login: AliasInput = { kind, value, valid_from: chTs(now - day), valid_to: null, confidence: 1, note: "" };
    const exact: AliasInput = {
      kind: exactKind, value: value.toUpperCase(),
      valid_from: chTs(state === "future" ? now + day : now - 3 * day),
      valid_to: state === "expired" ? chTs(now - 2 * day) : null,
      confidence: state === "held" ? 0.3 : 1,
      note: state === "held" ? "policy:hold:fixture" : "",
    };
    return state === "same-person"
      ? [person(owner, [login, exact])]
      : [person(owner, [login]), person(other, [exact])];
  });

  try {
    await actors().upsertIdentities(persons, "fixture");
    const events = scenarios.flatMap(({ names }) => names.map((actor_name) => ({
      ts, source, source_class: "identity", action: "auth.login", actor_name, node: `neutral-node-${run}`,
    })));
    await ch().chCommand(`INSERT INTO events FORMAT JSONEachRow\n${events.map((e) => JSON.stringify(e)).join("\n")}`);

    for (const { kind, exactKind, state, value, names, owner } of scenarios) {
      await t.test(`${kind} + ${exactKind}: ${state}`, async () => {
        // Both inputs resolve to the same person. Held, expired and future
        // aliases cannot introduce another current owner.
        for (const query of [value, value.toUpperCase()]) {
          const resolution = await actors().resolveAlias(query, now);
          assert.equal(resolution.status, "resolved");
          assert.deepEqual(resolution.matches.map((m) => m.person_id), [owner]);
        }
        const history = await actors().aliasHistory(value);
        assert.deepEqual(history.map((a) => [a.person_id, a.kind]), [[owner, kind]]);

        const lower = await actors().aliasSightings(value, "24h", now);
        const upper = await actors().aliasSightings(value.toUpperCase(), "24h", now);
        assert.equal(lower.kind, "actor");
        assert.deepEqual(lower.rows.map((r) => r.who).sort(), [...names].sort(),
          `${kind}: the ${state} ${exactKind} alias must not hide a matching event`);
        assert.deepEqual(upper.rows.map((r) => r.who).sort(), [...names].sort(),
          `${kind}: changing query case must preserve the event set`);
        assert.ok(lower.rows.every((r) => r.source === source && r.events === 1));
      });
    }
  } finally {
    await ch().chCommand("ALTER TABLE events DELETE WHERE source = {source:String} SETTINGS mutations_sync = 1", { source });
    for (const table of ["identity_aliases", "identities"]) {
      await ch().chCommand(`ALTER TABLE ${table} DELETE WHERE startsWith(person_id, {prefix:String}) SETTINGS mutations_sync = 1`, { prefix });
    }
  }
});
