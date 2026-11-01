// PR #72 / merge #70: activity for all listed persons must still fit through
// ClickHouse's HTTP transport. chQuery puts bound parameters in the request URI,
// even when the SQL itself is sent by POST. No server or network is needed here.
import { test } from "node:test";
import assert from "node:assert/strict";
import { listPersons } from "../src/lib/actors";
import { parseIdentitiesDoc } from "../src/lib/shared/actors";

// ClickHouse 24.8, as used by docker-compose.yml; ARGUS does not override this.
// https://github.com/ClickHouse/ClickHouse/blob/v24.8.14.39-lts/src/Core/Settings.h#L363
const HTTP_MAX_URI_SIZE = 1_048_576;

test("PR #72: activity for 5000 persons stays within ClickHouse's HTTP URI limit", async (t) => {
  const now = Date.UTC(2026, 10, 1, 12);
  const validFrom = "2026-10-01 00:00:00.000";
  const persons = Array.from({ length: 5000 }, (_, i) => {
    const id = `person-${String(i).padStart(4, "0")}`;
    return { person_id: id, display: id, kind: "person", team: "", note: "" };
  });
  const aliases = persons.flatMap((p, i) => [
    { alias_kind: "login", alias_value: p.person_id },
    { alias_kind: "email", alias_value: `${p.person_id}@example.test` },
    { alias_kind: "host", alias_value: `ws-${String(i).padStart(4, "0")}` },
  ].map((a) => ({
    ...a, person_id: p.person_id, valid_from: validFrom, valid_to_raw: null,
    source: "yaml", confidence: 1, note: "",
  })));

  // This is accepted input, well below the 100000-alias list limit. Three
  // aliases per person also fit the former batches of 100 persons.
  const input = parseIdentitiesDoc({ persons: Object.fromEntries(persons.map((p, i) => [p.person_id, {
    display: p.display,
    aliases: aliases.slice(i * 3, i * 3 + 3).map((a) => ({
      kind: a.alias_kind, value: a.alias_value, from: "2026-10-01", confidence: 1,
    })),
  }])) });
  assert.ok(input.ok, "the identity import must accept the regression fixture");

  const rows = (data: unknown[]) => new Response(data.map((r) => JSON.stringify(r)).join("\n"));
  const eventRequests: number[] = [];
  t.mock.method(globalThis, "fetch", async (input: URL | string | Request, init?: RequestInit) => {
    const url = new URL(input instanceof Request ? input.url : String(input));
    const sql = String(init?.body ?? "");
    if (sql.includes("FROM identity_aliases")) return rows(aliases);
    if (sql.includes("FROM identities")) return rows(persons);
    if (sql.includes("FROM events")) {
      // Exercise the real query builder, parameter encoder and URL serializer.
      // Do not replicate activityPlan or require any particular batching scheme.
      eventRequests.push(Buffer.byteLength(url.pathname + url.search));
      return rows([]);
    }
    if (sql.includes("FROM incidents_current")) return rows([]);
    assert.fail(`unexpected ClickHouse query: ${sql}`);
  });

  const result = await listPersons("7d", now);
  assert.equal(result.length, persons.length, "every listed person must be retained");
  assert.ok(result.every((p) => p.aliases === 3 && p.events === 0 && p.last_ts === null));
  assert.ok(eventRequests.length > 0, "the fixture must reach the activity query");
  for (const bytes of eventRequests) {
    assert.ok(bytes <= HTTP_MAX_URI_SIZE,
      `activity request URI is ${bytes} bytes; ClickHouse rejects more than ${HTTP_MAX_URI_SIZE} before executing SQL`);
  }
});
