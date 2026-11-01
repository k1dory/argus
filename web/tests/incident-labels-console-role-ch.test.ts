// /api/incidents/labels документирует limit до 50000. Проверяем настоящий
// incidentLabels под production профилем консоли, где max_result_rows = 20000.
// Администратор готовит фикстуру; ответ запроса не подменяется.
import { after, before, test } from "node:test";
import assert from "node:assert/strict";
import { randomBytes, randomInt } from "node:crypto";
import { readFileSync } from "node:fs";
import path from "node:path";
import { applyAllMigrations, ch, liveSkip as skip, root, serializeLiveFile } from "./_ch-live";

serializeLiveFile({ before, after });

/* eslint-disable @typescript-eslint/no-require-imports -- окружение _ch-live до загрузки запросов */
const queries = () => require("../src/lib/argus-queries") as typeof import("../src/lib/argus-queries");
/* eslint-enable @typescript-eslint/no-require-imports */

function consoleProfile(): { settings: string; grants: string[] } {
  const script = readFileSync(path.join(root, "scripts/migrate.sh"), "utf8");
  const call = script.match(/^mkuser argus_console\b(?:.*\\\n)*.*$/m);
  assert.ok(call, "production профиль argus_console найден");
  const quoted = [...call[0].matchAll(/"((?:\\.|[^"\\])*)"|'([^']*)'/g)]
    .map((m) => m[2] ?? m[1].replace(/\\(["\\$`])/g, "$1"));
  const [, settings, ...grants] = quoted;
  assert.ok(settings && settings.includes("max_result_rows"));
  assert.ok(grants.includes("SELECT ON argus.*"));
  assert.ok(grants.length && grants.every((g) => /^(SELECT|INSERT)\b/.test(g) && !g.includes("$")));
  return { settings, grants };
}

test("incidentLabels: документированный limit 50000 работает под точным профилем argus_console", { skip }, async (t) => {
  await applyAllMigrations();
  const { settings, grants } = consoleProfile();
  const suffix = randomBytes(6).toString("hex");
  const user = `labels_console_test_${suffix}`;
  const password = `fixture-${randomBytes(16).toString("hex")}`;
  const actor = `labels.limit.${suffix}`;
  const id = `INC-${randomInt(100_000_000, 900_000_000)}`;
  const since = "2099-01-01T00:00:00Z";
  const count = 25_001;
  let created = false, insertedIncident = false, insertedLabels = false, asConsole = false;
  const nativeFetch = globalThis.fetch;
  const consoleAuth = "Basic " + Buffer.from(`${user}:${password}`).toString("base64");
  t.mock.method(globalThis, "fetch", async (input: URL | string | Request, init?: RequestInit) => {
    if (!asConsole) return nativeFetch(input, init);
    const headers = new Headers(init?.headers);
    headers.set("Authorization", consoleAuth);
    return nativeFetch(input, { ...init, headers });
  });
  try {
    await ch().chCommand(`CREATE USER ${user} IDENTIFIED WITH sha256_password BY '${password}'`);
    created = true;
    await ch().chCommand(`ALTER USER ${user} SETTINGS ${settings}`);
    await ch().chCommand(`REVOKE ALL ON *.* FROM ${user}`);
    for (const grant of grants) await ch().chCommand(`GRANT ${grant} TO ${user}`);

    await ch().chCommand(`INSERT INTO incidents (incident_id, created_at, updated_at, rule_id, rule_title, level, tags, status, first_ts, last_ts)
      VALUES ({id:String}, now(), now(), 'fixture-labels', 'Labels fixture', 'high', ['attack.t1110'], 'new', now64(3), now64(3))`, { id });
    insertedIncident = true;
    // Append-only журнал допускает отдельную метку каждого завершения. Будущее
    // since отделяет фикстуру от обычных live-тестов в общей БД; cleanup — свой actor.
    await ch().chCommand(`INSERT INTO incident_state_events
      (event_id, incident_id, revision, changed_at, actor, kind, status, owner, reason,
       disposition, escalate, severity_correct, blind, labeled_by_human)
      SELECT generateUUIDv4(), {id:String}, number + 1,
        parseDateTime64BestEffort({since:String}, 3, 'UTC') + toIntervalMillisecond(number),
        {actor:String}, 'status', 'closed', {actor:String}, concat('fixture label ', toString(number)),
        'benign_authorized', false, true, true, true
      FROM numbers({count:UInt32})`, { id, since, actor, count });
    insertedLabels = true;
    const [seeded] = await ch().chQuery<{ n: string | number }>(
      "SELECT count() AS n FROM incident_state_events WHERE actor = {actor:String}", { actor });
    assert.equal(Number(seeded.n), count);

    asConsole = true;
    const [principal] = await ch().chQuery<{ name: string }>("SELECT currentUser() AS name");
    assert.equal(principal.name, user, "runtime запрос исполняется консольной ролью, не администратором");
    const rows = await queries().incidentLabels(since, 50_000);
    assert.equal(rows.length, count, "запрошенная допустимая порция не должна падать или обрезаться на 20000");
    assert.ok(rows.every((row) => row.actor === actor && row.incident_id === id && row.rule_id === "fixture-labels"));
    assert.equal(rows[0].reason, "fixture label 0");
    assert.equal(rows.at(-1)!.reason, `fixture label ${count - 1}`);
  } finally {
    asConsole = false;
    try {
      if (created) await ch().chCommand(`DROP USER ${user}`);
    } finally {
      if (insertedLabels) await ch().chCommand("ALTER TABLE incident_state_events DELETE WHERE actor = {actor:String} SETTINGS mutations_sync = 1", { actor });
      if (insertedIncident) await ch().chCommand("ALTER TABLE incidents DELETE WHERE incident_id = {id:String} SETTINGS mutations_sync = 1", { id });
    }
  }
});
