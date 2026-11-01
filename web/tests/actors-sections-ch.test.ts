// Разделы паспорта на живом ClickHouse: SECTION_SQL раскладывает события так же,
// как classifyEvent, и частый раздел (журнал соединений) не вытесняет редкие.
import { after, before, test } from "node:test";
import assert from "node:assert/strict";
import { randomBytes } from "node:crypto";
import { applyAllMigrations, ch, liveSkip as skip, serializeLiveFile } from "./_ch-live";
import { chTs } from "../src/lib/shared/log-query";
import { classifyEvent, SECTION_SQL, type Alias, type Person } from "../src/lib/shared/actors";

serializeLiveFile({ before, after });

/* eslint-disable @typescript-eslint/no-require-imports -- ClickHouse env установлен _ch-live до загрузки actors */
const actors = () => require("../src/lib/actors") as typeof import("../src/lib/actors");
/* eslint-enable @typescript-eslint/no-require-imports */

const CASES: [action: string, outcome: string, sourceClass: string][] = [
  ["auth.login", "failure", "idp"], ["user.LOGIN", "success", ""], ["sshd.accept", "success", "syslog"],
  ["identity.alias", "success", "identity"], ["identity.policy.violation", "failure", ""],
  ["net.connection", "success", "network"], ["flow", "success", "netflow"], ["allow", "success", "NGFW"],
  ["priv.escalate", "success", ""], ["sudo.command", "success", ""], ["pam.su", "success", ""], ["session.open", "success", ""],
  ["suspend", "success", ""], ["app.open", "success", ""], ["oauth.token", "success", ""], ["Authorize", "success", ""],
  ["file.modify", "success", ""], ["file.delete", "failure", ""], ["user.Create", "SUCCESS", ""], ["dns.query", "success", "dns"],
];

test("SECTION_SQL совпадает с classifyEvent", { skip }, async () => {
  const rows = await ch().chQuery<{ i: string | number; section: string }>(
    `SELECT i, ${SECTION_SQL} AS section FROM (
       SELECT arrayJoin(arrayEnumerate({a:Array(String)})) AS i, {a:Array(String)}[i] AS action, {o:Array(String)}[i] AS outcome, {c:Array(String)}[i] AS source_class)
     ORDER BY i`,
    { a: JSON.stringify(CASES.map((c) => c[0])).replace(/"/g, "'"), o: JSON.stringify(CASES.map((c) => c[1])).replace(/"/g, "'"), c: JSON.stringify(CASES.map((c) => c[2])).replace(/"/g, "'") },
  );
  assert.deepEqual(rows.map((r) => [CASES[Number(r.i) - 1][0], r.section]), CASES.map((c) => [c[0], classifyEvent(...c)]));
});

test("actorReport: поток net.connection не вытесняет входы и sudo из разделов", { skip }, async () => {
  await applyAllMigrations();
  const run = randomBytes(4).toString("hex");
  const source = `actor.sections.${run}`;
  const login = `sect.user.${run}`;
  const ip = `100.103.${parseInt(run.slice(0, 2), 16)}.${parseInt(run.slice(2, 4), 16)}`;
  const fromMs = Date.now() - 3600_000;
  const params = { source, login, ip, from: chTs(fromMs) };
  const person: Person = { person_id: `sect-${run}`, display: "Sections fixture", kind: "person", team: "test", note: "" };
  const aliases: Alias[] = [
    { person_id: person.person_id, kind: "login", value: login, valid_from: chTs(fromMs - 1000), valid_to: null, source: "fixture", confidence: 1, note: "" },
    { person_id: person.person_id, kind: "ip", value: ip, valid_from: chTs(fromMs - 1000), valid_to: null, source: "fixture", confidence: 1, note: "" },
  ];
  // Вход и sudo — в начале окна, 500 соединений после них.
  await ch().chCommand(`INSERT INTO events (ts, source, source_class, actor_name, actor_kind, src_ip, node, action, outcome)
    SELECT parseDateTime64BestEffort({from:String}, 3, 'UTC') + toIntervalSecond(number),
      {source:String}, if(number < 2, 'syslog', 'network'), if(number < 2, {login:String}, ''), 'user',
      if(number < 2, '', {ip:String}), 'fixture-node', multiIf(number = 0, 'auth.login', number = 1, 'sudo.command', 'net.connection'), 'success'
    FROM numbers(502)`, params);
  try {
    const report = await actors().actorReport(person, aliases, "24h", 20, { window: { fromMs: fromMs - 1000, toMs: fromMs + 600_000 }, now: fromMs + 600_000 });
    assert.deepEqual(report.missing, []);
    assert.equal(report.summary.events, 502);
    assert.equal(report.timeline.length, 20);
    assert.ok(report.timeline.every((e) => e.action === "net.connection"), "общая лента — последние события, тут только соединения");
    assert.deepEqual(report.sections.login.map((e) => e.action), ["auth.login"]);
    assert.deepEqual(report.sections.host.map((e) => e.action), ["sudo.command"]);
    assert.equal(report.sections.network.length, 20);
  } finally {
    await ch().chCommand("ALTER TABLE events DELETE WHERE source = {source:String} SETTINGS mutations_sync = 1", { source });
  }
});
