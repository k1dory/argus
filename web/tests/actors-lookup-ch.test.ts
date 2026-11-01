// PR #5: «Кому принадлежит» обещает историю и события для login/email/host/phone
// с теми же правилами значения, что у алиасов (README, OpenAPI AliasKind).
// Вызываем production aliasSightings на живом ClickHouse. Ответы/SQL не подменяем.
import { after, before, test } from "node:test";
import assert from "node:assert/strict";
import { randomBytes } from "node:crypto";
import { applyAllMigrations, ch, liveSkip as skip, serializeLiveFile } from "./_ch-live";
import { chTs } from "../src/lib/shared/log-query";
import type { AliasKind, PersonInput } from "../src/lib/shared/actors";

serializeLiveFile({ before, after });

/* eslint-disable @typescript-eslint/no-require-imports -- _ch-live устанавливает env до загрузки actors */
const actors = () => require("../src/lib/actors") as typeof import("../src/lib/actors");
/* eslint-enable @typescript-eslint/no-require-imports */

test("aliasSightings: login/email без учёта регистра, host по node, телефон в E.164", { skip }, async (t) => {
  await applyAllMigrations();
  const run = randomBytes(4).toString("hex");
  const source = `lookup.contract.${run}`;
  const personPrefix = `lookup-${run}-`;
  const now = Date.now();
  const eventTS = chTs(now - 3600_000);
  const login = `lookup.${run}.alice`;
  const loginNames = [login, login.toUpperCase(), `Lookup.${run}.Alice`];
  const email = `lookup.${run}@example.test`;
  const emailNames = [email, email.toUpperCase(), `Lookup.${run}@Example.Test`];
  const host = `host-${run}.example.test`;
  const node = `Host-${run}.Example.Test`;
  const digits = String(parseInt(run, 16) % 10_000_000).padStart(7, "0");
  const phone = `+1555${digits}`;
  const formattedPhone = `+1 (555) ${digits.slice(0, 3)}-${digits.slice(3)}`;

  const person = (kind: AliasKind, value: string): PersonInput => ({
    person_id: `${personPrefix}${kind}`, display: `Lookup ${kind}`, kind: "person", team: "fixture", note: "",
    aliases: [{ kind, value, valid_from: chTs(now - 86400_000), valid_to: null, confidence: 1, note: "" }],
  });
  const eventRows = [
    ...loginNames.map((actor, i) => ({ actor, node: `login-node-${i}`, action: "auth.login" })),
    ...emailNames.map((actor, i) => ({ actor, node: `email-node-${i}`, action: "auth.sso" })),
    { actor: `operator.${run}`, node, action: "host.access" },
    { actor: phone, node: "otp-gateway", action: "otp.send" },
  ];

  async function hasOwnerAndHistory(value: string, kind: AliasKind) {
    const resolution = await actors().resolveAlias(value, now);
    assert.equal(resolution.status, "resolved", `${kind}: значение распознано резолвером`);
    assert.deepEqual(resolution.matches.map((m) => [m.person_id, m.alias_kind]), [[`${personPrefix}${kind}`, kind]]);
    const history = await actors().aliasHistory(value);
    assert.deepEqual(history.map((h) => [h.person_id, h.kind]), [[`${personPrefix}${kind}`, kind]], `${kind}: история использует те же правила значения`);
  }

  try {
    await actors().upsertIdentities([
      person("login", login), person("email", email), person("host", host), person("phone", phone),
    ], "fixture");
    for (const row of eventRows) {
      await ch().chCommand(`INSERT INTO events (ts, source, source_class, actor_name, node, action, src_ip)
        VALUES (parseDateTime64BestEffort({ts:String}, 3, 'UTC'), {source:String}, 'syslog',
          {actor:String}, {node:String}, {action:String}, '192.0.2.17')`, { ...row, source, ts: eventTS });
    }

    for (const scenario of [
      { kind: "login", value: login, names: loginNames },
      { kind: "email", value: email, names: emailNames },
    ] as const) {
      await t.test(`${scenario.kind}: поиск в нижнем регистре видит все варианты actor_name`, async () => {
        await hasOwnerAndHistory(scenario.value, scenario.kind);
        const seen = await actors().aliasSightings(scenario.value, "24h", now);
        assert.deepEqual(seen.rows.map((r) => r.who).sort(), [...scenario.names].sort(),
          `${scenario.kind} по контракту регистронезависим: owner/history найдены, события другого регистра не должны пропадать`);
        assert.equal(seen.rows.reduce((n, row) => n + row.events, 0), scenario.names.length);
        assert.ok(seen.rows.every((row) => row.source === source));
      });
    }

    await t.test("host: найденный алиас показывает событие узла, даже когда actor_name другой", async () => {
      await hasOwnerAndHistory(host, "host");
      const seen = await actors().aliasSightings(host, "24h", now);
      assert.deepEqual(seen.rows.map((r) => ({ source: r.source, who: r.who, where: r.where, events: r.events })), [
        { source, who: `operator.${run}`, where: node, events: 1 },
      ], "host сопоставляется с node без учёта регистра, а не с actor_name");
    });

    await t.test("phone: форматированный ввод видит те же события, что канонический E.164", async () => {
      await hasOwnerAndHistory(formattedPhone, "phone");
      const canonical = await actors().aliasSightings(phone, "24h", now);
      assert.equal(canonical.rows.length, 1, "контроль: событие с каноническим actor_name присутствует");
      assert.equal(canonical.rows[0].source, source);
      assert.equal(canonical.rows[0].who, phone);
      const formatted = await actors().aliasSightings(formattedPhone, "24h", now);
      assert.deepEqual(formatted.rows, canonical.rows, "тот же телефон с пробелами/скобками/дефисами не должен давать пустой журнал");
    });
  } finally {
    // Файлы делят БД под lock; убираем только события и идентичности этой фикстуры.
    await ch().chCommand("ALTER TABLE events DELETE WHERE source = {source:String} SETTINGS mutations_sync = 1", { source });
    for (const table of ["identity_aliases", "identities"]) {
      await ch().chCommand(`ALTER TABLE ${table} DELETE WHERE startsWith(person_id, {prefix:String}) SETTINGS mutations_sync = 1`, { prefix: personPrefix });
    }
  }
});
