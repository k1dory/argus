import { after, before, test } from "node:test";
import assert from "node:assert/strict";
import { applyAllMigrations, ch, liveSkip as skip, serializeLiveFile } from "./_ch-live";

serializeLiveFile({ before, after });

/* eslint-disable @typescript-eslint/no-require-imports -- модуль читает env при загрузке */
const q = () => require("../src/lib/argus-queries") as typeof import("../src/lib/argus-queries");
/* eslint-enable @typescript-eslint/no-require-imports */

// Подсеть считается в запросе на живом ClickHouse: /24 и /48, ::ffff: и пробелы
// сводятся к своему IPv4, развёрнутый IPv6 — к своей /48; закрытые, чужие правила
// и субъект-не-адрес в группы не попадают и остаются в очереди.
test("scanGroups / scanGroupIncidents / incidentsList(groupScans) на живом ClickHouse", { skip }, async () => {
  await applyAllMigrations();
  const run = `скан-${Date.now().toString(36)}-${Math.floor(Math.random() * 1e6)}`;
  let n = 0;
  const add = async (rule: string, actor: string, status = "new", level = "medium", owner = "") => {
    const id = `INC-8${Date.now() % 1e6}${n++}`;
    await ch().chCommand(`INSERT INTO incidents (incident_id, created_at, updated_at, rule_id, rule_title, level, tags, status, owner, actor_name, first_ts, last_ts)
      VALUES ({id:String}, now(), now(), {rule:String}, {title:String}, {level:String}, [], {status:String}, {owner:String}, {actor:String}, now64(3), now64(3))`,
    { id, rule, title: `Сканирование ${run}`, level, status, owner, actor });
    return id;
  };
  const a1 = await add("a41c-net-070", "203.0.113.7");
  const a2 = await add("a41c-net-072", " 203.0.113.9 ", "new", "low", "anna");
  const a3 = await add("a41c-net-071", "::ffff:203.0.113.10", "new", "high");
  const v6a = await add("a41c-net-070", "2001:0DB8:0001:0000:0000:0000:0000:0007");
  const v6b = await add("a41c-net-071", "2001:db8:1:ab::1");
  const closed = await add("a41c-net-070", "203.0.113.11", "closed");
  const other = await add("a41c-auth-030", "203.0.113.12");
  const noAddr = await add("a41c-net-070", "exporter-1");

  const groups = await q().scanGroups({ q: run });
  const by = Object.fromEntries(groups.map((g) => [g.subnet, g]));
  assert.deepEqual(Object.keys(by).sort(), ["2001:db8:1::/48", "203.0.113.0/24"]);
  assert.equal(by["203.0.113.0/24"].incidents, 3);
  assert.equal(by["203.0.113.0/24"].addresses, 3);
  assert.equal(by["203.0.113.0/24"].level, "high", "уровень группы — максимум");
  assert.equal(by["203.0.113.0/24"].unassigned, 2);
  assert.deepEqual(by["203.0.113.0/24"].rules, ["a41c-net-070", "a41c-net-071", "a41c-net-072"]);
  assert.equal(by["2001:db8:1::/48"].incidents, 2);

  const inSubnet = (await q().scanGroupIncidents("203.0.113.0/24", { q: run })).map((r) => r.incident_id).sort();
  assert.deepEqual(inSubnet, [a1, a2, a3].sort());
  assert.deepEqual((await q().scanGroupIncidents("2001:db8:1::/48", { q: run })).map((r) => r.incident_id).sort(), [v6a, v6b].sort());

  const flat = (await q().incidentsList({ q: run, groupScans: true, pageSize: 200 })).rows.map((r) => r.incident_id).sort();
  assert.deepEqual(flat, [closed, other, noAddr].sort(), "в очереди остаются закрытые, чужие правила и субъект-не-адрес");
  const all = (await q().incidentsList({ q: run, pageSize: 200 })).rows.length;
  assert.equal(all, 8, "без группировки — все как раньше");

  await ch().chCommand(`INSERT INTO response_log (ts, incident_id, rule_id, ip, mode, executor, dry_run, ok, detail, reason, actor)
    VALUES (now() - 1, {a1:String}, 'a41c-net-070', '203.0.113.7', 'ips', 'argus', 0, 0, 'все исполнители отказали — повтор №1', '', 'argus-engine'),
           (now(), {a1:String}, 'a41c-net-070', '203.0.113.7', 'ips', 'ngfw.edge', 0, 1, 'POST', '', 'argus-engine')`, { a1 });
  assert.deepEqual(await q().incidentBlockStates([a1, a2]), { [a1]: "blocked" });
});
