import { test } from "node:test";
import assert from "node:assert/strict";
import { incidentsList, scanGroups, scanGroupIncidents } from "../src/lib/argus-queries";
import { blockState, isSubnetKey, SCAN_GROUP_RULES, subnetSQL } from "../src/lib/shared/scan-groups";

test("isSubnetKey: только то, что выдаёт subnetSQL", () => {
  for (const ok of ["203.0.113.0/24", "2001:db8:1::/48", "::/48"]) assert.ok(isSubnetKey(ok), ok);
  for (const bad of ["203.0.113.7/24", "203.0.113.0/16", "2001:db8:1::/64", "x' OR 1=1", "", "203.0.113.0"]) assert.ok(!isSubnetKey(bad), bad);
});

test("subnetSQL: /24, /48, ::ffff: → IPv4, пробелы, не адрес → ''", () => {
  const sql = subnetSQL("actor_name");
  assert.match(sql, /IPv4CIDRToRange\(toIPv4OrDefault\(.*\), 24\)/);
  assert.match(sql, /IPv6CIDRToRange\(toIPv6OrDefault\(.*\), 48\)/);
  assert.match(sql, /startsWith\(.*, '::ffff:'\)/, "IPv4 в записи IPv6 — после канонизации IPv6NumToString");
  assert.match(sql, /trimBoth\(actor_name\)/);
  assert.match(sql, /, ''\)$/);
});

test("blockState: категории по последней записи журнала", () => {
  const base = { mode: "ips", dry_run: 0, ok: 1, detail: "" };
  assert.equal(blockState(undefined), "none");
  assert.equal(blockState({ ...base, executor: "ngfw.edge" }), "blocked");
  assert.equal(blockState({ ...base, executor: "ngfw.edge", ok: 0 }), "failed");
  assert.equal(blockState({ ...base, executor: "ngfw.edge", mode: "simulate" }), "simulated");
  assert.equal(blockState({ ...base, executor: "ngfw.edge.unblock" }), "released");
  assert.equal(blockState({ ...base, executor: "argus", detail: "уже заблокирован до 2026-11-01T12:00:00Z" }), "blocked");
  assert.equal(blockState({ ...base, executor: "argus", ok: 0, detail: "все исполнители отказали — повтор №1 в 10:00:00" }), "failed");
  assert.equal(blockState({ ...base, executor: "argus", detail: "режим IDS: автоответ выключен" }), "ids");
  assert.equal(blockState({ ...base, executor: "argus", detail: "ожидание: доверенных событий 0 из 1" }), "waiting");
  assert.equal(blockState({ ...base, executor: "argus", detail: "203.0.113.7 в allowlist" }), "refused");
});

test("incidentsList: groupScans убирает открытые сканы с адресом из очереди", async (t) => {
  const seen: string[] = [];
  t.mock.method(globalThis, "fetch", async (url: URL, options: RequestInit) => {
    seen.push(String(options.body));
    assert.equal(url.searchParams.get("param_scan_rules"), `[${SCAN_GROUP_RULES.map((r) => `'${r}'`).join(",")}]`);
    return new Response(String(options.body).includes("count()") ? '{"c":"0"}\n' : "");
  });
  await incidentsList({ queue: "open", groupScans: true });
  assert.ok(seen.every((sql) => sql.includes("NOT (rule_id IN {scan_rules:Array(String)} AND status NOT IN ('closed', 'false_positive')")), seen.join("\n"));
});

test("incidentsList без groupScans — прежний запрос", async (t) => {
  t.mock.method(globalThis, "fetch", async (_url: URL, options: RequestInit) => {
    assert.ok(!String(options.body).includes("scan_rules"));
    return new Response(String(options.body).includes("count()") ? '{"c":"0"}\n' : "");
  });
  await incidentsList({ queue: "open" });
});

test("scanGroups: те же условия очереди, уровень — максимум, числа — числами", async (t) => {
  t.mock.method(globalThis, "fetch", async (url: URL, options: RequestInit) => {
    const sql = String(options.body);
    assert.match(sql, /GROUP BY subnet/);
    assert.match(sql, /owner = \{user:String\}/, "очередь «мои» действует и на группы");
    assert.equal(url.searchParams.get("param_user"), "anna");
    return new Response('{"subnet":"203.0.113.0/24","incidents":"3","addresses":"2","rules":["a41c-net-070","a41c-net-071"],"first_ts":"2026-11-01 10:00:00","last_ts":"2026-11-01 10:05:00","level_rank":"2","unassigned":"1"}\n');
  });
  const g = await scanGroups({ queue: "mine", user: "anna" });
  assert.deepEqual(g, [{ subnet: "203.0.113.0/24", incidents: 3, addresses: 2, rules: ["a41c-net-070", "a41c-net-071"], first_ts: "2026-11-01 10:00:00", last_ts: "2026-11-01 10:05:00", level: "medium", unassigned: 1 }]);
});

test("scanGroupIncidents: неподсеть в запрос не попадает", async (t) => {
  let calls = 0;
  t.mock.method(globalThis, "fetch", async () => { calls++; return new Response(""); });
  assert.deepEqual(await scanGroupIncidents("203.0.113.7' OR '1'='1"), []);
  assert.equal(calls, 0);
});
