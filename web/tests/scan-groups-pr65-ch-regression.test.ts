// PR #65: поведенческие проверки настоящего SQL, без эмуляции IP-функций/агрегатов.
// Запускать только на отдельном тестовом ClickHouse через ARGUS_TEST_CLICKHOUSE_URL.
// Без него используется обычный skip существующего раннера web/tests.
import { after, before, test } from "node:test";
import assert from "node:assert/strict";
import { randomUUID } from "node:crypto";
import { applyAllMigrations, ch, liveSkip as skip, serializeLiveFile } from "./_ch-live";
import { subnetSQL } from "../src/lib/shared/scan-groups";

serializeLiveFile({ before, after });
before(async () => { if (!skip) await applyAllMigrations(); });

/* eslint-disable @typescript-eslint/no-require-imports -- env живого CH задаётся до загрузки запросов */
const queries = () => require("../src/lib/argus-queries") as typeof import("../src/lib/argus-queries");
/* eslint-enable @typescript-eslint/no-require-imports */

const stamp = (agoSeconds = 0) => new Date(Date.now() - agoSeconds * 1000).toISOString().slice(0, 19).replace("T", " ");
const fixtureKey = () => `pr65-${randomUUID()}`;

async function insertIncidents(run: string, input: { actor: string; rule?: string; status?: string }[]) {
  const ts = stamp();
  const rows = input.map((item, i) => ({
    incident_id: `INC-${run}-${String(i).padStart(4, "0")}`, created_at: ts, updated_at: ts,
    rule_id: item.rule ?? "a41c-net-070", rule_title: `Fixture ${run}`, level: "medium", tags: [],
    status: item.status ?? "new", owner: "", actor_name: item.actor, node: "fixture-edge",
    sources: ["netflow"], first_ts: ts, last_ts: ts, event_count: 50,
  }));
  await ch().chCommand("INSERT INTO incidents FORMAT JSONEachRow\n" + rows.map((r) => JSON.stringify(r)).join("\n"));
  return rows.map((r) => r.incident_id);
}

async function subnetResults(inputs: string[]): Promise<Record<string, string>> {
  const params = Object.fromEntries(inputs.map((value, i) => [`address${i}`, value]));
  const addresses = inputs.map((_, i) => `{address${i}:String}`).join(", ");
  const rows = await ch().chQuery<{ input_addr: string; subnet: string }>(
    `SELECT input_addr, ${subnetSQL("input_addr")} AS subnet FROM (SELECT arrayJoin([${addresses}]) AS input_addr)`, params,
  );
  return Object.fromEntries(rows.map((r) => [r.input_addr, r.subnet]));
}

test("PR65 control: IPv4/IPv6/пустой src и не-адрес вычисляются реальным ClickHouse", { skip }, async () => {
  const expected = {
    "203.0.113.7": "203.0.113.0/24",
    " 203.0.113.9 ": "203.0.113.0/24",
    "::ffff:203.0.113.7": "203.0.113.0/24",
    "2001:0DB8:0001:0000:0000:0000:0000:0007": "2001:db8:1::/48",
    "2001:db8:1:abcd::9": "2001:db8:1::/48",
    "2001:db8:2::9": "2001:db8:2::/48",
    "": "", "   ": "", "exporter-1": "",
  };
  assert.deepEqual(await subnetResults(Object.keys(expected)), expected);
});

test("PR65: mapped IPv6 в hex/полной записи сохраняет именно IPv4 /24", { skip }, async () => {
  const expected = {
    "::ffff:cb00:7107": "203.0.113.0/24",
    "0:0:0:0:0:ffff:203.0.113.7": "203.0.113.0/24",
    "0000:0000:0000:0000:0000:FFFF:CB00:7107": "203.0.113.0/24",
    "::ffff:c633:6407": "198.51.100.0/24",
  };
  assert.deepEqual(await subnetResults(Object.keys(expected)), expected,
    "разные IPv4-подсети нельзя сливать в общую ::/48 из-за формы записи адреса");
});

test("PR65: число адресов не зависит от пробелов, mapped и формы записи IPv6", { skip }, async () => {
  const run = fixtureKey();
  await insertIncidents(run, [
    { actor: "203.0.113.7" },
    { actor: " 203.0.113.7 ", rule: "a41c-net-071" },
    { actor: "::ffff:203.0.113.7", rule: "a41c-net-072" },
    { actor: "2001:db8:65::7" },
    { actor: "2001:0DB8:0065:0000:0000:0000:0000:0007", rule: "a41c-net-071" },
  ]);
  const groups = await queries().scanGroups({ q: run });
  assert.deepEqual(groups.map((g) => [g.subnet, g.incidents, g.addresses]).sort(), [
    ["2001:db8:65::/48", 2, 1], ["203.0.113.0/24", 3, 1],
  ], "у каждой подсети один источник, с несколькими инцидентами по разным правилам");
});

test("PR65: 101-я группа доступна следующей страницей после исключения сканов из очереди", { skip }, async () => {
  const run = fixtureKey();
  await insertIncidents(run, Array.from({ length: 101 }, (_, i) => ({ actor: `198.18.${i}.1` })));
  const flat = await queries().incidentsList({ q: run, groupScans: true });
  assert.equal(flat.total, 0, "все 101 инцидент удалены из обычной очереди режимом группировки");
  const first = await queries().scanGroups({ q: run, page: 1 }, 100);
  const second = await queries().scanGroups({ q: run, page: 2 }, 100);
  assert.equal(new Set([...first, ...second].map((g) => g.subnet)).size, 101,
    "после первых 100 нужен переход к остальным: смена page не должна повторять те же группы");
});

test("PR65: раскрытие подсети позволяет дойти до 501-го открытого инцидента", { skip }, async () => {
  const run = fixtureKey();
  const ids = await insertIncidents(run, Array.from({ length: 501 }, (_, i) => ({ actor: `2001:db8:65:${i.toString(16)}::7` })));
  const groups = await queries().scanGroups({ q: run });
  assert.equal(groups[0].incidents, 501);
  const first = await queries().scanGroupIncidents("2001:db8:65::/48", { q: run, page: 1 });
  const second = await queries().scanGroupIncidents("2001:db8:65::/48", { q: run, page: 2 });
  assert.deepEqual([...new Set([...first, ...second].map((r) => r.incident_id))].sort(), ids.sort(),
    "LIMIT 500 не должен навсегда скрывать хвост группы за одним и тем же набором строк");
});

type ResponseFixture = {
  ts: string; incident_id: string; ip: string; executor: string; ok: number; detail: string;
};
async function insertResponses(rows: ResponseFixture[]) {
  await ch().chCommand("INSERT INTO response_log FORMAT JSONEachRow\n" + rows.map((r) => JSON.stringify({
    rule_id: "a41c-net-070", mode: "ips", dry_run: 0, reason: "PR65 fixture", actor: "argus-engine", ...r,
  })).join("\n"));
}

test("PR65: ожидание доверенных событий видно при пустом ip в response_log", { skip }, async () => {
  const [id] = await insertIncidents(fixtureKey(), [{ actor: "203.0.113.7" }]);
  // autoRespond в engine/cmd/engine/respond.go пишет waiting до выбора IP:
  // Incident и Detail заполнены, IP у respond.Result остаётся пустым.
  await insertResponses([{
    ts: stamp(), incident_id: id, ip: "", executor: "argus", ok: 0,
    detail: "ожидание: доверенных событий 0 из 1 (respond.min_events) — блокировка после следующего доверенного события в окне",
  }]);
  assert.deepEqual(await queries().incidentBlockStates([id]), { [id]: "waiting" });
});

test("PR65: снятие общего IP не оставляет второй инцидент в состоянии «заблокирован»", { skip }, async () => {
  const ip = `2001:db8:${randomUUID().slice(0, 4)}:${randomUUID().slice(0, 4)}::7`;
  const [original, second] = await insertIncidents(fixtureKey(), [
    { actor: ip }, { actor: ip, rule: "a41c-net-071" },
  ]);
  // auto() хранит active по IP: второй инцидент получает Noop, а Expire/Unblock
  // записывает снятие только с Incident первоначального Block.
  await insertResponses([
    { ts: stamp(3), incident_id: original, ip, executor: "ngfw.edge", ok: 1, detail: "POST" },
    { ts: stamp(2), incident_id: second, ip, executor: "argus", ok: 1, detail: `уже заблокирован до ${new Date(Date.now() - 1000).toISOString()}` },
    { ts: stamp(1), incident_id: original, ip, executor: "ngfw.edge.unblock", ok: 1, detail: `разблокирован ${ip}` },
  ]);
  const states = await queries().incidentBlockStates([original, second]);
  assert.equal(states[original], "released", "положительный контроль: исходный инцидент видит снятие");
  assert.equal(states[second], "released", "тот же уже разблокированный IP не должен считаться заблокированным у другого правила");
  assert.equal((await queries().incidentBlockStates([second]))[second], "released",
    "снятие должно учитываться и когда первоначальный инцидент не входит в раскрытые строки");
});
