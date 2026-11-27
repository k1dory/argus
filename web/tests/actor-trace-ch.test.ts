// Трассировка на живом ClickHouse: запрос actorTrace собирает сессию
// «вход по ssh → sudo на том же узле → сеть», поток NetFlow режется до топа
// адресов на корзину, чужие события в трассу не попадают.
import { after, before, test } from "node:test";
import assert from "node:assert/strict";
import { randomBytes } from "node:crypto";
import { applyAllMigrations, ch, liveSkip as skip, serializeLiveFile } from "./_ch-live";
import { chTs } from "../src/lib/shared/log-query";
import { TRACE_NETWORK_TOP } from "../src/lib/shared/actor-trace";
import type { Alias } from "../src/lib/shared/actors";

serializeLiveFile({ before, after });

/* eslint-disable @typescript-eslint/no-require-imports -- ClickHouse env установлен _ch-live до загрузки actors */
const actors = () => require("../src/lib/actors") as typeof import("../src/lib/actors");
/* eslint-enable @typescript-eslint/no-require-imports */

test("actorTrace: вход → sudo → сеть одной сессией, сеть — топ адресов", { skip }, async () => {
  await applyAllMigrations();
  const run = randomBytes(4).toString("hex");
  const source = `actor.trace.${run}`;
  const login = `trace.user.${run}`;
  const ip = `100.104.${parseInt(run.slice(0, 2), 16)}.${parseInt(run.slice(2, 4), 16)}`;
  const node = `trace-node-${run}`;
  const fromMs = Math.floor((Date.now() - 3600_000) / 60_000) * 60_000;
  const params = { source, login, ip, node, from: chTs(fromMs) };
  const aliases: Alias[] = [
    { person_id: `trace-${run}`, kind: "login", value: login, valid_from: chTs(fromMs - 1000), valid_to: null, source: "fixture", confidence: 1, note: "" },
    { person_id: `trace-${run}`, kind: "ip", value: ip, valid_from: chTs(fromMs - 1000), valid_to: null, source: "fixture", confidence: 1, note: "" },
  ];
  const t0 = "parseDateTime64BestEffort({from:String}, 3, 'UTC')";
  // Вход по ssh с ip на узел, sudo на узле без адреса (с логином), отказ sudo,
  // 30 адресов назначения NetFlow с ip в одной минуте, чужое событие на том же узле.
  await ch().chCommand(`INSERT INTO events (ts, source, source_class, actor_name, actor_kind, src_ip, node, dst_ip, dst_port, action, outcome)
    SELECT ${t0} + toIntervalSecond(10), {source:String}, 'syslog', {login:String}, 'user', {ip:String}, {node:String}, '', 0, 'auth.ssh', 'success'
    UNION ALL SELECT ${t0} + toIntervalSecond(30 + number), {source:String}, 'syslog', {login:String}, 'user', '', {node:String}, '', 0, 'priv.sudo', if(number = 0, 'failure', 'success') FROM numbers(3)
    UNION ALL SELECT ${t0} + toIntervalSecond(40), {source:String}, 'netflow', '', '', {ip:String}, '', concat('10.77.0.', toString(number)), 443, 'flow', 'success' FROM numbers(30)
    UNION ALL SELECT ${t0} + toIntervalSecond(50), {source:String}, 'syslog', 'someone.else', 'user', '', {node:String}, '', 0, 'priv.sudo', 'success'`, params);
  try {
    const trace = await actors().actorTrace(aliases, "24h", { window: { fromMs: fromMs - 1000, toMs: fromMs + 600_000 }, now: fromMs + 600_000 });
    assert.equal(trace.truncated, false);
    assert.equal(trace.sessions.length, 1);
    const [s] = trace.sessions;
    assert.equal(s.networkOnly, false);
    assert.deepEqual(s.origins.map((o) => o.origin), [ip], "sudo без адреса привязан к входу, ветки «без адреса» нет");
    const spans = s.origins[0].spans;
    const login = spans.find((x) => x.section === "login")!;
    assert.deepEqual([login.target, login.target_kind, login.actions[0].action], [node, "node", "auth.ssh"]);
    const sudo = spans.find((x) => x.section === "host")!;
    assert.equal(sudo.count, 3, "событие someone.else на том же узле не субъекта");
    assert.equal(sudo.fails, 1);
    assert.equal(sudo.attached, true);
    const net = spans.filter((x) => x.section === "network");
    const shown = net.filter((x) => !x.folded);
    // SQL отдаёт топ на корзину, сборка — топ на источник в сессии: строк не больше TRACE_NETWORK_TOP + свёртка.
    assert.equal(shown.length, TRACE_NETWORK_TOP);
    assert.ok(shown.every((x) => x.target_kind === "dst" && x.dst_port === 443 && x.target.startsWith("10.77.0.")));
    assert.equal(net.reduce((n, x) => n + x.count, 0), TRACE_NETWORK_TOP, "в SQL сеть урезана до топа на корзину");
  } finally {
    await ch().chCommand("ALTER TABLE events DELETE WHERE source = {source:String} SETTINGS mutations_sync = 1", { source });
  }
});
