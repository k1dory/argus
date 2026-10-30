// Свободный поиск на живом ClickHouse: новое условие (подстрока по полям +
// предфильтр по n-граммному индексу idx_text) находит ровно то же, что прежний
// positionCaseInsensitiveUTF8 по склейке полей, и индекс действительно
// применяется к условию, которое собирает buildWhere (EXPLAIN indexes=1).
// Нужен сервер: ARGUS_TEST_CLICKHOUSE_URL (+ _USER, _PASSWORD), БД argus;
// без него тест пропускается. Таблицы между прогонами не чистятся — фикстура
// помечена своим source/агентом на прогон.
import { test } from "node:test";
import assert from "node:assert/strict";
import { readdirSync, readFileSync } from "node:fs";
import path from "node:path";

const url = process.env.ARGUS_TEST_CLICKHOUSE_URL;
const skip = url ? false : "нет ARGUS_TEST_CLICKHOUSE_URL — тест живого ClickHouse пропущен";
if (url) {
  process.env.CLICKHOUSE_URL = url;
  process.env.CLICKHOUSE_USER = process.env.ARGUS_TEST_CLICKHOUSE_USER ?? "default";
  process.env.CLICKHOUSE_PASSWORD = process.env.ARGUS_TEST_CLICKHOUSE_PASSWORD ?? "";
  process.env.CLICKHOUSE_DB = "argus";
}

/* eslint-disable @typescript-eslint/no-require-imports -- модули читают env при загрузке */
const ch = () => require("../src/lib/clickhouse") as typeof import("../src/lib/clickhouse");
const s = () => require("../src/lib/search") as typeof import("../src/lib/search");
/* eslint-enable @typescript-eslint/no-require-imports */

const root = path.resolve(__dirname, "../..");
const RUN = `r${Date.now().toString(36)}`;
const SRC = `search.test.${RUN}`;
const AGENT = `agent-${RUN}`;
/** Прежняя склейка полей поиска по событиям (до миграции 0030). */
const OLD_HAY = "concat(raw, ' ', actor_name, ' ', object, ' ', node, ' ', src_ip, ' ', dst_ip, ' ', action, ' ', toString(attrs))";

async function applyMigrations(): Promise<void> {
  const files = readdirSync(path.join(root, "clickhouse/migrations")).filter((f) => f.endsWith(".sql")).sort();
  for (const f of files) {
    const text = readFileSync(path.join(root, "clickhouse/migrations", f), "utf8").replace(/^--.*$/gm, "");
    for (const stmt of text.split(/;\s*\n/).map((x) => x.trim()).filter(Boolean)) await ch().chCommand(stmt);
  }
}

const now = () => new Date().toISOString().replace("T", " ").replace("Z", "");
type Ev = { raw?: string; actor_name?: string; object?: string; node?: string; src_ip?: string; dst_ip?: string; action?: string; attrs?: Record<string, string>; severity?: number };
const FIXTURE: Ev[] = [
  { raw: "Accepted publickey for ROOT from 198.51.100.7 port 22", actor_name: "root", node: "web-01", action: "auth.login" },
  { raw: "Пароль пользователя сменён администратором", actor_name: "a.sidorova", action: "user.change" },
  // Поток без raw: найти можно только по полям и атрибутам.
  { raw: "", src_ip: "10.1.2.3", dst_ip: "203.0.113.77", action: "flow", attrs: { comment: "Beacon-XYZ seen", scope: "outbound" } },
  { raw: "promo 50%_off it's here", object: "/var/www/шаблон.html" },
  // Фраза через границу полей: «deploy» в конце raw, «hostgroup» — субъект.
  { raw: "job finished by deploy", actor_name: "hostgroup", severity: 9 },
  { raw: "nothing interesting here", node: "db-02" },
];

async function insertFixture(): Promise<void> {
  const ts = now();
  const lines = FIXTURE.map((e) => JSON.stringify({ ts, source: SRC, source_class: "syslog", severity: e.severity ?? 3, raw: e.raw ?? "", actor_name: e.actor_name ?? "", object: e.object ?? "", node: e.node ?? "", src_ip: e.src_ip ?? "", dst_ip: e.dst_ip ?? "", action: e.action ?? "", attrs: e.attrs ?? {} }));
  await ch().chCommand(`INSERT INTO events FORMAT JSONEachRow\n${lines.join("\n")}`);
  const alerts = [
    { timestamp: ts.slice(0, 19), agent_name: AGENT, rule_id: 5712, rule_level: 10, rule_description: "sshd brute force", raw: '{"full_log":"sshd: Brute Force trying to get access from 203.0.113.9"}' },
    { timestamp: ts.slice(0, 19), agent_name: AGENT, rule_id: 5501, rule_level: 3, rule_description: "login", raw: '{"full_log":"session opened for user root"}' },
  ];
  await ch().chCommand(`INSERT INTO wazuh_alerts FORMAT JSONEachRow\n${alerts.map((a) => JSON.stringify(a)).join("\n")}`);
}

async function countNew(q: string, index: "events" | "alerts" = "events"): Promise<number> {
  const scoped = index === "events" ? `source:"${SRC}" ${q}` : `agent:"${AGENT}" ${q}`;
  const b = s().buildWhere({ index, q: scoped, range: "24h", page: 1, showMuted: true });
  assert.equal(b.error, null, q);
  const table = index === "events" ? "events" : "wazuh_alerts";
  const rows = await ch().chQuery<{ n: string }>(`SELECT count() AS n FROM ${table} WHERE ${b.where}`, b.params);
  return Number(rows[0].n);
}

async function countOld(value: string): Promise<number> {
  const rows = await ch().chQuery<{ n: string }>(`SELECT count() AS n FROM events WHERE source = {s:String} AND positionCaseInsensitiveUTF8(${OLD_HAY}, {v:String}) > 0`, { s: SRC, v: value });
  return Number(rows[0].n);
}

test("свободный текст: те же совпадения, что у прежнего предиката; индекс idx_text применяется", { skip }, async (t) => {
  await applyMigrations();
  await insertFixture();

  await t.test("одиночные слова и фразы — как раньше", async () => {
    const cases: [string, number][] = [
      ["root", 1], // ROOT в raw, root в actor_name — одна запись
      ["publickey", 1],
      ["198.51.100.7", 1],
      ["ПАРОЛЬ", 1], // регистр кириллицы
      ["сменён", 1],
      ["beacon-xyz", 1], // только в attrs, у записи пустой raw
      ["outbound", 1],
      ["203.0.113.77", 1], // только в dst_ip
      ["шаблон", 1], // object
      ["50%_off", 1], // % и _ — буквально, не маска LIKE
      ["50_off", 0],
      ["it's", 1],
      ["comment", 1], // ключ атрибута — тоже текст записи, как в toString(attrs)
      ["deploy hostgroup", 1], // фраза через границу полей
      ["deployhostgroup", 0], // а склейка без пробела — не совпадение
      ["web-01", 1],
      ["nosuchthing-zz", 0],
      ["22", 1], // короче 4 байт — без предфильтра по индексу, поиск тот же
    ];
    for (const [qv, want] of cases) {
      const term = /\s/.test(qv) ? `"${qv}"` : qv;
      assert.equal(await countNew(term), want, `new: ${qv}`);
      assert.equal(await countOld(qv), want, `old: ${qv}`);
    }
    // отрицание и сочетание с полем
    assert.equal(await countNew("-root"), FIXTURE.length - 1);
    assert.equal(await countNew("action:flow beacon"), 1);
    assert.equal(await countNew("action:flow root"), 0);
  });

  await t.test("алерты: подстрока в raw, фраза целиком", async () => {
    assert.equal(await countNew('"brute force"', "alerts"), 1);
    assert.equal(await countNew("BRUTE", "alerts"), 1);
    assert.equal(await countNew("root", "alerts"), 1);
    assert.equal(await countNew("nosuchthing", "alerts"), 0);
  });

  await t.test("EXPLAIN: индекс idx_text выбран для условия из buildWhere (и у алертов)", async () => {
    for (const [index, table] of [["events", "events"], ["alerts", "wazuh_alerts"]] as const) {
      const b = s().buildWhere({ index, q: "zxqrare1token", range: "24h", page: 1, showMuted: true });
      const plan = await ch().chQuery<{ explain: string }>(`EXPLAIN indexes = 1 SELECT count() FROM ${table} WHERE ${b.where}`, b.params);
      const text = plan.map((r) => r.explain).join("\n");
      assert.match(text, /Name: idx_text/, `${table}:\n${text}`);
    }
  });

  await t.test("search(): страница, итог и фасеты по выборке", async () => {
    const r = await s().search({ index: "events", q: `source:"${SRC}" beacon-xyz`, range: "24h", page: 1 });
    assert.equal(r.error, null);
    assert.equal(r.rows.length, 1);
    assert.equal(r.total, 1);
    assert.equal(r.total_exact, true);
    assert.deepEqual(r.incomplete, []);
    assert.equal(r.facets_sample, 1);
    assert.deepEqual(r.facets.find((f) => f.field === "src")?.values, [{ value: "10.1.2.3", count: 1 }]);
    const all = await s().search({ index: "events", q: `source:"${SRC}"`, range: "24h", page: 1 });
    assert.equal(all.total, FIXTURE.length);
    assert.equal(all.facets_sample, FIXTURE.length);
    assert.equal(all.series.reduce((n, p) => n + p.critical, 0), 1, "severity 9 — critical");
  });

  await t.test("выгрузка — то же условие", async () => {
    const r = await s().searchExport({ index: "events", q: `source:"${SRC}" сменён`, range: "24h", page: 1 }, 100, false);
    assert.equal(r.error, null);
    assert.equal(r.rows.length, 1);
    assert.equal(r.rows[0].raw, undefined, "raw=0 — без исходной строки");
  });
});
