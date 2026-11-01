// Диапазонные фильтры консоли на живом ClickHouse: настоящие запросы витрин
// (журнал алертов, агенты, MITRE, CVE, лента «Источников», очередь инцидентов)
// принимают параметры диапазонов, сужают выдачу и не ломают SQL; условие окна
// по времени отсекает партиции и гранулы (EXPLAIN indexes = 1), как требует
// стоимость консоли. Фикстура — отдельная база одним партом на месяц: чужие
// строки в общей argus не влияют на подсчёт гранул.
import { after, before, test } from "node:test";
import assert from "node:assert/strict";
import { randomBytes } from "node:crypto";
import { readdirSync } from "node:fs";
import { MIGRATIONS_DIR, ch, liveSkip as skip, migrationStatements, serializeLiveFile } from "./_ch-live";
import { toChParam, toDtParam } from "../src/lib/shared/filters";

serializeLiveFile({ before, after });

/* eslint-disable @typescript-eslint/no-require-imports -- ClickHouse env установлен _ch-live до загрузки модулей */
const queries = () => require("../src/lib/queries") as typeof import("../src/lib/queries");
const argus = () => require("../src/lib/argus-queries") as typeof import("../src/lib/argus-queries");
/* eslint-enable @typescript-eslint/no-require-imports */

type Plan = { parts: [number, number]; granules: [number, number]; text: string };

/** Стадии плана по порядку (MinMax → Partition → PrimaryKey → Skip): parts — первая стадия
 *  (сколько партиций осталось из всех), granules — итог последней стадии из всех гранул таблицы. */
function planOf(text: string): Plan {
  const all = (re: RegExp): [number, number][] => {
    const found = [...text.matchAll(re)].map((m) => [Number(m[1]), Number(m[2])] as [number, number]);
    assert.ok(found.length > 0, `EXPLAIN без ${re}:\n${text}`);
    return found;
  };
  const parts = all(/Parts:\s*(\d+)\s*\/\s*(\d+)/g);
  const granules = all(/Granules:\s*(\d+)\s*\/\s*(\d+)/g);
  return { parts: parts[0], granules: [granules[granules.length - 1][0], granules[0][1]], text };
}

test("диапазоны витрин на живом ClickHouse: сужают выдачу и отсекают партиции/гранулы", { skip }, async (t) => {
  const db = `argus_range_${randomBytes(6).toString("hex")}`;
  let database = "default", created = false;
  let explain: RegExp | null = null;
  const plans: string[] = [];
  const nativeFetch = globalThis.fetch;
  t.mock.method(globalThis, "fetch", async (input: URL | string | Request, init?: RequestInit) => {
    const url = new URL(input instanceof Request ? input.url : String(input));
    url.searchParams.set("database", database);
    const body = String(init?.body ?? "");
    // Режим EXPLAIN: тот же SQL и те же параметры, что отправила витрина.
    if (explain && explain.test(body)) {
      const r = await nativeFetch(url, { ...init, body: `EXPLAIN indexes = 1 ${body}` });
      const text = await r.text();
      plans.push(text.split("\n").filter(Boolean).map((l) => (JSON.parse(l) as { explain: string }).explain).join("\n"));
      return new Response("", { status: r.status, headers: r.headers });
    }
    return nativeFetch(url, init);
  });

  // Три месяца назад, два, один: по партиции toYYYYMM на месяц, внутри — по часу.
  const now = new Date(Date.now());
  const month = (back: number) => Date.UTC(now.getUTCFullYear(), now.getUTCMonth() - back, 10, 0, 0, 0);
  const months = [month(3), month(2), month(1)];
  const ROWS = 3 * 8192; // три гранулы на месяц

  try {
    created = true;
    await ch().chCommand(`CREATE DATABASE ${db}`);
    database = db;
    for (const file of readdirSync(MIGRATIONS_DIR).filter((f) => f.endsWith(".sql")).sort()) {
      for (const sql of migrationStatements(file)) {
        if (/^CREATE DATABASE\b/i.test(sql)) continue;
        await ch().chCommand(sql.replaceAll("argus.", `${db}.`));
      }
    }

    // wazuh_alerts: уровень 1..15 по кругу, агент web-01/db-01, техника у каждого пятого, CVE — отдельными строками ниже.
    for (const start of months) {
      await ch().chCommand(`INSERT INTO wazuh_alerts (timestamp, agent_id, agent_name, rule_id, rule_level, rule_description, mitre_ids, mitre_techniques, mitre_tactics)
        SELECT toDateTime64({start:String}, 3, 'UTC') + toIntervalSecond(number * 10), if(number % 2 = 0, '001', '002'), if(number % 2 = 0, 'web-01', 'db-01'),
          5700 + number % 15, 1 + number % 15, 'fixture', if(number % 5 = 0, ['T1110'], []), if(number % 5 = 0, ['Brute Force'], []), if(number % 5 = 0, ['Credential Access'], [])
        FROM numbers({n:UInt32})`, { start: toChParam(start), n: ROWS });
      // events: received_at = ts, серьёзность 0..9.
      await ch().chCommand(`INSERT INTO events (ts, received_at, source, source_class, action, outcome, severity, actor_name, node)
        SELECT toDateTime64({start:String}, 3, 'UTC') + toIntervalSecond(number * 10), toDateTime({start:String}, 'UTC') + toIntervalSecond(number * 10),
          'range.fixture', 'syslog', 'auth.login', 'success', number % 10, 'u', 'n'
        FROM numbers({n:UInt32})`, { start: toChParam(start), n: ROWS });
    }

    // Окно — первые сутки последнего месяца: внутри одной партиции, одна гранула из трёх.
    const from = months[2], to = months[2] + 86_400_000;
    const time = { from: toDtParam(from), to: toDtParam(to) };

    await t.test("журнал алертов: окно и уровень от–до — точный счёт, одна партиция", async () => {
      const all = await queries().alertsList({ range: "24h", time, showMuted: true });
      // По алерту в 10 с; обе границы окна включительно — 8641, уровни по кругу 1..15.
      assert.equal(all.total, 8641);
      const lvl = await queries().alertsList({ range: "24h", time, minLevel: 7, maxLevel: 9, showMuted: true });
      assert.equal(lvl.total, 8640 * 3 / 15);
      assert.ok(lvl.rows.every((r) => r.rule_level >= 7 && r.rule_level <= 9));
      explain = /SELECT timestamp, agent_name, rule_id/;
      await queries().alertsList({ range: "24h", time, minLevel: 7, showMuted: true });
      explain = null;
      const p = planOf(plans.pop()!);
      assert.deepEqual(p.parts, [1, 3], `окно отсекает партиции чужих месяцев:\n${p.text}`);
      assert.ok(p.granules[0] < p.granules[1], `и гранулы по первичному ключу timestamp:\n${p.text}`);
    });

    await t.test("агенты и MITRE: уровень и пороги итогов (HAVING)", async () => {
      const agents = await queries().agentsSummary(time, { level: { min: 15 } });
      // Уровень 15 — у каждой 15-й строки; номера 14, 29, … чередуют чётность — оба агента.
      assert.deepEqual(agents.map((a) => a.agent_name).sort(), ["db-01", "web-01"]);
      // 8641 алерт в окне: web-01 (чётные номера) — 4321, db-01 — 4320.
      assert.deepEqual((await queries().agentsSummary(time, { alerts: { min: 4321 } })).map((a) => a.agent_name), ["web-01"]);
      assert.deepEqual((await queries().agentsSummary(time, { alerts: { max: 4320 } })).map((a) => a.agent_name), ["db-01"]);
      assert.deepEqual(await queries().agentsSummary(time, { alerts: { min: 5000 } }), []);
      const tech = await queries().topTechniques(time, 20, { min: 1 });
      assert.equal(tech[0]?.id, "T1110");
      const techHigh = await queries().topTechniques(time, 20, { min: 14, max: 14 });
      // Техника — у number % 5 = 0, уровень 14 — у number % 15 = 13: не пересекаются.
      assert.deepEqual(techHigh, []);
    });

    await t.test("CVE: серьёзность по шкале и CVSS — HAVING по последней записи", async () => {
      await ch().chCommand(`INSERT INTO wazuh_alerts (timestamp, agent_name, rule_id, rule_level, vuln_cve, vuln_severity, vuln_score, vuln_package, vuln_status) VALUES
        (now64(3) - 60, 'web-01', 23505, 10, 'CVE-2026-0001', 'Critical', 9.8, 'openssl', 'Active'),
        (now64(3) - 60, 'web-01', 23505, 7, 'CVE-2026-0002', 'High', 7.5, 'curl', 'Active'),
        (now64(3) - 60, 'db-01', 23505, 3, 'CVE-2026-0003', 'Low', 2.1, 'vim', 'Active')`);
      const cves = async (f: Parameters<ReturnType<typeof queries>["vulnList"]>[0]) => (await queries().vulnList(f)).map((v) => v.cve).sort();
      assert.deepEqual(await cves({}), ["CVE-2026-0001", "CVE-2026-0002", "CVE-2026-0003"]);
      assert.deepEqual(await cves({ severity: { min: "High" } }), ["CVE-2026-0001", "CVE-2026-0002"]);
      assert.deepEqual(await cves({ severity: { max: "High" } }), ["CVE-2026-0002", "CVE-2026-0003"]);
      assert.deepEqual(await cves({ cvss: { min: 7, max: 9 } }), ["CVE-2026-0002"]);
      assert.deepEqual(await cves({ time }), [], "окно месяц назад — свежих CVE в нём нет");
    });

    await t.test("лента «Источников»: окно по received_at (skip-индекс) и серьёзность", async () => {
      const rows = await argus().eventsRecent("range.fixture", 1000, { time, severity: { min: 8 } });
      assert.equal(rows.length, 1000);
      assert.ok(rows.every((r) => r.severity >= 8));
      explain = /FROM events WHERE/;
      await argus().eventsRecent("range.fixture", 60, { time });
      explain = null;
      const p = planOf(plans.pop()!);
      assert.ok(p.granules[0] < p.granules[1], `minmax idx_received_at отсекает гранулы вне окна:\n${p.text}`);
    });

    await t.test("очередь инцидентов: окно по first_ts, уровень по шкале, событий от–до", async () => {
      const add = (id: string, level: string, events: number, firstMs: number) => ch().chCommand(
        `INSERT INTO incidents (incident_id, created_at, updated_at, rule_id, rule_title, level, tags, status, owner, actor_name, event_count, first_ts, last_ts)
         VALUES ({id:String}, now(), now(), 'r', 'range fixture', {level:String}, [], 'new', '', 'u', {events:UInt32}, toDateTime64({first:String}, 3, 'UTC'), toDateTime64({first:String}, 3, 'UTC'))`,
        { id, level, events, first: toChParam(firstMs) });
      await add("INC-R1", "critical", 40, from + 3_600_000);
      await add("INC-R2", "medium", 3, from + 3_600_000);
      await add("INC-R3", "high", 12, months[0]);
      const ids = async (ranges: Parameters<ReturnType<typeof argus>["incidentsList"]>[0]) => (await argus().incidentsList({ q: "range fixture", ...ranges })).rows.map((r) => r.incident_id).sort();
      assert.deepEqual(await ids({}), ["INC-R1", "INC-R2", "INC-R3"]);
      assert.deepEqual(await ids({ ranges: { level: { min: "high" } } }), ["INC-R1", "INC-R3"]);
      assert.deepEqual(await ids({ ranges: { level: { max: "high" } } }), ["INC-R2", "INC-R3"]);
      assert.deepEqual(await ids({ ranges: { time } }), ["INC-R1", "INC-R2"]);
      assert.deepEqual(await ids({ ranges: { events: { min: 10 }, time } }), ["INC-R1"]);
      assert.deepEqual(await ids({ level: "medium", ranges: { events: { max: 5 } } }), ["INC-R2"], "точный level и диапазон — вместе");
      assert.deepEqual(await ids({ ranges: { time: { range: "1h" } } }), [], "first_ts фикстуры старше часа");
    });
  } finally {
    database = "default";
    if (created) await ch().chCommand(`DROP DATABASE IF EXISTS ${db}`);
  }
});
