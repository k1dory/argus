// Стоимость настоящего actorReport, а не копии aliasPredicate. Редкие login/
// email сравниваются без учёта регистра; добавление IP-алиаса через OR не
// должно превращать каждый запрос паспорта в чтение всего временного окна.
// Никаких SLA по времени: проверяем результат и гранулы в EXPLAIN indexes=1.
//
// План детерминирован. Фикстура лежит в отдельной базе одним партом, без чужих
// строк в окне: в общей argus соседний парт добавлял гранулы к базе сравнения,
// и «меньше окна» проходило даже без отсечения. Значения алиасов постоянные:
// у bloom_filter(0.01) около 1 % случайных login ложно совпадали с фоновой
// группой гранул, и тест падал через раз. Постоянные значения проверены против
// постоянного фона; если обновление ClickHouse сменит хеш, тест упадёт сразу и
// всегда, тогда нужно выбрать другие значения.
import { after, before, test } from "node:test";
import assert from "node:assert/strict";
import { randomBytes } from "node:crypto";
import { readdirSync } from "node:fs";
import { MIGRATIONS_DIR, ch, liveSkip as skip, migrationStatements, serializeLiveFile } from "./_ch-live";
import { chTs } from "../src/lib/shared/log-query";
import type { Alias, AliasKind, Person } from "../src/lib/shared/actors";

serializeLiveFile({ before, after });

/* eslint-disable @typescript-eslint/no-require-imports -- ClickHouse env установлен _ch-live до загрузки actors */
const actors = () => require("../src/lib/actors") as typeof import("../src/lib/actors");
/* eslint-enable @typescript-eslint/no-require-imports */

type Query = { sql: string; params: Record<string, string | number> };
async function granules(query: Query): Promise<{ selected: number; text: string }> {
  const rows = await ch().chQuery<{ explain: string }>(`EXPLAIN indexes = 1 ${query.sql}`, query.params);
  const text = rows.map((r) => r.explain).join("\n");
  // У агрегаций и выборок разделов один events-read. Последняя строка Granules — результат
  // после всех индексов, не только отбор партиций/первичного ключа по времени.
  const stages = [...text.matchAll(/Granules:\s*(\d+)\s*\/\s*(\d+)/g)];
  assert.ok(stages.length > 0, `EXPLAIN должен показать чтение гранул:\n${text}`);
  return { selected: Number(stages[stages.length - 1][1]), text };
}

test("actorReport: редкий login/email с IP-алиасом сохраняет результат и отсекает гранулы", { skip }, async (t) => {
  const db = `argus_actors_cost_${randomBytes(6).toString("hex")}`;
  const source = "actor.cost.fixture";
  const login = "rare.user.fixture";
  const email = "rare.fixture@example.test";
  const ip = "2001:db8:a5::7";
  let database = "default", created = false;
  const nativeFetch = globalThis.fetch;
  t.mock.method(globalThis, "fetch", (input: URL | string | Request, init?: RequestInit) => {
    const url = new URL(input instanceof Request ? input.url : String(input));
    url.searchParams.set("database", database);
    return nativeFetch(url, init);
  });
  // Середина прошлого месяца: окно и INSERT целиком в одной партиции toYYYYMM(ts),
  // в какой бы момент ни запускался тест (now − 48h на границе месяца давало две).
  const today = new Date(Date.now());
  const window = { fromMs: Date.UTC(today.getUTCFullYear(), today.getUTCMonth() - 1, 15, 12), toMs: 0 };
  window.toMs = window.fromMs + 66_000;
  const params = { source, login, email, ip, from: chTs(window.fromMs), to: chTs(window.toMs) };
  const person: Person = { person_id: "cost-fixture", display: "Cost fixture", kind: "person", team: "test", note: "" };
  const alias = (kind: AliasKind, value: string): Alias => ({
    person_id: person.person_id, kind, value, valid_from: params.from, valid_to: null,
    source: "fixture", confidence: 1, note: "",
  });
  const sections = ["login", "host", "network", "app", "change"] as const;
  const idsFrom = (...starts: number[]) => starts.flatMap((start) => sections.map((_, i) => String(start + i))).sort();

  // 65536 коротких строк => не менее восьми гранул. По пять событий каждого
  // вида совпадения (login/email в обоих регистрах и IP) лежат в первой.
  // Во всех гранулах есть все пять разделов, включая фоновые события:
  // фильтр раздела не может выдать отсечение за поиск редкого алиаса.
  // Окно охватывает весь INSERT, так что первичный ключ по ts тоже не помогает.
  try {
    // Все миграции по порядку, как migrate.sh, но в отдельной базе. Флаг — до
    // CREATE: ответ может потеряться после того, как сервер базу уже создал.
    created = true;
    await ch().chCommand(`CREATE DATABASE ${db}`);
    database = db;
    for (const file of readdirSync(MIGRATIONS_DIR).filter((f) => f.endsWith(".sql")).sort()) {
      for (const sql of migrationStatements(file)) {
        // CREATE DATABASE argus из 0001 создал бы на чистом сервере общую базу.
        if (/^CREATE DATABASE\b/i.test(sql)) continue;
        await ch().chCommand(sql.replaceAll("argus.", `${db}.`));
      }
    }
    await ch().chCommand(`INSERT INTO events (ts, source, source_class, actor_name, actor_kind, src_ip, node, action, outcome, attrs)
    SELECT parseDateTime64BestEffort({from:String}, 3, 'UTC') + toIntervalMillisecond(number),
      {source:String}, 'syslog',
      multiIf(number >= 1230 AND number < 1235, {login:String}, number >= 1235 AND number < 1240, upperUTF8({login:String}),
        number >= 1500 AND number < 1505, {email:String}, number >= 1505 AND number < 1510, upperUTF8({email:String}), 'unrelated-background'),
      'user', if(number >= 2045 AND number < 2050, {ip:String}, '192.0.2.254'), 'fixture-node',
      ['auth.login', 'sudo.command', 'net.connection', 'app.open', 'file.modify'][1 + number % 5], 'success',
      map('fixture_row', toString(number))
    FROM numbers(65536)`, params);
    const [parts] = await ch().chQuery<{ parts: string | number; marks: string | number }>(
      "SELECT count() AS parts, sum(marks) AS marks FROM system.parts WHERE database = currentDatabase() AND table = 'events' AND active");
    // Один парт: сливать фоновому merge нечего, границы групп индекса постоянны.
    assert.equal(Number(parts.parts), 1, "фикстура пишется одним партом");
    const baseline = await granules({
      sql: `SELECT actor_name, src_ip FROM events
        WHERE ts >= parseDateTime64BestEffort({from:String}, 3, 'UTC') AND ts < parseDateTime64BestEffort({to:String}, 3, 'UTC')`,
      params,
    });
    assert.equal(baseline.selected, 8, `фикстура занимает две группы skip-индекса по четыре гранулы:\n${baseline.text}`);

    const cases: { name: string; aliases: Alias[]; ids: string[] }[] = [
      { name: "login без учёта регистра", aliases: [alias("login", login)], ids: idsFrom(1230, 1235) },
      { name: "email без учёта регистра", aliases: [alias("email", email)], ids: idsFrom(1500, 1505) },
      { name: "login OR src_ip", aliases: [alias("login", login), alias("ip", ip)], ids: idsFrom(1230, 1235, 2045) },
      { name: "email OR src_ip", aliases: [alias("email", email), alias("ip", ip)], ids: idsFrom(1500, 1505, 2045) },
    ];
    for (const scenario of cases) {
      await t.test(scenario.name, async (caseTest) => {
        const captured: Query[] = [];
        const fetch = globalThis.fetch;
        const spy = caseTest.mock.method(globalThis, "fetch", async (input: URL | string | Request, init?: RequestInit) => {
          const sql = String(init?.body ?? "");
          if (/^\s*SELECT\b/i.test(sql) && /\bFROM\s+events\b/i.test(sql)) {
            const url = new URL(input instanceof Request ? input.url : String(input));
            const bound = Object.fromEntries([...url.searchParams].filter(([k]) => k.startsWith("param_")).map(([k, v]) => [k.slice(6), v]));
            captured.push({ sql, params: bound });
          }
          // Ответы настоящего ClickHouse; spy лишь сохраняет отправленный SQL.
          return fetch(input, init);
        });
        const report = await actors().actorReport(person, scenario.aliases, "7d", 20, { window, now: window.toMs });
        spy.mock.restore();
        assert.deepEqual(report.missing, [], "ошибку запроса нельзя принять за дешёвый пустой ответ");
        assert.equal(report.summary.events, scenario.ids.length);
        assert.deepEqual(report.timeline.map((e) => e.attrs.fixture_row).sort(), scenario.ids);
        assert.ok(report.timeline.every((e) => e.source === source));
        assert.equal(report.sources.reduce((n, row) => n + row.count, 0), scenario.ids.length);
        for (const [i, section] of sections.entries()) {
          const expected = scenario.ids.filter((id) => Number(id) % 5 === i).reverse();
          assert.deepEqual(report.sections[section].map((e) => e.attrs.fixture_row), expected,
            `${section}: оба регистра алиаса и IP сохранены, фон исключён, новые события сверху`);
          assert.ok(report.sections[section].every((e) => e.source === source));
        }

        const aggregateQueries = captured.filter((q) => /\bGROUP BY\b/i.test(q.sql));
        assert.ok(aggregateQueries.length > 0, "проверяется SQL агрегаций, фактически отправленный actorReport");
        const plans = await Promise.all(aggregateQueries.map(async (query) => ({ query, plan: await granules(query) })));
        // Редкие строки лежат в первой группе индекса, вторая — только фон: доля, а не «меньше».
        const unpruned = plans.filter(({ plan }) => plan.selected * 2 > baseline.selected);
        assert.deepEqual(unpruned.map(({ query, plan }) => ({ sql: query.sql, selected: plan.selected })), [],
          `редкий алиас должен читать не больше половины гранул окна (${baseline.selected}); планы без отсечения:\n${unpruned.map(({ plan }) => plan.text).join("\n\n")}`);

        const sectionQueries = captured.filter((q) => typeof q.params.section === "string");
        assert.deepEqual(sectionQueries.map((q) => q.params.section).sort(), [...sections].sort(),
          "проверяются все пять отдельных выборок разделов, фактически отправленных actorReport");
        const sectionPlans = await Promise.all(sectionQueries.map(async (query) => ({ query, plan: await granules(query) })));
        for (const { query, plan } of sectionPlans) {
          const bloom = plan.text.match(/Name:\s+idx_actor_keys\b[\s\S]*?Granules:\s*(\d+)\s*\/\s*(\d+)/);
          assert.ok(bloom, `${query.params.section}: применяется bloom-индекс ключей алиасов:\n${plan.text}`);
          assert.ok(Number(bloom[1]) * 2 <= Number(bloom[2]),
            `${query.params.section}: bloom-индекс должен отсечь фоновые гранулы:\n${plan.text}`);
          assert.ok(plan.selected * 2 <= baseline.selected,
            `${query.params.section}: выборка раздела читает не больше половины гранул окна (${baseline.selected}):\n${plan.text}`);
        }
      });
    }
    await t.test("aliasSightings: предфильтр idx_actor_keys при подзапросах к identity_aliases", async (caseTest) => {
      const captured: Query[] = [];
      const fetch = globalThis.fetch;
      const spy = caseTest.mock.method(globalThis, "fetch", async (input: URL | string | Request, init?: RequestInit) => {
        const sql = String(init?.body ?? "");
        if (/\bFROM\s+events\b/i.test(sql) && /\bGROUP BY source, action, actor_name, node\b/.test(sql)) {
          const url = new URL(input instanceof Request ? input.url : String(input));
          const bound = Object.fromEntries([...url.searchParams].filter(([k]) => k.startsWith("param_")).map(([k, v]) => [k.slice(6), v]));
          captured.push({ sql, params: bound });
        }
        return fetch(input, init);
      });
      const seen = await actors().aliasSightings(login, "7d", window.toMs);
      spy.mock.restore();
      // login не зарегистрирован — сравнение точное: только нижний регистр.
      assert.ok(seen.rows.length > 0 && seen.rows.every((r) => r.source === source && r.who === login), JSON.stringify(seen.rows));
      assert.equal(seen.rows.reduce((n, r) => n + r.events, 0), 5);
      assert.equal(captured.length, 1, "проверяется SQL, фактически отправленный aliasSightings");
      const plan = await granules(captured[0]);
      const bloom = plan.text.match(/Name:\s+idx_actor_keys\b[\s\S]*?Granules:\s*(\d+)\s*\/\s*(\d+)/);
      assert.ok(bloom, `aliasSightings: применяется bloom-индекс ключей алиасов:\n${plan.text}`);
      assert.ok(Number(bloom[1]) * 2 <= Number(bloom[2]), `aliasSightings: bloom-индекс должен отсечь фоновые гранулы:\n${plan.text}`);
    });
  } finally {
    database = "default";
    if (created) await ch().chCommand(`DROP DATABASE IF EXISTS ${db} SYNC`);
  }
});
