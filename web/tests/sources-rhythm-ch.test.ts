// Ритм и список источников на живом ClickHouse: SQL sourcesHealthReport — единственное
// место расчёта ритма, юнит-тест его не видит. Фикстура: непрерывный источник, пачка
// 15 минут раз в сутки, непрерывный с одним двухсуточным провалом, телеметрия мимо
// коллектора (только events, без heartbeat). Нужен ARGUS_TEST_CLICKHOUSE_URL.
import { after, before, test } from "node:test";
import assert from "node:assert/strict";
import { serializeLiveFile, ch, liveSkip as skip, runMigration } from "./_ch-live";
import { SILENCE_MIN_SEC } from "../src/lib/shared/source-health";

serializeLiveFile({ before, after });

/* eslint-disable @typescript-eslint/no-require-imports -- модуль читает env при загрузке */
const q = () => require("../src/lib/argus-queries") as typeof import("../src/lib/argus-queries");
/* eslint-enable @typescript-eslint/no-require-imports */

const RUN = `r${Date.now().toString(36)}`;
const CONT = `cont.${RUN}`, DAILY = `daily.${RUN}`, OUTAGE = `outage.${RUN}`, SYS = `argus.system.${RUN}`;
const DAY = 86400;

async function seed(): Promise<void> {
  const c = ch();
  const hb = (src: string, minutesExpr: string, n: number) =>
    c.chCommand(`INSERT INTO collector_health (source, listener, seen_at, events_1m)
      SELECT {s:String}, 'http', toStartOfMinute(now()) - ${minutesExpr}, 10 FROM numbers(${n})`, { s: src });
  const ev = (src: string, cls: string, agoSec: number, n: number) =>
    c.chCommand(`INSERT INTO events (ts, received_at, source, source_class, action)
      SELECT now() - {a:UInt32} - number, now() - {a:UInt32} - number, {s:String}, {c:String}, 'x' FROM numbers(${n})`, { s: src, c: cls, a: agoSec });
  // Непрерывный: каждая минута трое суток.
  await hb(CONT, "60 * number", 3 * 1440);
  await ev(CONT, "netflow", 0, 100);
  // Пачка 15 минут раз в сутки 10 суток; последняя закончилась 12 часов назад.
  await hb(DAILY, "60 * (720 + intDiv(number, 15) * 1440 + number % 15)", 10 * 15);
  await ev(DAILY, "cicd", 12 * 3600, 50);
  // Непрерывный 10 суток с провалом на двое суток (дни 4–6 назад); сейчас пишет.
  await c.chCommand(`INSERT INTO collector_health (source, listener, seen_at, events_1m)
    SELECT {s:String}, 'syslog', toStartOfMinute(now()) - 60 * number, 3 FROM numbers(10 * 1440)
    WHERE NOT (number >= 4 * 1440 AND number < 6 * 1440)`, { s: OUTAGE });
  await ev(OUTAGE, "syslog", 0, 30);
  // Телеметрия мимо коллектора: только events, замолчала 3 часа назад.
  await ev(SYS, "system", 3 * 3600, 5);
}

// Только схема событий и heartbeat: файлы тестов идут параллельно, и полный прогон
// миграций здесь гонялся бы с triage-claim-ch.test.ts за таблицы вебхуков (0018/0025).
const MIGRATIONS = ["0001_init.sql", "0005_events_incidents.sql", "0008_collector_health_log.sql", "0023_events_value.sql",
  "0028_events_received_at_index.sql", "0031_events_source_last_projection.sql"];

test("миграции событий и heartbeat (включая проекцию p_source_last) применяются, фикстура вставляется", { skip }, async () => {
  for (const f of MIGRATIONS) await runMigration(f);
  await seed();
});

test("ритм: пачка раз в сутки — около суток и жива через 12 часов; непрерывный — минута; провал не растягивает ритм", { skip }, async () => {
  const { sources } = await q().sourcesHealthReport();
  const by = new Map(sources.map((r) => [r.source, r]));
  const cont = by.get(CONT), daily = by.get(DAILY), outage = by.get(OUTAGE);
  assert.ok(cont && daily && outage, `источники в списке: ${sources.map((r) => r.source).join(", ")}`);
  assert.equal(cont.rhythm_sec, 60); assert.equal(cont.silence_threshold_sec, SILENCE_MIN_SEC); assert.equal(cont.alive, 1);
  assert.ok(daily.rhythm_sec! > 20 * 3600 && daily.rhythm_sec! <= DAY, `суточная пачка 15 минут → ~сутки, а не минута: ${daily.rhythm_sec}`);
  assert.equal(daily.rhythm_sec, (1440 - 14) * 60, "production SQL взвешивает разрывы по времени: пауза между 15-минутными пачками");
  assert.equal(daily.alive, 1, "через 12 часов после пачки суточный источник жив");
  assert.ok(daily.silent_for_sec >= 12 * 3600 - 60);
  assert.equal(outage.rhythm_sec, 60, "одиночный двухсуточный провал отброшен — ритм непрерывного остаётся минутой");
});

test("замолчавшие: источник мимо коллектора остаётся в списке как «молчит»; порядок — от недавних к давним", { skip }, async () => {
  const { sources, omitted } = await q().sourcesHealthReport();
  const sys = sources.find((r) => r.source === SYS);
  assert.ok(sys, "телеметрия без heartbeat не пропадает через час");
  assert.equal(sys.alive, 0); assert.equal(sys.source_class, "system"); assert.equal(sys.rhythm_sec, null);
  assert.ok(sys.silent_for_sec >= 3 * 3600 - 60 && sys.events_1h === 0);
  assert.ok(Number.isInteger(omitted) && omitted >= 0);
  const quiet = sources.filter((r) => r.events_1h === 0);
  for (let i = 1; i < quiet.length; i++) assert.ok(quiet[i - 1].silent_for_sec <= quiet[i].silent_for_sec + 60, `порядок: ${quiet[i - 1].source} → ${quiet[i].source}`);
});

test("больше 2000 молчащих: порядок при равном времени, точный omitted и объединение с heartbeat", { skip }, async (t) => {
  const c = ch();
  const limit = q().STALE_SOURCES_LIMIT;
  assert.equal(limit, 2000, "предел соответствует текущему контракту /api/sources");
  const prefix = `cap.${RUN}.`;
  const name = (i: number) => `${prefix}${String(i).padStart(5, "0")}`;
  const n = limit + 5;
  const baseline = await q().sourcesHealthReport();
  const beforeQuiet = baseline.sources.filter((s) => s.events_1h === 0);
  assert.ok(beforeQuiet.every((s) => s.silent_for_sec > 70 * 60), "фикстура cap должна быть новее ранее вставленных молчащих источников");
  const beforeTotal = beforeQuiet.length + baseline.omitted;
  const [stamp] = await c.chQuery<{ ts: string }>("SELECT toString(now() - INTERVAL 65 MINUTE) AS ts");
  await c.chCommand(`INSERT INTO events (ts, received_at, source, source_class, action)
    SELECT toDateTime({ts:String}), toDateTime({ts:String}), concat({prefix:String}, leftPad(toString(number), 5, '0')), 'system', 'x'
    FROM numbers({n:UInt32}) ORDER BY number DESC`, { ts: stamp.ts, prefix, n });
  try {
    await t.test("равные timestamp сортируются по source, limit не зависит от порядка вставки", async () => {
      const first = await q().sourcesHealthReport();
      const second = await q().sourcesHealthReport();
      const expected = Array.from({ length: limit }, (_, i) => name(i));
      assert.deepEqual(first.sources.filter((s) => s.events_1h === 0).map((s) => s.source), expected);
      assert.deepEqual(second.sources.map((s) => s.source), first.sources.map((s) => s.source), "повтор загрузки показывает тот же набор");
      assert.equal(first.omitted, beforeTotal + n - limit, "все источники вне списка посчитаны");
      assert.equal(second.omitted, first.omitted);
    });

    // Источник есть в events, но оказался за LIMIT. Его heartbeat с тем же
    // временем не должен добавлять ещё один пропущенный источник.
    await c.chCommand(`INSERT INTO collector_health (source, listener, seen_at, events_1m)
      VALUES ({s:String}, 'http', toDateTime({ts:String}), 1)`, { s: name(n - 1), ts: stamp.ts });
    await t.test("heartbeat источника за LIMIT не дублирует счётчик", async () => {
      const report = await q().sourcesHealthReport();
      assert.equal(report.omitted, beforeTotal + n - limit);
    });

    // После отдельной проверки дубля удаляем его heartbeat, чтобы ошибка
    // переучёта не могла замаскировать недоучёт старого heartbeat-only.
    for (const table of ["collector_health", "collector_health_log"]) {
      await c.chCommand(`ALTER TABLE ${table} DELETE WHERE source = {s:String} SETTINGS mutations_sync = 1`, { s: name(n - 1) });
    }
    await c.chCommand(`INSERT INTO collector_health (source, listener, seen_at, events_1m)
      VALUES ({s:String}, 'http', now() - INTERVAL 4 HOUR, 1)`, { s: `${prefix}heartbeat-only` });
    await t.test("старый heartbeat-only остаётся в omitted, когда места в списке нет", async () => {
      const report = await q().sourcesHealthReport();
      assert.equal(report.omitted, beforeTotal + n + 1 - limit);
      assert.equal(report.sources.some((s) => s.source === `${prefix}heartbeat-only`), false);
    });
  } finally {
    // Файлы делят одну БД под lock: убираем только свою cap-фикстуру, чтобы она
    // не вытесняла источники из последующих живых тестов.
    for (const table of ["events", "collector_health", "collector_health_log"]) {
      await c.chCommand(`ALTER TABLE ${table} DELETE WHERE startsWith(source, {prefix:String}) SETTINGS mutations_sync = 1`, { prefix });
    }
  }
});
