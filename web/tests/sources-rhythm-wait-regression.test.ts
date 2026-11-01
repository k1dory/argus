// PR #89: исполняем callback настоящей cap-фикстуры с виртуальным временем.
// Реальный sourcesHealthReport получает HTTP-ответы для небольшого набора
// events/heartbeat, пересчитываемого при каждом запросе. Отдельные проверки
// намеренно портят только omitted, чтобы проверить обнаружение регрессии.
// Формулу размещения cap не копируем, SQL ритма не эмулируем. Живая БД не нужна.
import { test, type TestContext } from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import path from "node:path";
import { createContext, Script } from "node:vm";
import ts from "typescript";
import * as queries from "../src/lib/argus-queries";
import * as health from "../src/lib/shared/source-health";

const fixtureFile = path.join(__dirname, "sources-rhythm-ch.test.ts");
const compiled = ts.transpileModule(readFileSync(fixtureFile, "utf8"), {
  compilerOptions: {
    target: ts.ScriptTarget.ES2022,
    module: ts.ModuleKind.CommonJS,
    esModuleInterop: true,
  },
}).outputText;

const START = Date.parse("2026-11-01T12:00:00.000Z") / 1000;
const HOUR = 3600;
const WINDOW = 30 * 86400;
// acquireLiveLock в _ch-live.ts сдаётся через 10 минут: владелец блокировки
// не должен ждать возраст одной строки дольше дедлайна остальных live-файлов.
const LOCK_WAIT_MS = 600_000;
const timestamp = (sec: number) => new Date(sec * 1000).toISOString().slice(0, 19).replace("T", " ");
const seconds = (value: unknown) => Date.parse(String(value).replace(" ", "T") + "Z") / 1000;
type Params = Record<string, string | number>;
type Sample = { source: string; ageSec: number };
type FixtureContext = { test: (name: string, body: () => Promise<void>) => Promise<void> };
type FixtureBody = (t: FixtureContext) => Promise<void>;
type Options = { events: Sample[]; heartbeats?: Sample[]; stopAtInsert?: boolean; overcountOmitted?: boolean };

async function runFixture(t: TestContext, options: Options) {
  let now = START;
  const events = new Map(options.events.map((row) => [row.source, START - row.ageSec]));
  const heartbeats = new Map((options.heartbeats ?? []).map((row) => [row.source, START - row.ageSec]));
  const waits: number[] = [];
  const reports: queries.SourcesReport[] = [];
  const subtests: string[] = [];
  const subtestFailures: { name: string; error: unknown }[] = [];
  const stopAfterInsert = new Error("INSERT cap записан; проверки живой БД не запускаем");
  const waitBudgetExceeded = new Error("виртуальное ожидание превысило дедлайн live-lock");
  let failure: unknown;
  let corruptions = 0;
  let cap: { prefix: string; lastSec: number; count: number } | undefined;

  const eventRows = () => Array.from(events, ([source, last_sec]) => ({
    source, source_class: "system", last_sec, last_ts: timestamp(last_sec),
  }));
  const staleRows = () => eventRows()
    .filter((row) => row.last_sec < now - HOUR && row.last_sec >= now - WINDOW)
    .sort((a, b) => b.last_sec - a.last_sec || a.source.localeCompare(b.source));

  t.mock.method(Date, "now", () => now * 1000);
  t.mock.method(globalThis, "fetch", async (input: unknown, init?: RequestInit) => {
    const sql = String(init?.body ?? "");
    const params = new URL(String(input)).searchParams;
    let rows: unknown[];
    if (sql.includes("AS events_1h")) {
      rows = eventRows().filter((row) => row.last_sec >= now - HOUR).map((row) => ({
        ...row, events_1h: "1", eps_60s: row.last_sec >= now - 60 ? "1" : "0", pii_share: 0, now_sec: now,
      }));
    } else if (sql.includes("FROM collector_health_log")) {
      rows = Array.from(heartbeats, ([source, last_sec]) => ({
        source, last_sec, events_window: "1", gap_q: null, now_sec: now,
      })).filter((row) => row.last_sec >= now - WINDOW);
    } else if (sql.includes("AS stale_total")) {
      const stale = staleRows();
      rows = stale.slice(0, Number(params.get("param_lim"))).map((row) => ({
        ...row, stale_total: String(stale.length),
      }));
    } else if (/source\s+IN\b/.test(sql)) {
      // Имена стенда — ASCII без кавычек/экранирования; это не SQL-парсер.
      const names = new Set(Array.from((params.get("param_names") ?? "").matchAll(/'([^']*)'/g), (m) => m[1]));
      rows = staleRows().filter((row) => names.has(row.source));
    } else assert.fail(`неожиданный запрос sourcesHealthReport: ${sql}`);
    return new Response(rows.map((row) => JSON.stringify(row)).join("\n"));
  });

  const client = {
    chQuery: async (sql: string, params: Params = {}) => {
      assert.match(sql, /^SELECT toString\(now\(\) - toIntervalSecond\(\{s:UInt32\}\)\) AS ts$/);
      assert.ok(Number.isSafeInteger(params.s) && Number(params.s) >= 0);
      return [{ ts: timestamp(now - Number(params.s)) }];
    },
    chCommand: async (sql: string, params: Params = {}) => {
      if (/^INSERT INTO events\b/.test(sql)) {
        assert.equal(params.n, queries.STALE_SOURCES_LIMIT + 5);
        cap = { prefix: String(params.prefix), lastSec: seconds(params.ts), count: Number(params.n) };
        assert.ok(Number.isFinite(cap.lastSec));
        for (let i = 0; i < cap.count; i++) events.set(`${cap.prefix}${String(i).padStart(5, "0")}`, cap.lastSec);
        if (options.stopAtInsert) throw stopAfterInsert;
      } else if (/^INSERT INTO collector_health\b/.test(sql)) {
        heartbeats.set(String(params.s), params.ts === undefined ? now - 4 * HOUR : seconds(params.ts));
      } else if (/^ALTER TABLE (events|collector_health|collector_health_log) DELETE\b/.test(sql)) {
        const table = sql.startsWith("ALTER TABLE events ") ? events : heartbeats;
        if (params.prefix !== undefined) {
          for (const source of table.keys()) if (source.startsWith(String(params.prefix))) table.delete(source);
        } else {
          assert.ok(params.s !== undefined);
          table.delete(String(params.s));
        }
      } else assert.fail(`неожиданная команда фикстуры: ${sql}`);
    },
  };
  const bodies: FixtureBody[] = [];
  const dependencies: Record<string, unknown> = {
    "node:assert/strict": assert,
    "node:test": {
      before: () => undefined,
      after: () => undefined,
      test: (name: string, opts: { skip: boolean }, body: FixtureBody) => {
        if (!name.startsWith("больше 2000 молчащих:")) return;
        assert.equal(opts.skip, false);
        bodies.push(body);
      },
    },
    "./_ch-live": {
      liveSkip: false,
      serializeLiveFile: () => undefined,
      runMigration: () => assert.fail("callback cap не должен применять миграции"),
      ch: () => client,
    },
    "../src/lib/shared/source-health": health,
    "../src/lib/argus-queries": {
      STALE_SOURCES_LIMIT: queries.STALE_SOURCES_LIMIT,
      sourcesHealthReport: async () => {
        const report = await queries.sourcesHealthReport();
        // Контролируемая регрессия: off-by-one только при заполненном LIMIT.
        // Baseline без усечения остаётся корректным (omitted === 0).
        if (options.overcountOmitted && report.omitted > 0) {
          report.omitted++;
          corruptions++;
        }
        reports.push(report);
        return report;
      },
    },
  };
  // VM изолирует регистрацию node:test, а не обеспечивает безопасность исполнения.
  const context = createContext({
    Date,
    // expected = Array.from(...) в callback и массивы реального report должны
    // иметь один prototype, иначе assert/strict отвергнет их из-за разных VM.
    Array,
    setTimeout: (resolve: () => void, ms: number) => {
      assert.ok(Number.isFinite(ms) && ms >= 0);
      waits.push(ms);
      // Ни настоящего ожидания, ни неограниченного цикла при будущих изменениях.
      if (waits.length > 100 || waits.reduce((a, b) => a + b, 0) >= LOCK_WAIT_MS) throw waitBudgetExceeded;
      now += ms / 1000;
      resolve();
      return waits.length;
    },
  });
  const evaluate = new Script(
    `(function(require, module, exports, __dirname, __filename) {\n${compiled}\n})`,
    { filename: fixtureFile },
  ).runInContext(context, { timeout: 1000 });
  const mod = { exports: {} };
  evaluate((name: string) => {
    assert.ok(Object.hasOwn(dependencies, name), `неожиданный импорт: ${name}`);
    return dependencies[name];
  }, mod, mod.exports, path.dirname(fixtureFile), fixtureFile);
  assert.equal(bodies.length, 1);
  try {
    await bodies[0]({
      test: async (name, body) => {
        subtests.push(name);
        // Как node:test: сбой дочернего теста фиксируется, но t.test разрешается,
        // поэтому оставшиеся проверки omitted и finally тоже выполняются.
        try { await body(); } catch (error) { subtestFailures.push({ name, error }); }
      },
    });
  } catch (error) { failure = error; }
  assert.ok(reports.length > 0, `production baseline должен быть прочитан: ${String(failure)}`);
  return { waits, reports, subtests, subtestFailures, failure, cap, now, corruptions };
}

function assertFixturePass(result: Awaited<ReturnType<typeof runFixture>>) {
  assert.equal(result.failure, undefined, `ошибка callback: ${String(result.failure)}`);
  assert.equal(result.subtests.length, 3, "все проверки LIMIT/omitted должны выполняться");
  assert.deepEqual(result.subtestFailures.map(({ name, error }) => `${name}: ${String(error).slice(0, 600)}`), [],
    "корректные ответы sourcesHealthReport не должны приводить к падению live-фикстуры");
  assert.ok(result.cap);
  assert.ok(result.now - result.cap.lastSec >= HOUR + 30, "cap не моложе 60:30 по часам CH");
}

test("PR89: контроль стенда — полный callback без ожидания", { timeout: 5000 }, async (t) => {
  const result = await runFixture(t, { events: [{ source: "previous.quiet", ageSec: 2 * HOUR }] });
  assertFixturePass(result);
  assert.deepEqual(result.waits, []);
});

test("PR89: контроль стенда — ожидание безопасно при неизменном составе источников", { timeout: 5000 }, async (t) => {
  const result = await runFixture(t, { events: [{ source: "previous.quiet", ageSec: HOUR + 1 }] });
  assertFixturePass(result);
  assert.ok(result.waits.length > 0, "достигнута новая ветка ожидания");
  assert.equal(result.cap!.lastSec, START - HOUR, "cap на секунду новее предыдущего источника");
});

function assertWrongOmittedRejected(result: Awaited<ReturnType<typeof runFixture>>) {
  assert.equal(result.failure, undefined);
  assert.equal(result.subtests.length, 3);
  assert.ok(result.corruptions >= 4, "ошибка внедрена в каждый отчёт после INSERT cap");
  assert.ok(result.subtestFailures.length > 0,
    "live-фикстура не должна проходить, когда omitted всех отчётов после LIMIT завышен на единицу");
}

test("PR89: контроль стенда — ошибка omitted при неизменном baseline обнаруживается", { timeout: 5000 }, async (t) => {
  const result = await runFixture(t, {
    events: [{ source: "previous.quiet", ageSec: HOUR + 1 }], overcountOmitted: true,
  });
  assertWrongOmittedRejected(result);
});

// F1: events_1h === 0 включает и недавний heartbeat-only. Его timestamp не
// ограничен часовым окном events; дата в будущем также проходит SQL heartbeat.
for (const ageSec of [60, -86400]) {
  test(`PR89: heartbeat-only возрастом ${ageSec} с не занимает live-lock дольше его дедлайна`, { timeout: 5000 }, async (t) => {
    const result = await runFixture(t, {
      events: [], heartbeats: [{ source: "heartbeat.only", ageSec }], stopAtInsert: true,
    });
    assert.equal(result.reports[0].sources[0]?.source, "heartbeat.only");
    assert.equal(result.reports[0].sources[0].events_1h, 0);
    const requestedMs = result.waits.reduce((a, b) => a + b, 0);
    assert.ok(requestedMs < LOCK_WAIT_MS,
      `setup запросил ${requestedMs / 1000} с ожидания; остальные live-файлы сдаются через ${LOCK_WAIT_MS / 1000} с`);
    // Допустимы и короткое ожидание, и явный отказ setup для неподходящей даты.
  });
}

// F2: даже без конкурентных писателей время меняет состав baseline. После
// ожидания надо заново выбрать cap и пересчитать исходный omitted.
test("PR89: выход активного источника из events_1h во время ожидания не ломает cap", { timeout: 5000 }, async (t) => {
  const result = await runFixture(t, { events: [
    { source: "previous.quiet", ageSec: HOUR + 1 },
    { source: "previous.active", ageSec: HOUR - 10 },
  ] });
  assert.equal(result.reports[0].sources.find((s) => s.source === "previous.active")?.events_1h, 1);
  assertFixturePass(result);
});

test("PR89: истечение окна 30 суток во время ожидания не оставляет лишний omitted", { timeout: 5000 }, async (t) => {
  const result = await runFixture(t, { events: [
    { source: "previous.quiet", ageSec: HOUR + 1 },
    { source: "previous.expiring", ageSec: WINDOW - 10 },
  ] });
  assert.equal(result.reports[0].sources.length, 2);
  assertFixturePass(result);
});

test("PR89: истечение окна 30 суток не маскирует регрессию omitted после LIMIT", { timeout: 5000 }, async (t) => {
  const result = await runFixture(t, {
    events: [
      { source: "previous.quiet", ageSec: HOUR + 1 },
      { source: "previous.expiring", ageSec: WINDOW - 10 },
    ],
    overcountOmitted: true,
  });
  assert.equal(result.reports[0].sources.length, 2);
  assert.equal(result.reports[0].omitted, 0);
  assertWrongOmittedRejected(result);
});

// Ревью дельты 94eeffe..HEAD: граница бюджета и результат setup должны
// проверяться явно. Одного requestedMs < LOCK_WAIT_MS недостаточно:
// runFixture перехватывает исключения, а его FixtureContext не передаёт skip.
test("PR89: ожидание ровно 90 с допустимо и выполняет все проверки cap", { timeout: 5000 }, async (t) => {
  const result = await runFixture(t, {
    events: [], heartbeats: [{ source: "heartbeat.only", ageSec: HOUR - 59 }],
  });
  assertFixturePass(result);
  assert.deepEqual(result.waits, [90_000]);
});

for (const ageSec of [HOUR - 60, 60, -86400]) {
  test(`PR89: отказ от ожидания для heartbeat возрастом ${ageSec} с не маскирует исключение callback`, { timeout: 5000 }, async (t) => {
    const result = await runFixture(t, {
      events: [], heartbeats: [{ source: "heartbeat.only", ageSec }],
    });
    assert.equal(result.failure, undefined,
      `исчерпание бюджета должно моделировать node:test skip, а не проглатывать исключение: ${String(result.failure)}`);
    assert.deepEqual(result.waits, [], "ожидание дольше 90 с отклоняется до таймера");
    assert.equal(result.cap, undefined, "пропущенная фикстура не вставляется");
    assert.equal(result.subtests.length, 0, "проверки cap после skip не выполняются");
  });
}
