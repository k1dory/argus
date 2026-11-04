// PR #84: проверяем setup настоящей cap-фикстуры, а не копию её формулы.
// sourcesHealthReport выполняется целиком; подменены только HTTP-ответы CH.
// SQL ритма этот тест не эмулирует. Часы Node и CH заданы независимо.
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

const SERVER_NOW = Date.parse("2026-11-01T12:00:00.000Z") / 1000;
const previousSource = "previous-run.events-only";
const timestamp = (sec: number) => new Date(sec * 1000).toISOString().slice(0, 19).replace("T", " ");
type Params = Record<string, string | number>;
type FixtureBody = (t: TestContext) => Promise<void>;

async function runCapSetup(t: TestContext, ageSec: number, nodeAheadSec = 0) {
  const previousLastSec = SERVER_NOW - ageSec;
  const stopAfterInsert = new Error("cap INSERT записан; остановка перед проверками LIMIT");
  let baseline: queries.SourcesReport | undefined;
  let insertedSec: number | undefined;
  let failure: unknown;
  let stampQueries = 0;

  t.mock.method(Date, "now", () => (SERVER_NOW + nodeAheadSec) * 1000);
  t.mock.method(globalThis, "fetch", async (_input: unknown, init?: RequestInit) => {
    const sql = String(init?.body ?? "");
    let rows: unknown[];
    if (sql.includes("AS events_1h")) rows = [];
    else if (sql.includes("FROM collector_health_log")) rows = [];
    else if (sql.includes("AS stale_total")) {
      rows = [{
        source: previousSource, source_class: "system",
        last_ts: timestamp(previousLastSec), last_sec: previousLastSec, stale_total: "1",
      }];
    } else assert.fail(`неожиданный запрос sourcesHealthReport: ${sql}`);
    return new Response(rows.map((row) => JSON.stringify(row)).join("\n"));
  });

  // Модель единственного скалярного SQL setup: now() принадлежит CH,
  // а не Date.now(). Не обращается к живому серверу или общей БД.
  const client = {
    chQuery: async (sql: string, params: Params = {}) => {
      assert.match(sql, /^SELECT toString\(now\(\) - toIntervalSecond\(\{s:UInt32\}\)\) AS ts$/);
      assert.ok(Number.isSafeInteger(params.s) && Number(params.s) >= 0);
      stampQueries++;
      return [{ ts: timestamp(SERVER_NOW - Number(params.s)) }];
    },
    chCommand: async (sql: string, params: Params = {}) => {
      assert.match(sql, /^INSERT INTO events\b/);
      assert.match(sql, /toDateTime\(\{ts:String\}\)/);
      assert.equal(params.n, queries.STALE_SOURCES_LIMIT + 5);
      assert.match(String(params.prefix), /^cap\./);
      insertedSec = Date.parse(String(params.ts).replace(" ", "T") + "Z") / 1000;
      // Не запускаем вложенные тесты живой БД: предмет проверки — timestamp
      // фактического INSERT и достижимость setup при допустимом baseline.
      throw stopAfterInsert;
    },
  };

  const bodies: FixtureBody[] = [];
  const dependencies: Record<string, unknown> = {
    "node:assert/strict": assert,
    "node:test": {
      before: () => undefined,
      after: () => undefined,
      test: (name: string, options: { skip: boolean }, body: FixtureBody) => {
        if (!name.startsWith("больше 2000 молчащих:")) return;
        assert.equal(options.skip, false);
        bodies.push(body);
      },
    },
    "./_ch-live": {
      liveSkip: false,
      serializeLiveFile: () => undefined,
      runMigration: () => assert.fail("setup cap не должен запускать миграции"),
      ch: () => client,
    },
    "../src/lib/shared/source-health": health,
    "../src/lib/argus-queries": {
      STALE_SOURCES_LIMIT: queries.STALE_SOURCES_LIMIT,
      sourcesHealthReport: async () => {
        assert.equal(baseline, undefined, "читаем только исходный baseline");
        baseline = await queries.sourcesHealthReport();
        return baseline;
      },
    },
  };
  // VM изолирует регистрацию callback; это не ОС-песочница безопасности.
  const context = createContext({ Date, performance });
  const evaluate = new Script(
    `(function(require, module, exports, __dirname, __filename) {\n${compiled}\n})`,
    { filename: fixtureFile },
  ).runInContext(context, { timeout: 1000 });
  const mod = { exports: {} };
  evaluate((name: string) => {
    assert.ok(Object.hasOwn(dependencies, name), `неожиданный импорт фикстуры: ${name}`);
    return dependencies[name];
  }, mod, mod.exports, path.dirname(fixtureFile), fixtureFile);
  assert.equal(bodies.length, 1, "найден callback настоящей cap-фикстуры");
  try { await bodies[0](t); } catch (error) { failure = error; }
  assert.ok(baseline, "baseline получен через production sourcesHealthReport");
  assert.equal(baseline.sources.length, 1);
  assert.equal(baseline.sources[0].source, previousSource);
  assert.equal(baseline.sources[0].events_1h, 0);
  assert.equal(baseline.omitted, 0);
  return { baseline, previousLastSec, insertedSec, stampQueries, failure, stopAfterInsert };
}

function assertCapPlacement(result: Awaited<ReturnType<typeof runCapSetup>>) {
  assert.equal(result.failure, result.stopAfterInsert,
    `допустимый baseline должен доходить до INSERT без ручного ожидания: ${String(result.failure)}`);
  assert.equal(result.stampQueries, 1);
  assert.ok(result.insertedSec !== undefined && Number.isFinite(result.insertedSec));
  assert.ok(result.insertedSec < SERVER_NOW - 3600, "cap остаётся вне events_1h по часам CH");
  assert.ok(result.insertedSec > result.previousLastSec,
    `cap должен быть новее baseline: cap=${result.insertedSec}, baseline=${result.previousLastSec}`);
}

// На нижней границе есть корректное место для cap: событие на секунду новее
// baseline возрастом 61 мин всё ещё старше часового окна почти на минуту.
for (const ageSec of [61 * 60, 61 * 60 + 1, 61 * 60 + 2]) {
  test(`PR84: baseline ${ageSec} с не требует повторного запуска через минуту`, { timeout: 5000 }, async (t) => {
    assertCapPlacement(await runCapSetup(t, ageSec));
  });
}

// Контроль стенда: та же реальная фикстура на текущем коде допускает эти
// baseline. Проверяем границу сразу после предусловия и середину/конец окна.
for (const ageSec of [61 * 60 + 3, 65 * 60, 70 * 60]) {
  test(`PR84: контроль размещения cap при baseline ${ageSec} с`, { timeout: 5000 }, async (t) => {
    assertCapPlacement(await runCapSetup(t, ageSec));
  });
}

test("PR84: часы Node на 5 с впереди CH не делают cap старше baseline", { timeout: 5000 }, async (t) => {
  const result = await runCapSetup(t, 65 * 60, 5);
  assertCapPlacement(result);
});

// PR97: дополнительные чтения часов для бюджета не меняют контракт размещения.
// На HEAD callback доходит до правильного INSERT, но прежний проверяющий helper
// отвергает его из-за stampQueries === 1; это ломает также семь тестов выше.
test("PR97: измерение бюджета CH совместимо с проверкой корректного cap", { timeout: 5000 }, async (t) => {
  const result = await runCapSetup(t, 61 * 60, 5);
  assert.equal(result.failure, result.stopAfterInsert, "setup должен дойти до INSERT");
  assert.equal(result.insertedSec, result.previousLastSec + 1, "cap новее предыдущего источника");
  assert.doesNotThrow(() => assertCapPlacement(result),
    "проверка размещения не должна отвергать правильный cap из-за дополнительных чтений часов CH");
});
