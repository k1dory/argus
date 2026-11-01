// PR #89: бюджет ожидания cap должен учитывать время повторного baseline.
// Исполняется callback настоящей live-фикстуры; ответы sourcesHealthReport
// моделируют пять неизменных источников, а чтение отчёта занимает виртуальные
// 10 секунд. SQL и формула выбора cap здесь не воспроизводятся.
import { test } from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import path from "node:path";
import { createContext, Script } from "node:vm";
import ts from "typescript";
import { SILENCE_MIN_SEC } from "../src/lib/shared/source-health";

const fixtureFile = path.join(__dirname, "sources-rhythm-ch.test.ts");
const compiled = ts.transpileModule(readFileSync(fixtureFile, "utf8"), {
  compilerOptions: {
    target: ts.ScriptTarget.ES2022,
    module: ts.ModuleKind.CommonJS,
    esModuleInterop: true,
  },
}).outputText;

const START_MS = Date.parse("2026-11-01T12:00:00.000Z");
const WAIT_BUDGET_MS = 90_000;
const timestamp = (ms: number) => new Date(ms).toISOString().slice(0, 19).replace("T", " ");
type FixtureContext = {
  skip: (reason?: string) => void;
  test: (name: string, body: () => Promise<void>) => Promise<void>;
};
type FixtureBody = (t: FixtureContext) => Promise<void>;

type SetupOptions = {
  reportDelaysMs?: readonly number[];
  heartbeatAgeSec?: number;
  stopAtInsert?: boolean;
};

async function runSetup(reportDelayMs: number, options: SetupOptions = {}) {
  let nowMs = START_MS;
  let reportCount = 0;
  let failure: unknown;
  const skipped: string[] = [];
  const commands: string[] = [];
  const waits: { atMs: number; delayMs: number }[] = [];
  const bodies: FixtureBody[] = [];
  const stopAfterInsert = new Error("INSERT cap достигнут; конец проверки setup");
  // Источники выйдут из окна часа через 30, 61, 92, 123 и 154 секунды.
  // Во время setup ничего не вставляется и не удаляется.
  const events = [30, 61, 92, 123, 154].map((leavesSec, i) => ({
    source: `previous.${i}`,
    lastMs: START_MS - 3_600_000 + leavesSec * 1000,
  }));
  class FixtureDate extends Date {
    constructor(value: string | number = nowMs) { super(value); }
    static now() { return nowMs; }
  }
  const client = {
    chQuery: async (sql: string, params: Record<string, unknown>) => {
      assert.match(sql, /^SELECT toString\(now\(\) - toIntervalSecond\(\{s:UInt32\}\)\) AS ts$/);
      assert.equal(params.s, 0);
      return [{ ts: timestamp(nowMs) }];
    },
    chCommand: async (sql: string) => {
      commands.push(sql);
      if (options.stopAtInsert && /^INSERT INTO events\b/.test(sql)) throw stopAfterInsert;
      assert.fail("неподходящее окно должно завершиться skip до первой записи cap");
    },
  };
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
    "../src/lib/shared/source-health": { SILENCE_MIN_SEC },
    "../src/lib/argus-queries": {
      STALE_SOURCES_LIMIT: 2000,
      sourcesHealthReport: async () => {
        assert.ok(++reportCount <= 10, "ограничение числа итераций виртуального стенда");
        // Как now() ClickHouse: снимок берётся в начале запроса, ответ приходит
        // позже. Все строки по-прежнему находятся внутри окна 30 суток.
        const snapshotMs = nowMs;
        const sources = options.heartbeatAgeSec === undefined ? events.map(({ source, lastMs }) => ({
          source,
          events_1h: lastMs >= snapshotMs - 3_600_000 ? 1 : 0,
          last_ts: timestamp(lastMs),
          silent_for_sec: (snapshotMs - lastMs) / 1000,
        })) : [{
          source: "heartbeat.only",
          events_1h: 0,
          last_ts: timestamp(START_MS - options.heartbeatAgeSec * 1000),
          silent_for_sec: (snapshotMs - START_MS) / 1000 + options.heartbeatAgeSec,
        }];
        nowMs += options.reportDelaysMs?.[reportCount - 1] ?? reportDelayMs;
        return { sources, omitted: 0 };
      },
    },
  };
  // VM нужна только для изоляции регистрации node:test и виртуальных часов;
  // она не заменяет ОС-песочницу при запуске тестового процесса.
  const context = createContext({
    Date: FixtureDate,
    Array,
    setTimeout: (resolve: () => void, delayMs: number) => {
      assert.ok(Number.isFinite(delayMs) && delayMs > 0);
      assert.ok(waits.length < 10, "ограничение числа таймеров виртуального стенда");
      waits.push({ atMs: nowMs - START_MS, delayMs });
      nowMs += delayMs;
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
    assert.ok(Object.hasOwn(dependencies, name), `неожиданный импорт фикстуры: ${name}`);
    return dependencies[name];
  }, mod, mod.exports, path.dirname(fixtureFile), fixtureFile);
  assert.equal(bodies.length, 1, "найден callback настоящей cap-фикстуры");
  try {
    await bodies[0]({
      skip: (reason) => { skipped.push(reason ?? ""); },
      test: async () => { assert.fail("после skip проверки cap не запускаются"); },
    });
  } catch (error) { failure = error; }
  return { failure, skipped, commands, waits, reportCount, elapsedMs: nowMs - START_MS, stopAfterInsert };
}

for (const reportDelayMs of [0, 10_000]) {
  test(`PR89: повторный baseline длительностью ${reportDelayMs} мс входит в бюджет 90 с`, { timeout: 5000 }, async () => {
    const result = await runSetup(reportDelayMs);
    assert.equal(result.failure, undefined, `ошибка callback: ${String(result.failure)}`);
    assert.equal(result.skipped.length, 1, "при исчерпании бюджета нужен явный skip");
    assert.ok(result.skipped[0].length > 0, "skip должен объяснять причину");
    assert.deepEqual(result.commands, [], "до skip нет записи фикстуры");
    assert.ok(result.reportCount > 1, "достигнут повторный расчёт baseline");
    assert.ok(result.elapsedMs <= WAIT_BUDGET_MS,
      `setup удерживал live-lock ${result.elapsedMs / 1000} с: ` +
      `${result.reportCount} отчётов и ${result.waits.reduce((sum, wait) => sum + wait.delayMs, 0) / 1000} с таймеров`);
  });
}

// Первый baseline занимает 1 с. Heartbeat возрастом 3543 с требует затем
// ещё 87 с ожидания. Прогноз со старой длительностью разрешает новый отчёт:
// 1 + 87 + 1 = 89 с. Если второй baseline длится 3 с, INSERT достигается
// на 91-й секунде: wait <= 0 обходит проверку истёкшего бюджета.
test("PR97: замедлившийся повторный baseline не разрешает INSERT после 90 с", { timeout: 5000 }, async () => {
  const result = await runSetup(0, {
    heartbeatAgeSec: 3600 - 57,
    reportDelaysMs: [1000, 3000],
    stopAtInsert: true,
  });
  assert.deepEqual(result.commands, [],
    `исчерпанный бюджет должен завершить setup до INSERT; прошло ${result.elapsedMs} мс CH`);
  assert.equal(result.failure, undefined, "истечение бюджета должно завершаться без исключения");
  assert.equal(result.skipped.length, 1, "даже при wait <= 0 нужен явный skip по истёкшему бюджету");
  assert.ok(result.skipped[0].length > 0);
});

// Контроль того же стенда: запросы занимают ненулевое время, но на самой
// включённой границе бюджета cap уже допустим и должен доходить до INSERT.
test("PR97: baseline, завершившийся ровно на 90-й секунде, допускает INSERT", { timeout: 5000 }, async () => {
  const result = await runSetup(0, {
    heartbeatAgeSec: 3600 - 57,
    reportDelaysMs: [1000, 2000],
    stopAtInsert: true,
  });
  assert.equal(result.failure, result.stopAfterInsert, "остановка только в перехваченном INSERT");
  assert.equal(result.commands.length, 1);
  assert.equal(result.skipped.length, 0);
  assert.equal(result.elapsedMs, WAIT_BUDGET_MS);
});
