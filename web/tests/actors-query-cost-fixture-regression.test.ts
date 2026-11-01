// PR #46: жизненный цикл настоящей actors-query-cost-ch.test.ts.
// Вызывается её callback через настоящий HTTP-клиент с подменённым fetch.
// SQL не исполняется: модель хранит имена БД и месяцы вставляемого диапазона.
// До actorReport не доходим; это проверки setup/cleanup, а не эмуляция bloom.
import { test, type TestContext } from "node:test";
import assert from "node:assert/strict";
import { randomBytes } from "node:crypto";
import { readFileSync, readdirSync } from "node:fs";
import path from "node:path";
import { createContext, Script } from "node:vm";
import ts from "typescript";
import { MIGRATIONS_DIR, migrationStatements } from "./_ch-live";
import { chTs } from "../src/lib/shared/log-query";
import { CH_ERROR_NAMES } from "../src/lib/clickhouse-error-names";

const fixtureFile = path.join(__dirname, "actors-query-cost-ch.test.ts");
const clientFile = path.resolve(__dirname, "../src/lib/clickhouse.ts");
const setupComplete = new Error("остановка перед EXPLAIN: setup завершён");
const compiled = new Map<string, string>();
type FixtureBody = (t: TestContext) => Promise<void>;
type RequestRecord = { sql: string; url: URL };
type Options = { now?: string; emptyServer?: boolean; loseCreateReply?: boolean };

async function runSetup(t: TestContext, options: Options = {}) {
  const now = Date.parse(options.now ?? "2026-10-15T12:00:00.000Z");
  const initialDatabases = options.emptyServer ? ["default"] : ["default", "argus"];
  const databases = new Set(initialDatabases);
  const requests: RequestRecord[] = [];
  const created: string[] = [];
  let partitions: string[] = [];
  let inserted = false, lostReply = false, reachedExplain = false;
  let body: FixtureBody | undefined;

  const transport = async (input: URL | string | Request, init?: RequestInit): Promise<Response> => {
    const url = new URL(input instanceof Request ? input.url : String(input));
    const sql = String(init?.body ?? "").trim();
    requests.push({ sql, url });
    assert.ok(databases.has(url.searchParams.get("database") ?? ""), "запрос адресован существующей БД");

    const create = /^CREATE DATABASE (?:IF NOT EXISTS )?([a-z0-9_]+)\b/i.exec(sql);
    if (create) {
      databases.add(create[1]);
      created.push(create[1]);
      const response = new Response("");
      if (options.loseCreateReply && create[1].startsWith("argus_actors_cost_") && !lostReply) {
        // Сервер уже применил DDL. Клиент получил HTTP 200, но чтение тела
        // завершилось разрывом соединения — реальный chCommand отклонится.
        Object.defineProperty(response, "text", { value: async () => {
          lostReply = true;
          throw new TypeError("fixture: connection reset after CREATE DATABASE");
        } });
      }
      return response;
    }
    const drop = /^DROP DATABASE (?:IF EXISTS )?([a-z0-9_]+)\b/i.exec(sql);
    if (drop) {
      databases.delete(drop[1]);
      return new Response("");
    }
    if (/^INSERT INTO events\b/i.test(sql)) {
      const table = requests.find((r) => /^CREATE TABLE[^\n]*\.events\b/i.test(r.sql));
      assert.ok(table, "используется настоящая миграция events");
      assert.match(table.sql, /PARTITION BY toYYYYMM\(ts\)/);
      assert.match(sql, /parseDateTime64BestEffort\(\{from:String\}, 3, 'UTC'\) \+ toIntervalMillisecond\(number\)/);
      const count = Number(/FROM numbers\((\d+)\)/.exec(sql)?.[1]);
      assert.ok(Number.isSafeInteger(count) && count > 0);
      const from = url.searchParams.get("param_from");
      assert.ok(from, "начало диапазона взято из фактического INSERT");
      const first = Date.parse(from.replace(" ", "T") + "Z");
      const last = first + count - 1;
      assert.ok(Number.isFinite(first));
      // Для непрерывного диапазона длиной 65,536 секунды месяцы концов
      // определяют все затронутые партиции. Разные месяцы не сливаются.
      assert.ok(count < 86_400_000, "модель рассчитана на короткий INSERT");
      partitions = [...new Set([first, last].map((ms) => new Date(ms).toISOString().slice(0, 7)))];
      inserted = true;
      return new Response("");
    }
    if (/\bFROM system\.parts\b/.test(sql)) {
      assert.ok(inserted, "число партов запрашивается после INSERT");
      return new Response(JSON.stringify({ parts: partitions.length, marks: 9 }) + "\n");
    }
    // Остальные DDL и INSERT ... SELECT миграций работают с пустыми таблицами.
    assert.match(sql, /^(CREATE|ALTER|INSERT|DROP)\b/i, "неожиданный запрос setup");
    return new Response("");
  };

  class FixtureDate extends Date {
    constructor(value: string | number = now) { super(value); }
    static now() { return now; }
  }
  // Отдельный JS-контекст нужен, чтобы mock fetch/Date/env не затрагивал
  // соседние тесты. Это не замена ОС-песочницы для запуска недоверенного кода.
  const context = createContext({
    Date: FixtureDate, URL, Request, Response, AbortSignal, Buffer,
    setTimeout, clearTimeout, fetch: transport,
    console: { error: () => undefined },
    process: { env: {
      CLICKHOUSE_URL: "http://clickhouse-fixture.invalid",
      CLICKHOUSE_DB: "argus", CLICKHOUSE_USER: "fixture", CLICKHOUSE_PASSWORD: "",
    } },
  });
  const dependencies: Record<string, unknown> = {
    "node:assert/strict": assert,
    "node:crypto": { randomBytes },
    "node:fs": { readdirSync },
    "../src/lib/shared/log-query": { chTs },
    "./clickhouse-error-names": { CH_ERROR_NAMES },
    "server-only": {},
    "node:test": {
      before: () => undefined,
      after: () => undefined,
      test: (_name: string, opts: { skip: boolean }, callback: FixtureBody) => {
        assert.equal(opts.skip, false);
        assert.equal(body, undefined, "в файле одна проверяемая фикстура");
        body = callback;
      },
    },
  };
  function load(file: string) {
    let js = compiled.get(file);
    if (!js) {
      js = ts.transpileModule(readFileSync(file, "utf8"), { compilerOptions: {
        target: ts.ScriptTarget.ES2022, module: ts.ModuleKind.CommonJS, esModuleInterop: true,
      } }).outputText;
      compiled.set(file, js);
    }
    const module = { exports: {} };
    const evaluate = new Script(`(function(require, module, exports, __dirname, __filename) {\n${js}\n})`, { filename: file })
      .runInContext(context, { timeout: 1000 });
    evaluate((name: string) => {
      assert.ok(Object.hasOwn(dependencies, name), `неожиданный импорт ${name}`);
      return dependencies[name];
    }, module, module.exports, path.dirname(file), file);
    return module.exports;
  }
  const client = load(clientFile) as typeof import("../src/lib/clickhouse");
  dependencies["./_ch-live"] = {
    MIGRATIONS_DIR, migrationStatements, liveSkip: false,
    // Фиктивный транспорт не должен брать блокировку настоящего ClickHouse.
    serializeLiveFile: () => undefined,
    ch: () => ({ ...client, chQuery: (...args: Parameters<typeof client.chQuery>) => {
      if (/^EXPLAIN\b/i.test(args[0])) {
        reachedExplain = true;
        throw setupComplete;
      }
      return client.chQuery(...args);
    } }),
  };
  load(fixtureFile);
  assert.ok(body, "callback настоящего cost-теста зарегистрирован");
  let failure: unknown;
  try { await body(t); } catch (error) { failure = error; }
  return { initialDatabases, databases, requests, created, partitions, inserted, lostReply, reachedExplain, failure };
}

test("actors cost: обычное исключение после setup удаляет только свою БД (контроль стенда)", { timeout: 10_000 }, async (t) => {
  const result = await runSetup(t);
  assert.equal(result.failure, setupComplete);
  assert.equal(result.reachedExplain, true);
  assert.equal(result.inserted, true);
  assert.equal(result.partitions.length, 1);
  assert.deepEqual([...result.databases].sort(), result.initialDatabases.sort());
  const drops = result.requests.filter((r) => /^DROP DATABASE\b/.test(r.sql));
  assert.equal(drops.length, 1);
  assert.match(drops[0].sql, /^DROP DATABASE (?:IF EXISTS )?argus_actors_cost_[a-f0-9]+ SYNC$/);
  assert.ok(result.initialDatabases.includes(drops[0].url.searchParams.get("database") ?? ""));
});

test("actors cost: потерянный ответ CREATE не оставляет созданную БД", { timeout: 10_000 }, async (t) => {
  const result = await runSetup(t, { loseCreateReply: true });
  assert.equal(result.lostReply, true, "сбой чтения ответа произошёл после применения CREATE");
  assert.equal(new Set(result.created.filter((db) => db.startsWith("argus_actors_cost_"))).size, 1);
  assert.ok(result.failure, "ошибка CREATE либо контрольная остановка перед EXPLAIN");
  assert.deepEqual([...result.databases].sort(), result.initialDatabases.sort(),
    "finally обязан удалить свою БД и при потере подтверждения CREATE");
});

test("actors cost: миграции изолированной фикстуры не оставляют общую argus", { timeout: 10_000 }, async (t) => {
  const result = await runSetup(t, { emptyServer: true });
  assert.equal(result.failure, setupComplete, "миграции и INSERT дошли до проверки плана");
  assert.equal(result.reachedExplain, true);
  assert.deepEqual([...result.databases].sort(), result.initialDatabases.sort(),
    "после finally на чистом сервере не остаётся БД, созданных фикстурой");
});

test("actors cost: запуск на границе месяца сохраняет одну партицию и один парт", { timeout: 10_000 }, async (t) => {
  // now - 48h = 2026-10-31 23:59:30 UTC; последняя строка попадает в ноябрь.
  const result = await runSetup(t, { now: "2026-11-02T23:59:30.000Z" });
  assert.equal(result.inserted, true);
  assert.deepEqual([...result.databases].sort(), result.initialDatabases.sort(), "ошибка не мешает cleanup");
  assert.equal(result.partitions.length, 1,
    `фикстура должна занимать один месяц независимо от времени запуска: ${result.partitions.join(", ")}`);
  assert.equal(result.failure, setupComplete, `setup не должен падать до EXPLAIN: ${String(result.failure)}`);
});
