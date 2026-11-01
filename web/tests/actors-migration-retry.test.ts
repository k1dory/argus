// PR #10: повтор 0032 после сбоя записи schema_migrations не должен повторно
// ставить полную материализацию events. Запускается настоящий migrate.sh,
// но clickhouse-client заменён локальным журналом принятых команд: сети нет.
// Это проверка orchestration/retry, а не эмуляция исполнения SQL ClickHouse.
import { test, type TestContext } from "node:test";
import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { copyFileSync, existsSync, mkdirSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import os from "node:os";
import path from "node:path";

const root = path.resolve(__dirname, "../..");
const migration = "0032_events_actor_keys_index.sql";

// Только фиктивный клиент читает/пишет этот каталог. Отказ инъецируется ПОСЛЕ
// успешного --multiquery, перед сохранением имени миграции; принятые ALTER
// остаются в журнале, как серверная мутация после разрыва соединения.
const client = String.raw`
const fs = require("node:fs");
const path = require("node:path");
const state = process.env.ARGUS_MIGRATION_RETRY_STATE;
const file = (name) => path.join(state, name);
const args = process.argv.slice(2);
const query = args.indexOf("--query");
const sql = query >= 0 ? args[query + 1] : fs.readFileSync(0, "utf8");
const statements = sql.replace(/^--.*$/gm, "").split(";").map((s) => s.trim()).filter(Boolean);
for (const statement of statements) {
  const s = statement.replace(/\s+/g, " ");
  if (s === "SELECT 1") {
    process.stdout.write("1\n");
  } else if (/^CREATE (DATABASE|TABLE) IF NOT EXISTS argus\b/.test(s)) {
    // Начальная схема фикстуры, без связи с настоящей БД.
  } else if (s === "SELECT name FROM argus.schema_migrations") {
    if (fs.existsSync(file("applied"))) process.stdout.write(fs.readFileSync(file("applied")));
  } else if (/^ALTER TABLE argus\.events ADD INDEX IF NOT EXISTS idx_actor_keys\b/.test(s)) {
    fs.writeFileSync(file("index-exists"), "1");
  } else if (/^ALTER TABLE argus\.events MATERIALIZE INDEX (?:IF EXISTS )?idx_actor_keys\b/.test(s)) {
    if (!fs.existsSync(file("index-exists"))) throw new Error("index does not exist");
    fs.appendFileSync(file("materializations"), JSON.stringify(s) + "\n");
  } else if (/^INSERT INTO argus\.schema_migrations\b/.test(s)) {
    if (fs.existsSync(file("fail-bookkeeping-once"))) {
      fs.unlinkSync(file("fail-bookkeeping-once"));
      process.stderr.write("injected schema_migrations write failure\n");
      process.exit(75);
    }
    const name = /VALUES \('([^']+)'\)$/.exec(s);
    if (!name) throw new Error("unexpected migration bookkeeping: " + s);
    fs.appendFileSync(file("applied"), name[1] + "\n");
  } else {
    throw new Error("unexpected ClickHouse command in retry fixture: " + s);
  }
}
`;

function fixture(t: TestContext, failBookkeeping = false) {
  const scratch = mkdtempSync(path.join(os.tmpdir(), "argus-actor-index-retry-"));
  t.after(() => rmSync(scratch, { recursive: true, force: true }));
  const bin = path.join(scratch, "bin");
  const migrations = path.join(scratch, "migrations");
  const state = path.join(scratch, "state");
  const temp = path.join(scratch, "tmp");
  for (const dir of [bin, migrations, state, temp]) mkdirSync(dir);
  copyFileSync(path.join(root, "clickhouse/migrations", migration), path.join(migrations, migration));
  writeFileSync(path.join(bin, "clickhouse-client"), `#!${process.execPath}\n${client}`, { mode: 0o700 });
  if (failBookkeeping) writeFileSync(path.join(state, "fail-bookkeeping-once"), "1");
  const run = () => spawnSync("/bin/bash", [path.join(root, "scripts/migrate.sh")], {
    cwd: scratch,
    // Не наследовать пароли, адреса БД, BASH_ENV и прочее окружение оператора.
    env: {
      PATH: `${bin}:/usr/bin:/bin`,
      TMPDIR: temp,
      LC_ALL: "C",
      MIGRATIONS_DIR: migrations,
      ARGUS_MIGRATION_RETRY_STATE: state,
      CLICKHOUSE_HOST: "unused.invalid",
      CLICKHOUSE_USER: "default",
      CLICKHOUSE_PASSWORD: "",
      ARGUS_DEV: "0",
      NODE_ENV: "test", // ProcessEnv в @types/node требует NODE_ENV
    },
    encoding: "utf8",
    timeout: 10_000,
    maxBuffer: 64 * 1024,
  });
  const materializations = (): string[] => {
    const log = path.join(state, "materializations");
    return existsSync(log) ? readFileSync(log, "utf8").trim().split("\n").filter(Boolean).map((s) => JSON.parse(s) as string) : [];
  };
  return { run, materializations, state };
}

test("0032: сохранённая отметка миграции предотвращает повторную материализацию", { timeout: 30_000 }, (t) => {
  const f = fixture(t);
  const first = f.run();
  assert.ifError(first.error);
  assert.equal(first.status, 0, first.stderr);
  assert.equal(readFileSync(path.join(f.state, "applied"), "utf8"), `${migration}\n`);
  const before = f.materializations();
  const again = f.run();
  assert.ifError(again.error);
  assert.equal(again.status, 0, again.stderr);
  assert.match(again.stdout, /already applied/);
  assert.deepEqual(f.materializations(), before, "обычный повтор migrate.sh обязан пропустить уже применённую 0032");
});

test("0032: сбой schema_migrations после ALTER не дублирует полную мутацию при retry", { timeout: 30_000 }, (t) => {
  const f = fixture(t, true);
  const first = f.run();
  assert.ifError(first.error);
  assert.equal(first.status, 75, first.stderr);
  assert.match(first.stderr, /injected schema_migrations write failure/);
  assert.ok(existsSync(path.join(f.state, "index-exists")), "DDL успел выполниться до сбоя отметки");
  assert.ok(!existsSync(path.join(f.state, "applied")), "неудачная отметка не записана");
  const before = f.materializations();

  const retry = f.run();
  assert.ifError(retry.error);
  assert.equal(retry.status, 0, retry.stderr);
  assert.equal(readFileSync(path.join(f.state, "applied"), "utf8"), `${migration}\n`);
  assert.deepEqual(f.materializations(), before,
    "retry после принятого ALTER снова ставит MATERIALIZE INDEX по всей events; IF NOT EXISTS защищает только ADD INDEX");
});
