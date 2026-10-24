// Гранты учётки ClickHouse консоли: web пишет учёткой
// argus_console, а migrate.sh делает ей REVOKE ALL и выдаёт только
// перечисленное. Таблица, в которую консоль пишет без гранта, в бою даёт
// ошибку прав на каждый INSERT — моки запросов в тестах этого не видят.
import { test } from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import path from "node:path";

const root = path.resolve(__dirname, "../..");

/** Таблицы из INSERT INTO в исходнике запросов консоли. */
function insertTables(file: string): string[] {
  const src = readFileSync(path.join(root, file), "utf8");
  return [...src.matchAll(/INSERT INTO\s+(?:argus\.)?([a-z_][a-z0-9_]*)/gi)].map((m) => m[1]);
}

/** Гранты INSERT учётки argus_console из вызова mkuser в migrate.sh. */
function consoleInsertGrants(): Set<string> {
  const sh = readFileSync(path.join(root, "scripts/migrate.sh"), "utf8");
  const call = sh.match(/^mkuser argus_console\b(?:.*\\\n)*.*$/m);
  assert.ok(call, "в migrate.sh нет mkuser argus_console");
  return new Set([...call[0].matchAll(/"INSERT ON argus\.([a-z0-9_]+)"/g)].map((m) => m[1]));
}

test("каждая таблица из INSERT INTO консоли есть в грантах argus_console", () => {
  const grants = consoleInsertGrants();
  const tables = new Set([...insertTables("web/src/lib/argus-queries.ts"), ...insertTables("web/src/lib/queries.ts")]);
  assert.ok(tables.has("triage_verdicts"), "разбор самого теста: INSERT INTO triage_verdicts должен найтись");
  const missing = [...tables].filter((t) => !grants.has(t));
  assert.deepEqual(missing, [], `нет гранта INSERT для argus_console: ${missing.join(", ")}`);
});
