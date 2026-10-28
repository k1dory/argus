// Общее для тестов на живом ClickHouse: сервер задаётся ARGUS_TEST_CLICKHOUSE_URL
// (+ _USER, _PASSWORD), БД argus; без него тесты пропускаются. Миграции применяются
// из clickhouse/migrations по одному оператору — так же, как migrate.sh --multiquery,
// поэтому заодно проверяется, что каждый файл идемпотентен и применим с нуля по порядку.
import { readdirSync, readFileSync } from "node:fs";
import path from "node:path";

export const liveUrl = process.env.ARGUS_TEST_CLICKHOUSE_URL;
export const liveSkip = liveUrl ? false : "нет ARGUS_TEST_CLICKHOUSE_URL — тест живого ClickHouse пропущен";
if (liveUrl) {
  process.env.CLICKHOUSE_URL = liveUrl;
  process.env.CLICKHOUSE_USER = process.env.ARGUS_TEST_CLICKHOUSE_USER ?? "default";
  process.env.CLICKHOUSE_PASSWORD = process.env.ARGUS_TEST_CLICKHOUSE_PASSWORD ?? "";
  process.env.CLICKHOUSE_DB = "argus";
}

/* eslint-disable @typescript-eslint/no-require-imports -- модуль читает env при загрузке */
export const ch = () => require("../src/lib/clickhouse") as typeof import("../src/lib/clickhouse");
/* eslint-enable @typescript-eslint/no-require-imports */

export const root = path.resolve(__dirname, "../..");
export const MIGRATIONS_DIR = path.join(root, "clickhouse/migrations");

/** Операторы файла миграции без комментариев, в порядке записи. */
export function migrationStatements(file: string): string[] {
  const text = readFileSync(path.join(MIGRATIONS_DIR, file), "utf8").replace(/^--.*$/gm, "");
  return text.split(/;\s*\n/).map((s) => s.trim()).filter(Boolean);
}

export async function runMigration(file: string): Promise<void> {
  for (const stmt of migrationStatements(file)) await ch().chCommand(stmt);
}

/** Все миграции по порядку имён — как migrate.sh на свежей установке. */
export async function applyAllMigrations(): Promise<string[]> {
  const files = readdirSync(MIGRATIONS_DIR).filter((f) => f.endsWith(".sql")).sort();
  for (const f of files) await runMigration(f);
  return files;
}
