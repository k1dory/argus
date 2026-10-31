// Общее для тестов на живом ClickHouse: сервер задаётся ARGUS_TEST_CLICKHOUSE_URL
// (+ _USER, _PASSWORD), БД argus; без него тесты пропускаются. Миграции применяются
// из clickhouse/migrations по одному оператору — так же, как migrate.sh --multiquery,
// поэтому заодно проверяется, что каждый файл идемпотентен и применим с нуля по порядку.
import { closeSync, openSync, readdirSync, readFileSync, unlinkSync, writeSync } from "node:fs";
import { createHash } from "node:crypto";
import os from "node:os";
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

/** Межпроцессная блокировка живого ClickHouse: node --test гоняет файлы параллельно,
 *  а файлы с живым сервером делят одну базу argus. Тест claim вердикта снимает и
 *  возвращает колонку миграцией 0025, queries-ch в это время применяет все миграции —
 *  схема менялась под ногами, тесты падали через раз. Файл берёт блокировку в before
 *  и отпускает в after: живые файлы идут по одному, остальные — параллельно.
 *  Блокировка — файл с pid во временном каталоге; брошенную (процесс умер) снимает
 *  следующий. Без ARGUS_TEST_CLICKHOUSE_URL — ничего не делает. */
const LOCK_FILE = path.join(os.tmpdir(), `argus-ch-live-${createHash("sha256").update(liveUrl ?? "").digest("hex").slice(0, 12)}.lock`);

function pidAlive(pid: number): boolean {
  try {
    process.kill(pid, 0);
    return true;
  } catch (e) {
    return (e as NodeJS.ErrnoException).code === "EPERM";
  }
}

export async function acquireLiveLock(timeoutMs = 600_000): Promise<() => void> {
  if (!liveUrl) return () => undefined;
  const started = Date.now();
  for (;;) {
    try {
      const fd = openSync(LOCK_FILE, "wx");
      writeSync(fd, String(process.pid));
      closeSync(fd);
      let released = false;
      const release = () => {
        if (released) return;
        released = true;
        try { unlinkSync(LOCK_FILE); } catch { /* уже снят */ }
      };
      process.once("exit", release);
      return release;
    } catch (e) {
      if ((e as NodeJS.ErrnoException).code !== "EEXIST") throw e;
      try {
        const owner = Number(readFileSync(LOCK_FILE, "utf8"));
        if (owner && !pidAlive(owner)) {
          unlinkSync(LOCK_FILE);
          continue;
        }
      } catch { /* файл исчез между проверками — попробуем снова */ }
      if (Date.now() - started > timeoutMs) throw new Error(`живой ClickHouse занят другим тестом дольше ${timeoutMs / 1000} с (${LOCK_FILE})`);
      await new Promise((r) => setTimeout(r, 200));
    }
  }
}

/** before/after для файла с живым ClickHouse: весь файл — под блокировкой. */
export function serializeLiveFile(hooks: { before: (fn: () => Promise<void>) => void; after: (fn: () => void) => void }): void {
  let release: () => void = () => undefined;
  hooks.before(async () => { release = await acquireLiveLock(); });
  hooks.after(() => release());
}
