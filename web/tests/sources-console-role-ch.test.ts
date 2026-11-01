// Миграции и прежние live-тесты выполнялись админом, скрывая отсутствие SELECT
// ON system.parts у реальной консоли. Здесь production sourcesHealthReport
// запускается отдельным пользователем с настройками и правами из migrate.sh.
import { after, before, test } from "node:test";
import assert from "node:assert/strict";
import { randomBytes } from "node:crypto";
import { readFileSync } from "node:fs";
import path from "node:path";
import { applyAllMigrations, ch, liveSkip as skip, root, serializeLiveFile } from "./_ch-live";

serializeLiveFile({ before, after });

/* eslint-disable @typescript-eslint/no-require-imports -- _ch-live устанавливает соединение до загрузки запросов */
const queries = () => require("../src/lib/argus-queries") as typeof import("../src/lib/argus-queries");
/* eslint-enable @typescript-eslint/no-require-imports */

function consoleProfile(): { settings: string; grants: string[] } {
  const script = readFileSync(path.join(root, "scripts/migrate.sh"), "utf8");
  const call = script.match(/^mkuser argus_console\b(?:.*\\\n)*.*$/m);
  assert.ok(call, "production профиль argus_console должен находиться в migrate.sh");
  // Аргументы mkuser: password, settings, grants. Поддерживаем обе shell-кавычки
  // и экранирование внутри двойных (например, SQL-идентификатор `table`).
  // Сам shell-скрипт не исполняем и его пароль не используем.
  const quoted = [...call[0].matchAll(/"((?:\\.|[^"\\])*)"|'([^']*)'/g)]
    .map((m) => m[2] ?? m[1].replace(/\\(["\\$`])/g, "$1"));
  const [, settings, ...grants] = quoted;
  assert.ok(settings && settings.includes("allow_ddl"), "разобраны production настройки консоли");
  assert.ok(grants.includes("SELECT ON argus.*"), "консоль читает прикладную БД");
  assert.ok(grants.length > 0 && grants.every((g) => /^(SELECT|INSERT)\b/.test(g) && !g.includes("$")), "неизвестный формат грантов нельзя молча пропускать");
  return { settings, grants };
}

test("sourcesHealthReport работает с точными production правами argus_console", { skip }, async (t) => {
  await applyAllMigrations();
  const { settings, grants } = consoleProfile();
  const suffix = randomBytes(6).toString("hex");
  const user = `argus_console_test_${suffix}`;
  const password = `fixture-${randomBytes(16).toString("hex")}`;
  const source = `console.role.${suffix}`;
  let created = false, inserted = false, asConsole = false;
  const nativeFetch = globalThis.fetch;
  const consoleAuth = "Basic " + Buffer.from(`${user}:${password}`).toString("base64");
  t.mock.method(globalThis, "fetch", async (input: URL | string | Request, init?: RequestInit) => {
    // Только переключение principal. SQL, URL, параметры, настройки и ответы
    // настоящего ClickHouse сохраняются; production query не заменяется моками.
    if (!asConsole) return nativeFetch(input, init);
    const headers = new Headers(init?.headers);
    headers.set("Authorization", consoleAuth);
    return nativeFetch(input, { ...init, headers });
  });

  try {
    // Dummy-пароль не относится к окружению. Настройки, REVOKE ALL и каждый
    // GRANT воспроизводят mkuser; дополнительных разрешений тест не добавляет.
    await ch().chCommand(`CREATE USER ${user} IDENTIFIED WITH sha256_password BY '${password}'`);
    created = true;
    await ch().chCommand(`ALTER USER ${user} SETTINGS ${settings}`);
    await ch().chCommand(`REVOKE ALL ON *.* FROM ${user}`);
    for (const grant of grants) await ch().chCommand(`GRANT ${grant} TO ${user}`);

    // Прямой writer не имеет heartbeat: успешный результат должен прийти
    // именно через guard и p_source_last, а не случайно через fallback.
    await ch().chCommand(`INSERT INTO events (ts, received_at, source, source_class, action)
      SELECT now64(3) - INTERVAL 2 HOUR, now() - INTERVAL 2 HOUR, {source:String}, 'system', 'fixture'
      FROM numbers(20)`, { source });
    inserted = true;
    await ch().chCommand("ALTER TABLE events MATERIALIZE PROJECTION p_source_last SETTINGS mutations_sync = 2");
    const [ready] = await ch().chQuery<{ missing: string | number }>(
      "SELECT count() AS missing FROM system.parts WHERE database = currentDatabase() AND table = 'events' AND active AND rows > 0 AND NOT has(projections, 'p_source_last')");
    assert.equal(Number(ready.missing), 0, "проекция готова: проверяем права, не миграционный fallback");

    asConsole = true;
    const [principal] = await ch().chQuery<{ name: string }>("SELECT currentUser() AS name");
    assert.equal(principal.name, user, "запросы исполняются тестовым аналогом argus_console, не админом");
    const [visible] = await ch().chQuery<{ n: string | number }>("SELECT count() AS n FROM events WHERE source = {source:String}", { source });
    assert.equal(Number(visible.n), 20, "SELECT ON argus.* работает под этой же учёткой");

    await t.test("metadata grant не открывает лишние столбцы system.parts", async () => {
      await assert.rejects(ch().chQuery("SELECT name, path FROM system.parts WHERE database = currentDatabase() AND table = 'events' LIMIT 1"), (error: unknown) => {
        assert.ok(error instanceof ch().ClickHouseError);
        assert.equal(error.code, 497, "нужен отказ прав, а не произвольная ошибка SQL/сервера");
        return true;
      });
    });

    await t.test("полный sources report успешно читает metadata guard и прямого writer", async () => {
      const report = await queries().sourcesHealthReport();
      const direct = report.sources.find((row) => row.source === source);
      assert.ok(direct, "источник без heartbeat должен быть виден через полную проекцию");
      assert.equal(direct.source_class, "system");
      assert.equal(direct.events_1h, 0);
      assert.equal(direct.alive, 0);
      assert.ok(direct.last_ts);
      assert.ok(Number.isInteger(report.omitted) && report.omitted >= 0);
    });
  } finally {
    asConsole = false;
    try {
      if (created) await ch().chCommand(`DROP USER ${user}`);
    } finally {
      if (inserted) await ch().chCommand("ALTER TABLE events DELETE WHERE source = {source:String} SETTINGS mutations_sync = 1", { source });
    }
  }
});
