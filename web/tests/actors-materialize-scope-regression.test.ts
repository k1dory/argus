// PR #29: is_done относится к команде мутации, а не ко всем данным индекса.
// MATERIALIZE ... IN PARTITION и материализация другого индекса не доказывают,
// что прежняя 0032 уже построила idx_actor_keys по всей events. По правилу README
// любая завершённая строка из preflight разрешает пропустить полный ALTER.
// Исполняем SQL из README на литеральной истории; настоящие мутации не читаем.
import { test } from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import path from "node:path";
import { ch, liveSkip as skip } from "./_ch-live";

function preflightQueries(): string[] {
  const readme = readFileSync(path.resolve(__dirname, "../../README.md"), "utf8");
  const section = readme.split(/^## /m).find((part) => part.startsWith("Паспорт сотрудника\n"));
  assert.ok(section, "в README есть раздел «Паспорт сотрудника»");
  const commands = [...section.matchAll(/--query\s+"([^"]+)"/g)].map((match) => ({
    sql: match[1].trim().replace(/;\s*$/, ""), offset: match.index!,
  }));
  const materialize = commands.find(({ sql }) => /^ALTER\s+TABLE\s+argus\.events\s+MATERIALIZE\s+INDEX\s+(?:IF\s+EXISTS\s+)?idx_actor_keys\b/i.test(sql));
  assert.ok(materialize, "README содержит ручной шаг построения индекса");
  const queries = commands.filter(({ sql, offset }) => offset < materialize.offset
    && /^SELECT\b/i.test(sql) && /\bFROM\s+system\.mutations\b/i.test(sql));
  assert.ok(queries.length > 0, "перед полным ALTER проверяется история мутаций");
  return queries.map(({ sql }) => sql);
}

test("PR #29: preflight полной материализации не принимает частичную или чужую мутацию", { skip, timeout: 30_000 }, async (t) => {
  const queries = preflightQueries();
  const nativeFetch = globalThis.fetch;
  t.mock.method(globalThis, "fetch", (input: URL | string | Request, init?: RequestInit) => {
    const url = new URL(input instanceof Request ? input.url : String(input));
    url.searchParams.set("database", "default");
    url.searchParams.set("max_threads", "1");
    url.searchParams.set("max_memory_usage", String(64 * 1024 * 1024));
    url.searchParams.set("max_execution_time", "5");
    return nativeFetch(url, { ...init, signal: AbortSignal.timeout(5_000) });
  });

  const full = "MATERIALIZE INDEX idx_actor_keys";
  const cases = [
    { name: "0032 ещё выполняется", command: full, done: 0, parts: 3, visible: true },
    // parts_to_do=0 не заменяет is_done: такой статус всё ещё нужно показать.
    { name: "нет оставшихся партов, но is_done=0", command: full, done: 0, parts: 0, visible: true },
    { name: "0032 завершена по всей таблице", command: full, done: 1, parts: 0, visible: true },
    { name: "построена только одна партиция", command: `${full} IN PARTITION 202610`, done: 1, parts: 0, visible: false },
    { name: "материализован индекс с более длинным именем", command: `${full}_v2`, done: 1, parts: 0, visible: false },
    { name: "подчёркивания LIKE совпали с другим именем", command: "MATERIALIZE INDEX idxXactorXkeys", done: 1, parts: 0, visible: false },
  ];

  for (const scenario of cases) {
    await t.test(scenario.name, async () => {
      const fixture = `(SELECT
        'argus' AS database, 'events' AS table,
        'mutation_scope.txt' AS mutation_id,
        {scope_command:String} AS command,
        toDateTime('2026-10-31 00:00:00') AS create_time,
        toInt64(${scenario.parts}) AS parts_to_do,
        toUInt8(${scenario.done}) AS is_done,
        '' AS latest_failed_part,
        toDateTime(0) AS latest_fail_time,
        '' AS latest_fail_reason)`;
      const rows: { command: string; is_done: number | string }[] = [];
      for (const sql of queries) {
        const query = sql.replace(/\bFROM\s+system\.mutations\b/i, `FROM ${fixture}`);
        assert.doesNotMatch(query, /\bsystem\.mutations\b/i, "не читаем мутации реального стенда");
        rows.push(...await ch().chQuery<{ command: string; is_done: number | string }>(query, {
          scope_command: scenario.command,
        }));
      }
      if (scenario.visible) {
        assert.ok(rows.some((row) => row.command === full && Number(row.is_done) === scenario.done),
          "проверка обязана сохранять как выполняющуюся, так и завершённую полную материализацию");
      } else {
        assert.deepEqual(rows, [],
          `${scenario.command}: эта завершённая мутация не подтверждает построение idx_actor_keys по всей events; README ошибочно разрешает пропустить полный ALTER`);
      }
    });
  }
});
