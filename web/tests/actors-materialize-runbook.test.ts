// PR #28: старая 0032 уже ставила MATERIALIZE INDEX idx_actor_keys.
// Перед ручным запуском оператор должен видеть и выполняющуюся, и завершённую
// мутацию. Проверяем команды из README; Docker и ALTER здесь не исполняются.
import { test } from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import path from "node:path";
import { ch, liveSkip as skip } from "./_ch-live";

function runbookQueries() {
  const readme = readFileSync(path.resolve(__dirname, "../../README.md"), "utf8");
  const section = readme.split(/^## /m).find((part) => part.startsWith("Паспорт сотрудника\n"));
  assert.ok(section, "в README есть раздел «Паспорт сотрудника»");
  // Извлекается SQL внутри --query, включая многострочные команды.
  return [...section.matchAll(/--query\s+"([^"]+)"/g)].map((match) => ({
    sql: match[1].trim().replace(/;\s*$/, ""),
    offset: match.index!,
  }));
}

function mutationQueries() {
  const queries = runbookQueries().filter(({ sql }) => /^SELECT\b/i.test(sql) && /\bFROM\s+system\.mutations\b/i.test(sql));
  assert.ok(queries.length > 0, "README содержит запрос состояния мутаций");
  return queries;
}

test("README: проверка старой материализации 0032 предшествует ручному ALTER", () => {
  const materialize = runbookQueries().find(({ sql }) => /^ALTER\s+TABLE\s+argus\.events\s+MATERIALIZE\s+INDEX\s+(?:IF\s+EXISTS\s+)?idx_actor_keys\b/i.test(sql));
  assert.ok(materialize, "README содержит ручной шаг построения индекса");
  assert.ok(mutationQueries().some(({ offset }) => offset < materialize.offset),
    "0032 до PR #28 уже могла поставить MATERIALIZE; проверка только после ALTER допускает вторую полную мутацию events");
});

test("README: запрос состояния отличает старую материализацию от отсутствующей", { skip, timeout: 20_000 }, async (t) => {
  const nativeFetch = globalThis.fetch;
  t.mock.method(globalThis, "fetch", (input: URL | string | Request, init?: RequestInit) => {
    const url = new URL(input instanceof Request ? input.url : String(input));
    // Только SELECT над литералами: argus может ещё не существовать в CI.
    url.searchParams.set("database", "default");
    return nativeFetch(url, { ...init, signal: AbortSignal.timeout(5_000) });
  });

  for (const isDone of [0, 1]) {
    await t.test(isDone ? "старая 0032: материализация завершена" : "старая 0032: материализация ещё выполняется", async () => {
      // Строка соответствует system.mutations в ClickHouse 24.8. Сам SQL
      // фильтрации исполняет ClickHouse, его поведение не эмулируется в JS.
      const fixture = `(SELECT
        'argus' AS database, 'events' AS table,
        'mutation_32.txt' AS mutation_id,
        'MATERIALIZE INDEX idx_actor_keys' AS command,
        toDateTime('2026-10-31 00:00:00') AS create_time,
        toInt64(${isDone ? 0 : 3}) AS parts_to_do,
        toUInt8(${isDone}) AS is_done,
        '' AS latest_failed_part,
        toDateTime(0) AS latest_fail_time,
        '' AS latest_fail_reason)`;
      const results: { command: string; is_done: number }[] = [];
      for (const { sql } of mutationQueries()) {
        const query = sql.replace(/\bFROM\s+system\.mutations\b/i, `FROM ${fixture}`);
        assert.doesNotMatch(query, /\bsystem\.mutations\b/i, "не читаем мутации реального стенда");
        results.push(...await ch().chQuery<{ command: string; is_done: number }>(query));
      }
      assert.ok(results.some((row) => row.command === "MATERIALIZE INDEX idx_actor_keys" && Number(row.is_done) === isDone),
        `README скрывает уже принятую материализацию (is_done=${isDone}); пустой результат нельзя принимать за необходимость нового ALTER`);
    });
  }
});
