// Needs live validation on an isolated ClickHouse 24.8. No tables or DDL:
// compare the previous OR form with auto on the same bounded synthetic block.
// A prefilter is included and every row matches it, so it cannot hide expansion
// of the constant arrays for every candidate event.
import { after, before, test } from "node:test";
import assert from "node:assert/strict";
import { ch, liveSkip as skip, serializeLiveFile } from "./_ch-live";
import { aliasPredicate, aliasPrefilter, parseIdentitiesDoc, type Alias } from "../src/lib/shared/actors";
import { chTs } from "../src/lib/shared/log-query";

serializeLiveFile({ before, after });

test("PR #95: compact predicate preserves the OR result within a bounded memory budget", { skip, timeout: 30_000 }, async () => {
  const window = { fromMs: Date.UTC(2026, 9, 25), toMs: Date.UTC(2026, 10, 1) };
  const rowCount = 1024;
  const aliases: Alias[] = Array.from({ length: 1000 }, (_, i) => ({
    person_id: "pr95-memory", kind: "uid",
    value: `uid-${String(i).padStart(4, "0")}${"x".repeat(248)}`,
    valid_from: chTs(window.fromMs + i), valid_to: null,
    source: "pr95.fixture", confidence: 1, note: "",
  }));
  assert.equal(parseIdentitiesDoc({ persons: { "pr95-memory": {
    aliases: aliases.map((a) => ({ kind: a.kind, value: a.value,
      from: a.valid_from.replace(" ", "T") + "Z" })),
  } } }).ok, true);
  const prefilter = aliasPrefilter(aliases);
  const rows = `SELECT parseDateTime64BestEffort({start:String}, 3, 'UTC') + toIntervalMillisecond(number) AS ts,
      concat('uid-', leftPad(toString(number % 1000), 4, '0'), repeat('x', 248)) AS actor_name,
      '' AS src_ip, '' AS node
    FROM numbers(${rowCount})`;
  const count = async (form: "or" | "auto") => {
    const predicate = aliasPredicate(aliases, window, "", "ts", form);
    const result = await ch().chQuery<{ n: string | number }>(
      `SELECT count() AS n FROM (${rows}) WHERE ${prefilter.sql} AND ${predicate.sql}`,
      { ...prefilter.params, ...predicate.params, start: chTs(window.fromMs + 86_400_000) },
      { max_threads: 1, max_execution_time: 10, max_memory_usage: 128 * 1024 * 1024,
        max_block_size: rowCount, preferred_block_size_bytes: 0 });
    assert.equal(result.length, 1);
    return Number(result[0].n);
  };

  assert.equal(await count("or"), rowCount, "control: previous form fits the same memory/HTTP budget");
  assert.equal(await count("auto"), rowCount, "compact SQL must not lose the report to a memory-limit error");
});
