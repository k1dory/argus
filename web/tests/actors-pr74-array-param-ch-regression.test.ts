// Семантика частей Array(String)/Array(Array(UInt32)) на настоящем ClickHouse.
// Только SELECT над одной искусственной строкой; общие таблицы не затрагиваются.
// Запуск: существующий npm test с ARGUS_TEST_CLICKHOUSE_URL изолированного сервера.
import { after, before, test } from "node:test";
import assert from "node:assert/strict";
import { ch, liveSkip as skip, serializeLiveFile } from "./_ch-live";
import { activityPlan, aliasPrefilter } from "../src/lib/shared/actors";
import { chTs } from "../src/lib/shared/log-query";
import { PR74_WINDOW, fixtureAlias, largeClassFixture, unicodeFixture, type ActivityFixture } from "./_actors-pr74-fixtures";

serializeLiveFile({ before, after });

async function matches(fixture: ActivityFixture, actor: string, ip = "", node = "neutral") {
  const plan = activityPlan(fixture, PR74_WINDOW);
  const pf = aliasPrefilter(fixture.flatMap((p) => p.aliases));
  const rows = await ch().chQuery<{ hits: number[]; candidate: number }>(
    `SELECT ${plan.hits} AS hits, ${pf.sql} AS candidate
     FROM (SELECT parseDateTime64BestEffort({row_ts:String}, 3, 'UTC') AS ts,
       {row_actor:String} AS actor_name, {row_ip:String} AS src_ip, {row_node:String} AS node)`,
    { ...plan.params, ...pf.params, row_ts: chTs(PR74_WINDOW.toMs - 1), row_actor: actor, row_ip: ip, row_node: node },
    { max_threads: 1, max_execution_time: 10, max_memory_usage: 128 * 1024 * 1024 });
  assert.equal(rows.length, 1);
  return rows[0];
}

test("PR #74: Unicode проходит multipart и совпадает через transform и IN", { skip, timeout: 30_000 }, async () => {
  const fixture = unicodeFixture();
  assert.deepEqual(await matches(fixture, fixture[0].aliases[239].value), { hits: [240], candidate: 1 });
});

test("PR #74: 25000 классов одного IP проходят multipart без потери интервалов", { skip, timeout: 30_000 }, async () => {
  const got = await matches(largeClassFixture(), "neutral", "192.0.2.7");
  assert.equal(got.candidate, 1);
  assert.deepEqual(got.hits, Array.from({ length: 25_000 }, (_, i) => i + 1));
});

test("PR #74: SQL/HTTP-подобный uid остаётся данными после деления и multipart", { skip, timeout: 30_000 }, async () => {
  const payload = "Uid'OR(1=1)--\\&param_ap_k0=['evil']{x:String}";
  const aliases = Array.from({ length: 700 }, (_, i) =>
    fixtureAlias("literal", "uid", `filler-${i}`.padEnd(128, "x")));
  aliases.push(fixtureAlias("literal", "uid", payload));
  const fixture = [{ id: "literal", aliases }];
  assert.deepEqual(await matches(fixture, payload), { hits: [701], candidate: 1 });
  assert.deepEqual(await matches(fixture, "evil"), { hits: [], candidate: 0 });
});
