// aliasPredicate: компактная форма (массивы параметрами, arrayExists) отбирает ровно те же
// строки, что ветки OR, — на настоящем ClickHouse, на синтетических строках без таблиц.
import { after, before, test } from "node:test";
import assert from "node:assert/strict";
import { ch, liveSkip as skip, serializeLiveFile } from "./_ch-live";
import { aliasPredicate, PREDICATE_OR_MAX, type Alias } from "../src/lib/shared/actors";
import { chTs } from "../src/lib/shared/log-query";

serializeLiveFile({ before, after });

const W = { fromMs: Date.UTC(2026, 9, 25), toMs: Date.UTC(2026, 10, 1) };
const mk = (kind: Alias["kind"], value: string, from: number, to: number | null, confidence = 1): Alias =>
  ({ person_id: "p", kind, value, valid_from: chTs(from), valid_to: to === null ? null : chTs(to), source: "t", confidence, note: "" });

test("aliasPredicate: arrays и or считают одно и то же — виды, регистр, интервалы, удержанные, граница [from,to)", { skip, timeout: 30_000 }, async () => {
  const day = 86_400_000;
  const aliases: Alias[] = [
    mk("uid", "U-1", W.fromMs, null),
    mk("uid", "U-2", W.fromMs + 2 * day, W.fromMs + 3 * day),
    mk("login", "ivan", W.fromMs, null),                 // lowerUTF8(actor_name)
    mk("email", "ivan@corp.local", W.fromMs + day, null),
    mk("ip", "192.0.2.7", W.fromMs, W.fromMs + day),
    mk("host", "web-01", W.fromMs + 4 * day, null),
    mk("login", "held", W.fromMs, null, 0.2),            // удержанный — не считается
    mk("uid", "old", W.fromMs - 10 * day, W.fromMs - day), // вне окна
  ];
  const rows = `SELECT parseDateTime64BestEffort({start:String}, 3, 'UTC') + toIntervalMinute(number * 7) AS ts,
      ['U-1', 'U-2', 'IVAN', 'Ivan@Corp.local', 'held', 'old', 'x'][number % 7 + 1] AS actor_name,
      ['192.0.2.7', '198.51.100.1'][number % 2 + 1] AS src_ip,
      ['WEB-01', 'db-01', 'web-01'][number % 3 + 1] AS node
    FROM numbers(1440)`;
  const count = async (form: "or" | "arrays") => {
    const p = aliasPredicate(aliases, W, "", "ts", form);
    if (form === "arrays") assert.match(p.sql, /arrayExists/);
    else assert.doesNotMatch(p.sql, /arrayExists/);
    const r = await ch().chQuery<{ n: string | number }>(`SELECT countIf(${p.sql}) AS n FROM (${rows})`,
      { ...p.params, start: chTs(W.fromMs - day) });
    return Number(r[0].n);
  };
  const or = await count("or");
  assert.ok(or > 100, `выборка непустая: ${or}`);
  assert.equal(await count("arrays"), or);
  // auto: больше PREDICATE_OR_MAX алиасов — компактная форма, SQL не растёт.
  const many = Array.from({ length: 1000 }, (_, i) => mk("uid", `u-${i}`, W.fromMs, null));
  const auto = aliasPredicate(many, W);
  assert.ok(many.length > PREDICATE_OR_MAX && /arrayExists/.test(auto.sql) && auto.sql.length < 2000, auto.sql.slice(0, 200));
});
