// Активность персон в списке «Субъекты» (listPersons) на живом ClickHouse: один
// проход по окну через activityPlan вместо сотен веток OR. На проде (rc31) запрос
// countIf по OR алиасов сотни персон читал 23–25 млн строк горячих логинов и
// упирался в таймаут 20 с: hasAny со всеми 374 значениями сравнивал каждую строку с
// каждым значением (60+ с), а индекс при сотнях значений не отсекает. Здесь: персона
// на 210 алиасов, ещё 100 персон, горячий
// логин; результат сверяется с прежним предикатом (aliasPredicate, count/max по
// каждой персоне), SQL — без OR по алиасам и постоянного размера, предфильтр — IN по
// колонкам; с малым числом значений hasAny по idx_actor_keys отсекает гранулы (EXPLAIN).
import { after, before, test } from "node:test";
import assert from "node:assert/strict";
import { randomBytes } from "node:crypto";
import { readdirSync } from "node:fs";
import { MIGRATIONS_DIR, ch, liveSkip as skip, migrationStatements, serializeLiveFile } from "./_ch-live";
import { chTs } from "../src/lib/shared/log-query";
import { aliasPredicate, aliasPrefilter, clampWindow, rangeWindow, type Alias } from "../src/lib/shared/actors";

serializeLiveFile({ before, after });

/* eslint-disable @typescript-eslint/no-require-imports -- ClickHouse env установлен _ch-live до загрузки actors */
const actors = () => require("../src/lib/actors") as typeof import("../src/lib/actors");
/* eslint-enable @typescript-eslint/no-require-imports */

const DAY = 86_400_000;

test("listPersons: 200+ алиасов и 100 персон — один проход, счёт как у предиката, предфильтр по индексу", { skip, timeout: 120_000 }, async (t) => {
  const db = `argus_actors_activity_${randomBytes(6).toString("hex")}`;
  let database = "default", created = false;
  const captured: { sql: string; params: Record<string, string> }[] = [];
  const nativeFetch = globalThis.fetch;
  t.mock.method(globalThis, "fetch", (input: URL | string | Request, init?: RequestInit) => {
    const url = new URL(input instanceof Request ? input.url : String(input));
    url.searchParams.set("database", database);
    const sql = String(init?.body ?? "");
    if (/FROM events/.test(sql) && /ARRAY JOIN ps/.test(sql)) {
      captured.push({ sql, params: Object.fromEntries([...url.searchParams].filter(([k]) => k.startsWith("param_")).map(([k, v]) => [k.slice(6), v])) });
    }
    return nativeFetch(url, init);
  });
  const now = Date.now();
  const w = clampWindow(rangeWindow("7d", now));
  const at = (ms: number) => chTs(ms);
  try {
    created = true;
    await ch().chCommand(`CREATE DATABASE ${db}`);
    database = db;
    for (const file of readdirSync(MIGRATIONS_DIR).filter((f) => f.endsWith(".sql")).sort()) {
      for (const sql of migrationStatements(file)) {
        if (/^CREATE DATABASE\b/i.test(sql)) continue;
        await ch().chCommand(sql.replaceAll("argus.", `${db}.`));
      }
    }
    // Персоны и алиасы: big — 210 алиасов всех видов с разными интервалами; ещё
    // 100 персон по два алиаса; hot — логин, у которого 60 тыс. событий.
    type Row = { person_id: string; alias_kind: string; alias_value: string; valid_from: string; valid_to: string | null; confidence: number };
    const aliasRows: Row[] = [];
    const add = (person: string, kind: string, value: string, from = now - 30 * DAY, to: number | null = null, confidence = 1) =>
      aliasRows.push({ person_id: person, alias_kind: kind, alias_value: value, valid_from: at(from), valid_to: to === null ? null : at(to), confidence });
    for (let i = 0; i < 60; i++) add("big", "email", `big${i}@example.test`);
    for (let i = 0; i < 50; i++) add("big", "login", `big.login${i}`, now - 3 * DAY + i * 60_000); // начинаются внутри окна
    for (let i = 0; i < 40; i++) add("big", "uid", `big-uid-${i}`, now - 30 * DAY, now - 2 * DAY); // кончаются внутри окна
    for (let i = 0; i < 50; i++) add("big", "ip", `100.103.${Math.floor(i / 250)}.${(i % 250) + 1}`, now - 4 * DAY, now - DAY);
    for (let i = 0; i < 10; i++) add("big", "host", `big-host-${i}`);
    add("big", "uid", "dual"); add("big", "login", "dual"); // одна строка совпадает с двумя алиасами — один раз
    add("big", "login", "held.login", now - 30 * DAY, null, 0.4); // удержанный — не считается
    for (let p = 0; p < 100; p++) { add(`p${String(p).padStart(3, "0")}`, "login", `user${p}`); add(`p${String(p).padStart(3, "0")}`, "ip", `100.64.${p}.1`, now - 2 * DAY); }
    add("hot", "login", "admin");
    add("shared-a", "login", "shared.value"); add("shared-b", "uid", "shared.value"); // одно значение — две персоны
    const persons = [...new Set(aliasRows.map((r) => r.person_id))];
    const json = (rows: object[]) => rows.map((r) => JSON.stringify(r)).join("\n");
    await ch().chCommand(`INSERT INTO identities FORMAT JSONEachRow\n${json(persons.map((p) => ({ person_id: p, display: p, kind: "person", team: "", note: "", updated_at: at(now - DAY), deleted: 0 })))}`);
    await ch().chCommand(`INSERT INTO identity_aliases FORMAT JSONEachRow\n${json(aliasRows.map((r) => ({ ...r, source: "fixture", note: "", updated_at: at(now - DAY), deleted: 0 })))}`);
    // Фон: 65536 строк без алиасов — отдельным партом; затем совпадения.
    await ch().chCommand(`INSERT INTO events (ts, source, source_class, actor_name, src_ip, node, action, outcome)
      SELECT parseDateTime64BestEffort({f:String}, 3, 'UTC') + toIntervalMillisecond(number * 7), 'fixture.bg', 'syslog', 'unrelated-background', '192.0.2.254', 'bg-node', 'noise', 'success'
      FROM numbers(65536)`, { f: at(now - 5 * DAY) });
    const ev: object[] = [];
    const push = (ts: number, actor: string, ip = "", node = "") => ev.push({ ts: at(ts), source: "fixture.match", source_class: "identity", actor_name: actor, src_ip: ip, node, action: "auth.login", outcome: "success" });
    for (let i = 0; i < 60; i++) push(now - 2 * DAY - i * 1000, i % 2 ? `BIG${i}@EXAMPLE.TEST` : `big${i}@example.test`); // регистр не важен
    for (let i = 0; i < 50; i++) { push(now - 3 * DAY - 60_000, `big.login${i}`); push(now - DAY + i, `Big.Login${i}`); } // до начала алиаса — не считается
    for (let i = 0; i < 40; i++) { push(now - 3 * DAY, `big-uid-${i}`); push(now - DAY, `big-uid-${i}`); push(now - 3 * DAY, `BIG-UID-${i}`); } // uid — с учётом регистра; после конца — нет
    for (let i = 0; i < 50; i++) { push(now - 2 * DAY, "", `100.103.${Math.floor(i / 250)}.${(i % 250) + 1}`); push(now - 12 * 3600_000, "", `100.103.0.${(i % 250) + 1}`); }
    for (let i = 0; i < 10; i++) push(now - 2 * DAY, "", "", `BIG-HOST-${i}`);
    push(now - 2 * DAY, "dual"); push(now - 2 * DAY, "dual");
    push(now - 2 * DAY, "held.login");
    for (let p = 0; p < 100; p++) { push(now - 3 * DAY, `user${p}`); push(now - 3 * DAY, "", `100.64.${p}.1`); push(now - DAY, "", `100.64.${p}.1`); }
    push(now - 2 * DAY, "shared.value");
    push(now - 8 * DAY, "big0@example.test"); // вне окна
    await ch().chCommand(`INSERT INTO events (ts, source, source_class, actor_name, src_ip, node, action, outcome) FORMAT JSONEachRow\n${json(ev)}`);
    await ch().chCommand(`INSERT INTO events (ts, source, source_class, actor_name, src_ip, node, action, outcome)
      SELECT parseDateTime64BestEffort({f:String}, 3, 'UTC') + toIntervalMillisecond(number * 5), 'fixture.hot', 'auth', 'admin', '', 'jump', 'auth.ssh', 'failure'
      FROM numbers(60000)`, { f: at(now - 4 * DAY) });

    const list = await actors().listPersons("7d", now);
    assert.equal(captured.length, 1, "события всех персон — одним запросом");
    const q = captured[0];
    // OR — только между IN по колонкам (не больше четырёх), не по алиасам; при сотнях
    // значений hasAny не ставится: он сравнивал бы каждую строку с каждым значением.
    assert.ok((q.sql.match(/ OR /g) ?? []).length <= 3, "без OR по алиасам");
    assert.ok(!q.sql.includes("hasAny("), "больше PREFILTER_INDEX_MAX значений — не hasAny");
    assert.match(q.sql, /lowerUTF8\(actor_name\) IN \{pf_in\d:Array\(String\)\}/, "предфильтр — IN по колонке вида алиаса");
    assert.ok(q.sql.length < 3000, `размер SQL не зависит от числа алиасов: ${q.sql.length}`);

    // Эталон — прежний предикат по каждой персоне.
    const aliasesOf = (person: string): Alias[] => aliasRows.filter((r) => r.person_id === person).map((r) => ({
      person_id: r.person_id, kind: r.alias_kind as Alias["kind"], value: r.alias_value, valid_from: r.valid_from, valid_to: r.valid_to, source: "fixture", confidence: r.confidence, note: "",
    }));
    for (const person of persons) {
      // Эталон — без предфильтра: так видно, что IN/hasAny не уже точного предиката.
      const pred = aliasPredicate(aliasesOf(person), w);
      const [want] = await ch().chQuery<{ n: string; last: string }>(
        `SELECT count() AS n, toString(max(ts)) AS last FROM events WHERE ts >= parseDateTime64BestEffort({from:String}, 3, 'UTC') AND ts < parseDateTime64BestEffort({to:String}, 3, 'UTC') AND ${pred.sql}`,
        { from: chTs(w.fromMs), to: chTs(w.toMs), ...pred.params });
      const got = list.find((p) => p.person_id === person)!;
      assert.equal(got.events, Number(want.n), `${person}: событий`);
      assert.equal(got.last_ts, Number(want.n) > 0 ? want.last : null, `${person}: последнее событие`);
    }
    const big = list.find((p) => p.person_id === "big")!;
    // email 60 (без учёта регистра), login 50 (до начала алиаса — нет), uid 40 (с учётом
    // регистра, после конца — нет), ip 50, host 10, «dual» 2 (каждая строка один раз).
    assert.equal(big.events, 60 + 50 + 40 + 50 + 10 + 2, "big: регистр, интервалы, «dual» один раз, удержанный не считается");
    assert.equal(list.find((p) => p.person_id === "hot")!.events, 60000);
    assert.deepEqual([list.find((p) => p.person_id === "shared-a")!.events, list.find((p) => p.person_id === "shared-b")!.events], [1, 1], "одно значение — обеим персонам");

    // Отсечения по idx_actor_keys при сотнях значений нет: у bloom_filter(0.01) группа
    // гранул «может содержать» хотя бы одно из n значений с вероятностью 1 − 0,99ⁿ
    // (≈ 98 % при n = 374, как на argus1). Поэтому при многих значениях — IN; с малым
    // числом значений (паспорт одного человека) hasAny по индексу гранулы фона отсекает.
    const one = aliasPrefilter(aliasesOf("hot"));
    const single = (await ch().chQuery<{ explain: string }>(`EXPLAIN indexes = 1 SELECT count() FROM events WHERE ts >= parseDateTime64BestEffort({from:String}, 3, 'UTC') AND ${one.sql}`,
      { from: chTs(w.fromMs), ...one.params })).map((r) => r.explain).join("\n");
    const bloom = single.match(/Name:\s+idx_actor_keys\b[\s\S]*?Granules:\s*(\d+)\s*\/\s*(\d+)/);
    assert.ok(bloom && Number(bloom[1]) < Number(bloom[2]), `контроль: с одним значением гранулы фона отсечены:\n${single}`);
  } finally {
    database = "default";
    if (created) await ch().chCommand(`DROP DATABASE IF EXISTS ${db} SYNC`);
  }
});
