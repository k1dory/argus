// PR #70: сравнение реального listPersons с прежним aliasPredicate на границах
// интервалов, при переключении 32 -> 33 значения и при большом числе владельцев
// горячего значения. Только отдельная временная БД; запуск через обычный npm test
// с ARGUS_TEST_CLICKHOUSE_URL, указывающим на изолированный тестовый ClickHouse.
import { after, before, test, type TestContext } from "node:test";
import assert from "node:assert/strict";
import { randomBytes } from "node:crypto";
import { ch, liveSkip as skip, migrationStatements, serializeLiveFile } from "./_ch-live";
import { aliasPredicate, parseAliasInput, rangeWindow, type Alias, type AliasKind } from "../src/lib/shared/actors";
import { chTs } from "../src/lib/shared/log-query";

serializeLiveFile({ before, after });

/* eslint-disable @typescript-eslint/no-require-imports -- _ch-live задаёт окружение до загрузки клиента */
const actors = () => require("../src/lib/actors") as typeof import("../src/lib/actors");
/* eslint-enable @typescript-eslint/no-require-imports */

type RequestRecord = { sql: string; url: URL };
const DAY = 86_400_000;

async function withDatabase(t: TestContext, run: (requests: RequestRecord[]) => Promise<void>) {
  const db = `argus_pr70_activity_${randomBytes(6).toString("hex")}`;
  let database = "default", created = false;
  const requests: RequestRecord[] = [];
  const nativeFetch = globalThis.fetch;
  t.mock.method(globalThis, "fetch", (input: URL | string | Request, init?: RequestInit) => {
    const url = new URL(input instanceof Request ? input.url : String(input));
    url.searchParams.set("database", database);
    url.searchParams.set("max_threads", "1");
    url.searchParams.set("max_memory_usage", String(128 * 1024 * 1024));
    url.searchParams.set("max_execution_time", "10");
    url.searchParams.set("max_block_size", "16384");
    url.searchParams.set("preferred_block_size_bytes", "0");
    requests.push({ sql: String(init?.body ?? ""), url });
    return nativeFetch(url, { ...init, signal: AbortSignal.timeout(15_000) });
  });
  try {
    created = true;
    await ch().chCommand(`CREATE DATABASE ${db}`);
    database = db;
    for (const [file, table] of [
      ["0005_events_incidents.sql", "events"],
      ["0026_identities.sql", "identities"],
      ["0026_identities.sql", "identity_aliases"],
    ]) {
      const sql = migrationStatements(file).find((statement) => statement.startsWith(`CREATE TABLE IF NOT EXISTS argus.${table}\n`));
      assert.ok(sql, `${table}: схема взята из миграции`);
      await ch().chCommand(sql.replaceAll("argus.", `${db}.`));
    }
    // Для пустых инцидентов достаточно колонок, которые читает listPersons.
    // Таблицы событий, персон и версий алиасов используют настоящую схему.
    await ch().chCommand(`CREATE TABLE incidents_current
      (actor_name String, first_ts DateTime64(3, 'UTC'), created_at DateTime('UTC')) ENGINE = Memory`);
    await run(requests);
  } finally {
    database = "default";
    if (created) await ch().chCommand(`DROP DATABASE IF EXISTS ${db} SYNC`);
  }
}

async function insert(table: "events" | "identities" | "identity_aliases", rows: object[]) {
  if (rows.length) await ch().chCommand(`INSERT INTO ${table} FORMAT JSONEachRow\n${rows.map((row) => JSON.stringify(row)).join("\n")}`);
}

test("PR #70: count/last, границы [from,to), виды, удаления и SQL-параметры при 32 и 33 значениях", { skip, timeout: 120_000 }, async (t) => {
  await withDatabase(t, async (requests) => {
    const now = Date.now(), at = now - DAY;
    const w = rangeWindow("7d", now);
    const people = new Set<string>(["empty", "filler"]);
    const aliasRows: object[] = [], events: object[] = [];
    const expected = new Map<string, number[]>();
    const values = new Set<string>();
    const add = (person: string, kind: AliasKind, value: string, from = w.fromMs, to: number | null = null, confidence = 1) => {
      people.add(person);
      if (confidence >= 0.5) values.add(value);
      const row = {
        person_id: person, alias_kind: kind, alias_value: value,
        valid_from: chTs(from), valid_to: to === null ? null : chTs(to),
        confidence, source: "fixture", note: "", updated_at: chTs(now - 1000), deleted: 0,
      };
      aliasRows.push(row);
      return row;
    };
    const event = (ts: number, actor_name: string, src_ip = "", node = "neutral") => {
      events.push({ ts: chTs(ts), source: "pr70.fixture", source_class: "identity", action: "auth.login", actor_name, src_ip, node });
    };

    add("login", "login", "alice", at, at + 10);
    for (const offset of [-1, 0, 0, 9, 10]) event(at + offset, "ALICE");
    expected.set("login", [at, at, at + 9]);

    add("email", "email", "alice@example.test", w.fromMs - DAY);
    for (const ts of [w.fromMs - 1, w.fromMs, at, now]) event(ts, "ALICE@EXAMPLE.TEST");
    expected.set("email", [w.fromMs, at]);

    add("host", "host", "srv-1");
    event(at, "neutral", "", "SRV-1");
    event(at + 1, "SRV-1"); // actor_name не заменяет node.
    expected.set("host", [at]);

    add("ip", "ip", "2001:db8::7");
    event(at, "neutral", "2001:db8::7");
    event(at + 1, "2001:db8::7");
    expected.set("ip", [at]);

    const phone = parseAliasInput({ kind: "phone", value: "+7 (999) 123-45-67" });
    assert.ok(phone.ok);
    assert.equal(phone.alias.value, "+79991234567");
    add("phone", "phone", phone.alias.value);
    event(at, phone.alias.value);
    event(at + 1, "+7 (999) 123-45-67");
    expected.set("phone", [at]);

    for (const [kind, value] of [["uid", "UID-Case"], ["sid", "S-1-5-21-Case"], ["peer", "WireKey+AbC/="]] as const) {
      add(kind, kind, value);
      event(at, value);
      event(at + 1, value.toLowerCase());
      expected.set(kind, [at]);
    }

    add("all-slots", "uid", "dual"); add("all-slots", "login", "dual");
    add("all-slots", "host", "dual"); add("all-slots", "ip", "192.0.2.7");
    event(at, "dual", "192.0.2.7", "DUAL");
    event(at, "dual", "192.0.2.7", "DUAL");
    event(at + 1, "DUAL", "192.0.2.7", "DUAL");
    expected.set("all-slots", [at, at, at + 1]);

    const closed = add("previous", "login", "shared", w.fromMs, at + 1);
    aliasRows.push({ ...closed, valid_to: null, updated_at: chTs(now - 2000) });
    add("next", "login", "shared", at + 1);
    event(at, "SHARED"); event(at + 1, "SHARED");
    expected.set("previous", [at]); expected.set("next", [at + 1]);

    const held = add("held", "login", "held-login", w.fromMs, null, 0.49);
    aliasRows.push({ ...held, confidence: 1, updated_at: chTs(now - 2000) });
    event(at + 100, "held-login");
    const removed = add("deleted-alias", "login", "deleted-login");
    aliasRows.push({ ...removed, deleted: 1, updated_at: chTs(now - 500) });
    values.delete("deleted-login");
    event(at + 100, "deleted-login");
    add("deleted-person", "login", "orphan-login");
    values.delete("orphan-login");
    event(at + 100, "orphan-login");

    const literal = "Uid'OR(1=1)--\\&param_ap_k0=['evil']{x:String}";
    add("parameter", "uid", literal);
    event(at, literal); event(at + 1, "evil");
    expected.set("parameter", [at]);
    const fillerCount = 32 - values.size;
    assert.ok(fillerCount > 0);
    for (let i = 0; i < fillerCount; i++) add("filler", "login", `unused-${i}`);
    assert.equal(values.size, 32);

    const personRows = [...people].map((person_id) => ({
      person_id, display: person_id, kind: "person", team: "fixture", note: "", updated_at: chTs(now - 1000), deleted: 0,
    }));
    personRows.push({ ...personRows.find((person) => person.person_id === "deleted-person")!, deleted: 1, updated_at: chTs(now - 500) });
    await insert("identities", personRows);
    await insert("identity_aliases", aliasRows);
    await insert("events", events);

    for (const count of [32, 33]) {
      if (count === 33) {
        const extra = add("filler", "login", "unused-extra");
        await insert("identity_aliases", [extra]);
      }
      const start = requests.length;
      const list = await actors().listPersons("7d", now);
      const queries = requests.slice(start).filter((request) => /\bFROM events\b/.test(request.sql));
      assert.equal(queries.length, 1, "события всех персон читаются одним запросом");
      assert.ok(queries[0].sql.length < 3000);
      if (count === 32) assert.match(queries[0].sql, /hasAny\(/);
      else { assert.doesNotMatch(queries[0].sql, /hasAny\(/); assert.match(queries[0].sql, / IN \{pf_in\d:Array\(String\)\}/); }
      assert.ok(!queries[0].sql.includes(literal), "значение не становится SQL");
      assert.equal(queries[0].url.searchParams.get("max_result_rows"), "20000", "значение не становится HTTP-настройкой");
      assert.equal(list.length, people.size - 1);
      assert.ok(!list.some((person) => person.person_id === "deleted-person"));
      for (const person of list) {
        const times = expected.get(person.person_id) ?? [];
        const want = { events: times.length, last_ts: times.length ? chTs(Math.max(...times)) : null };
        assert.deepEqual({ events: person.events, last_ts: person.last_ts }, want, `${count}: ${person.person_id}`);
        const aliases = await actors().personAliases(person.person_id);
        const pred = aliasPredicate(aliases, w);
        const [reference] = await ch().chQuery<{ events: string | number; last_ts: string }>(
          `SELECT count() AS events, toString(max(ts)) AS last_ts FROM events WHERE ${pred.sql}`, pred.params);
        assert.deepEqual({ events: Number(reference.events), last_ts: Number(reference.events) ? reference.last_ts : null }, want,
          `${count}: прежний aliasPredicate, ${person.person_id}`);
      }
    }
  });
});

// Эта проверка устанавливает ограничение памяти, а не хрупкий SLA по времени.
// Её результат необходимо подтвердить на ClickHouse 24.8: unit-мок не способен
// проверить материализацию массивов ga[transform(...)] и захват ts в arrayFilter.
test("PR #70: горячие общие значения не раздувают listPersons сверх 128 MiB", { skip, timeout: 60_000 }, async (t) => {
  await withDatabase(t, async (requests) => {
    const now = Date.now(), eventCount = 16384, ownerCount = 512;
    const from = chTs(now - 2 * DAY), eventFrom = chTs(now - DAY);
    const people = Array.from({ length: ownerCount }, (_, i) => ({
      person_id: `hot-${String(i).padStart(4, "0")}`, display: `Hot ${String(i).padStart(4, "0")}`,
      kind: "person", team: "fixture", note: "", updated_at: chTs(now - 1000), deleted: 0,
    }));
    const aliases = people.flatMap((person) => ["login", "uid"].flatMap((kind) => ["hot-a", "hot-b"].map((value) => ({
      person_id: person.person_id, alias_kind: kind, alias_value: value,
      valid_from: from, valid_to: null, source: "fixture", confidence: 1, note: "", updated_at: chTs(now - 1000), deleted: 0,
    }))));
    await insert("identities", people);
    await insert("identity_aliases", aliases);
    await ch().chCommand(`INSERT INTO events (ts, source, source_class, action, actor_name, node)
      SELECT parseDateTime64BestEffort({from:String}, 3, 'UTC') + toIntervalMillisecond(number),
        'pr70.hot', 'identity', 'auth.login', if(number % 2 = 0, 'hot-a', 'hot-b'), 'neutral'
      FROM numbers({count:UInt64})`, { from: eventFrom, count: eventCount });

    // Контроль под теми же лимитами: прежний предикат считает каждую строку
    // однажды, хотя совпали login и uid; все 512 владельцев имеют этот предикат.
    const own: Alias[] = aliases.slice(0, 4).map((alias) => ({
      person_id: alias.person_id, kind: alias.alias_kind as AliasKind, value: alias.alias_value,
      valid_from: alias.valid_from, valid_to: null, source: alias.source, confidence: 1, note: "",
    }));
    const pred = aliasPredicate(own, rangeWindow("7d", now));
    const [reference] = await ch().chQuery<{ events: string | number; last_ts: string }>(
      `SELECT count() AS events, toString(max(ts)) AS last_ts FROM events WHERE ${pred.sql}`, pred.params);
    assert.equal(Number(reference.events), eventCount);
    const start = requests.length;
    const list = await actors().listPersons("7d", now);
    assert.equal(requests.slice(start).filter((request) => /\bFROM events\b/.test(request.sql)).length, 1);
    assert.equal(list.length, ownerCount);
    for (const person of list) {
      assert.equal(person.events, eventCount, person.person_id);
      assert.equal(person.last_ts, reference.last_ts, person.person_id);
    }
  });
});
