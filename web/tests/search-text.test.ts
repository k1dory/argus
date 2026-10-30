// Свободный текст поиска: точная проверка подстроки (смысл прежний) плюс
// предфильтр по n-граммному индексу idx_text (миграция 0030); разбор ответа
// поиска на страницу, гистограмму и фасеты с независимыми бюджетами.
import { test } from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import path from "node:path";
import { buildWhere, FACET_SAMPLE, INDEXES, PAGE_SIZE, search } from "../src/lib/search";

const where = (q: string, index: "events" | "alerts" = "events") => buildWhere({ index, q, range: "24h", page: 1 });
const MIGRATION = readFileSync(path.resolve(__dirname, "../../clickhouse/migrations/0030_search_text_index.sql"), "utf8");

test("выражение индекса в коде совпадает с миграцией 0030 символ в символ — иначе ClickHouse его не применит", () => {
  const ev = /ALTER TABLE argus\.events ADD INDEX IF NOT EXISTS idx_text (.+) TYPE ngrambf_v1/.exec(MIGRATION);
  const al = /ALTER TABLE argus\.wazuh_alerts ADD INDEX IF NOT EXISTS idx_text (.+) TYPE ngrambf_v1/.exec(MIGRATION);
  assert.equal(ev?.[1], INDEXES.events.text.index);
  assert.equal(al?.[1], INDEXES.alerts.text.index);
  // Строковые константы в выражении ломают сопоставление в новом анализаторе 24.8.
  assert.doesNotMatch(INDEXES.events.text.index, /'/);
  assert.doesNotMatch(INDEXES.alerts.text.index, /'/);
});

test("слово без пробелов: подстрока по каждому полю через OR, затем предфильтр по индексу", () => {
  const b = where("Kubectl");
  assert.equal(b.error, null);
  const fields = INDEXES.events.text.fields;
  for (const f of fields) assert.ok(b.where.includes(`positionCaseInsensitiveUTF8(${f}, {p0:String}) > 0`), f);
  assert.ok(b.where.includes(`${INDEXES.events.text.index} LIKE concat('%', lowerUTF8({p1:String}), '%')`));
  assert.equal(b.params.p0, "Kubectl");
  assert.equal(b.params.p1, "Kubectl");
  // Сначала точная проверка, потом индексное выражение: короткое замыкание AND.
  assert.ok(b.where.indexOf("positionCaseInsensitiveUTF8") < b.where.indexOf(" LIKE concat"));
  // Склейки строки на каждую запись для одного слова больше нет.
  assert.doesNotMatch(b.where, /concat\(raw, ' '/);
});

test("фраза с пробелом: точная проверка по склейке полей через пробел, предфильтр — по каждому куску", () => {
  const b = where('"Failed password for"');
  assert.match(b.where, /positionCaseInsensitiveUTF8\(concat\(raw, ' ', actor_name, ' ', object, ' ', node, ' ', src_ip, ' ', dst_ip, ' ', action, ' ', toString\(attrs\)\), \{p0:String\}\) > 0/);
  assert.equal(b.params.p0, "Failed password for");
  // «for» — 3 байта: индекс 4-грамм его не ускоряет, условие не добавляется.
  const likes = [...b.where.matchAll(/LIKE concat\('%', lowerUTF8\(\{(p\d+):String\}\), '%'\)/g)].map((m) => b.params[m[1]]);
  assert.deepEqual(likes, ["Failed", "password"]);
});

test("короткое слово (< 4 байт) — без предфильтра; кириллица считается в байтах", () => {
  assert.doesNotMatch(where("su").where, /LIKE/);
  assert.doesNotMatch(where("abc").where, /LIKE/);
  assert.match(where("abcd").where, /LIKE/);
  assert.match(where("ёж").where, /LIKE/, "«ёж» — 4 байта UTF-8");
});

test("% и _ в слове экранируются для LIKE, точная проверка получает слово как есть", () => {
  const b = where("50%_off");
  assert.equal(b.params.p0, "50%_off");
  assert.equal(b.params.p1, "50\\%\\_off");
  const bs = where("dir\\temp");
  assert.equal(bs.params.p0, "dir\\temp");
  assert.equal(bs.params.p1, "dir\\\\temp");
});

test("отрицание: NOT от точной проверки, без предфильтра (он только сужает чтение)", () => {
  const b = where("-sshd");
  assert.match(b.where, /NOT \(\(positionCaseInsensitiveUTF8\(raw, \{p0:String\}\) > 0 OR /);
  assert.doesNotMatch(b.where, /LIKE/);
});

test("алерты: одно поле raw — фраза целиком и в точной проверке, и в предфильтре", () => {
  const b = where('"brute force"', "alerts");
  assert.ok(b.where.includes("positionCaseInsensitiveUTF8(raw, {p0:String}) > 0"));
  assert.ok(b.where.includes("lowerUTF8(raw) LIKE concat('%', lowerUTF8({p1:String}), '%')"));
  assert.equal(b.params.p1, "brute force");
});

test("поле + текст: условие поля не меняется, текст добавляется тем же способом", () => {
  const b = where("source:syslog.linux root");
  assert.match(b.where, /source = \{p0:String\}/);
  assert.match(b.where, /positionCaseInsensitiveUTF8\(raw, \{p1:String\}\) > 0/);
  assert.ok(b.where.includes(`${INDEXES.events.text.index} LIKE concat('%', lowerUTF8({p2:String}), '%')`));
});

/* ===== search(): страница, гистограмма, фасеты ===== */

type Reply = { status?: number; body: string; code?: number };
function mockClickHouse(handler: (sql: string) => Reply): string[] {
  const seen: string[] = [];
  globalThis.fetch = (async (_url: URL | string, init?: RequestInit) => {
    const sql = String(init?.body ?? "");
    seen.push(sql);
    const r = handler(sql);
    const headers = new Headers();
    if (r.code) headers.set("X-ClickHouse-Exception-Code", String(r.code));
    return new Response(r.body, { status: r.status ?? 200, headers });
  }) as typeof fetch;
  return seen;
}
const row = (i: number) => JSON.stringify({ time: `2026-10-30 10:00:${String(i % 60).padStart(2, "0")}`, severity: 3, source: "s", raw: "x" });
const rowsBody = (n: number) => Array.from({ length: n }, (_, i) => row(i)).join("\n");
const timeout = (): Reply => ({ status: 500, code: 159, body: "Code: 159. DB::Exception: Timeout exceeded: elapsed 15 seconds. (TIMEOUT_EXCEEDED)" });
const isRows = (sql: string) => /OFFSET \{offset:UInt32\}/.test(sql);
const isSeries = (sql: string) => sql.includes("toStartOfInterval");
const isFacets = (sql: string) => sql.includes("arrayJoin");

test("всё посчиталось: итог — сумма гистограммы, фасеты по выборке, total_exact", async () => {
  const seen = mockClickHouse((sql) => {
    if (isRows(sql)) return { body: rowsBody(PAGE_SIZE) };
    if (isSeries(sql)) return { body: [JSON.stringify({ bucket: "b1", low: "100", high: "20", critical: "3" }), JSON.stringify({ bucket: "b2", low: 7, high: 0, critical: 0 })].join("\n") };
    if (isFacets(sql)) return { body: [JSON.stringify({ field: "source", value: "s", count: "9", sample: "9" }), JSON.stringify({ field: "node", value: "n", count: "4", sample: "9" })].join("\n") };
    return { body: "" };
  });
  const r = await search({ index: "events", q: "kubectl", range: "24h", page: 1 });
  assert.equal(r.error, null);
  assert.equal(r.rows.length, PAGE_SIZE);
  assert.equal(r.total, 130);
  assert.equal(r.total_exact, true);
  assert.deepEqual(r.incomplete, []);
  assert.equal(r.notice, null);
  assert.equal(r.facets_sample, 9);
  assert.deepEqual(r.facets.find((f) => f.field === "source")?.values, [{ value: "s", count: 9 }]);
  // Фасеты — по последним совпадениям: ORDER BY ts DESC LIMIT {fsample}, а не по всему окну.
  const facetsSql = seen.find(isFacets) ?? "";
  assert.match(facetsSql, /ORDER BY ts DESC LIMIT \{fsample:UInt32\}/);
  assert.match(facetsSql, /count\(\) OVER \(\) AS sample_n/);
  assert.ok(FACET_SAMPLE >= 1000);
});

test("гистограмма не уложилась: страница есть, итог — нижняя граница, причина в notice", async () => {
  mockClickHouse((sql) => {
    if (isRows(sql)) return { body: rowsBody(PAGE_SIZE) };
    if (isSeries(sql)) return timeout();
    if (isFacets(sql)) return { body: JSON.stringify({ field: "source", value: "s", count: 1, sample: 1 }) };
    return { body: "" };
  });
  const r = await search({ index: "events", q: "sshd", range: "30d", page: 3 });
  assert.equal(r.error, null);
  assert.equal(r.rows.length, PAGE_SIZE);
  assert.equal(r.total_exact, false);
  assert.equal(r.total, 2 * PAGE_SIZE + PAGE_SIZE + 1, "страница полная — пейджер предлагает следующую");
  assert.deepEqual(r.series, []);
  assert.deepEqual(r.incomplete, ["series"]);
  assert.match(r.notice ?? "", /не уложились в 15 с/);
});

test("фасеты не уложились: отдельно от страницы и итога", async () => {
  mockClickHouse((sql) => {
    if (isRows(sql)) return { body: rowsBody(3) };
    if (isSeries(sql)) return { body: JSON.stringify({ bucket: "b", low: 3, high: 0, critical: 0 }) };
    if (isFacets(sql)) return timeout();
    return { body: "" };
  });
  const r = await search({ index: "events", q: "sshd", range: "24h", page: 1 });
  assert.equal(r.total, 3);
  assert.equal(r.total_exact, true);
  assert.deepEqual(r.facets, []);
  assert.equal(r.facets_sample, null);
  assert.deepEqual(r.incomplete, ["facets"]);
  assert.match(r.notice ?? "", /поля не посчитаны: не уложились в 10 с/);
});

test("страница не получена — ошибка ответа (как раньше), части не важны", async () => {
  mockClickHouse((sql) => (isRows(sql) ? timeout() : { body: "" }));
  const r = await search({ index: "events", q: "sshd", range: "24h", page: 1 });
  assert.match(r.error ?? "", /не уложился в 20 с/);
  assert.deepEqual(r.rows, []);
});

test("сессия разбора: фасеты не запрашиваются вовсе", async () => {
  const seen = mockClickHouse((sql) => (isRows(sql) ? { body: rowsBody(1) } : { body: JSON.stringify({ bucket: "b", low: 1, high: 0, critical: 0 }) }));
  const r = await search({ index: "events", q: "x", range: "24h", page: 1, facets: false, bind: { actors: ["a"], nodes: [] } });
  assert.equal(seen.filter(isFacets).length, 0);
  assert.equal(r.facets_sample, null);
  assert.deepEqual(r.incomplete, []);
});

test("ошибка разбора запроса — без обращения к хранилищу", async () => {
  const seen = mockClickHouse(() => ({ body: "" }));
  const r = await search({ index: "events", q: "nosuchfield:x", range: "24h", page: 1 });
  assert.match(r.error ?? "", /неизвестное поле/);
  assert.equal(seen.length, 0);
  assert.equal(r.total_exact, true);
});
