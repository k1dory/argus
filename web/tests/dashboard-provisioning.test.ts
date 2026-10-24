import { test } from "node:test";
import assert from "node:assert/strict";
import { promises as fs } from "fs";
import path from "path";
import { getDashboard, listDashboards, normalizeSpec, provisionableFiles, scanSql, validateSql } from "../src/lib/dashboards";

// Тесты идут из web/, консоль по умолчанию читает ../dashboards — тот же каталог.
const DIR = path.resolve("../dashboards");

async function provisionedFiles(): Promise<{ file: string; id: string; raw: unknown }[]> {
  const files = (await fs.readdir(DIR)).filter((f) => f.endsWith(".json")).sort();
  return Promise.all(files.map(async (file) => {
    const raw = JSON.parse(await fs.readFile(path.join(DIR, file), "utf8")) as { id: string };
    return { file, id: raw.id, raw };
  }));
}

test("validateSql: «;» внутри строк и комментариев не делает запрос составным", () => {
  assert.equal(validateSql("SELECT arrayStringConcat(v, '; ') AS s FROM t"), null);
  assert.equal(validateSql(`SELECT 1 AS "a;b", 2 AS \`c;d\``), null);
  assert.equal(validateSql("SELECT 'it''s; ok', 'esc\\'; still string' FROM t"), null);
  assert.equal(validateSql("SELECT 1 -- комментарий; тоже\nFROM t"), null);
  assert.equal(validateSql("SELECT 1 /* ; */ FROM t"), null);
  assert.match(validateSql("SELECT 1; SELECT 2") ?? "", /«;»/);
  assert.match(validateSql("SELECT '; '; SELECT 2") ?? "", /«;»/);
  assert.match(validateSql("SELECT 'a\\\\'; SELECT 2") ?? "", /«;»/, "\\\\ закрывает экранирование, кавычка — конец строки");
  // Запрещённое слово ищется по исходному тексту, даже если оно в строке.
  assert.ok(validateSql("SELECT 'x' FROM url('http://x', CSV)"));
  assert.deepEqual(scanSql("a 'b;c' /* x */d"), { ok: true, code: "a    d", noComments: "a 'b;c'  d" });
  assert.equal(validateSql("SELECT 1 # комментарий; тоже\nFROM t"), null);
  assert.equal(validateSql("SELECT 1 #! комментарий; тоже\nFROM t"), null);
  assert.equal(validateSql("SELECT count() FROM t WHERE $__timeFilter(ts) AND ts > $__from"), null, "макросы — не heredoc");
});

test("validateSql: чего разбор не понимает наверняка — отказ, а не пропуск", () => {
  // Каждый запрос ниже — два оператора, если «;» не в литерале: разбор обязан отказать.
  const unsupported: [string, RegExp][] = [
    ["SELECT 1 #x; SELECT 2", /«#»/],
    ["SELECT $$; $$ AS s", /heredoc/],
    ["SELECT $t$; $t$ AS s", /heredoc/],
    ["SELECT $$ ' $$; SELECT 2 -- '", /heredoc/],
    ["SELECT \u2018; \u2019 AS s", /типографские/],
    ["SELECT \u201C; \u201D AS s", /типографские/],
  ];
  for (const [sql, re] of unsupported) assert.match(validateSql(sql) ?? "", re, sql);
  // Комментарий # с пробелом или ! — как --: «;» за ним настоящая только на следующей строке.
  assert.match(validateSql("SELECT 1 # x\n; SELECT 2") ?? "", /«;»/);
  assert.match(validateSql("SELECT 1 #! x\n; SELECT 2") ?? "", /«;»/);
  // Вложенный комментарий: «*/» первой глубины не закрывает внешний, «'» внутри — не строка.
  assert.equal(validateSql("SELECT 1 /* a /* b */ c ; */ FROM t"), null, "вложенный закрыт — «;» внутри комментария");
  assert.equal(validateSql("SELECT 1 /* /* */ ' */ ; SELECT 2 -- '"), "Один запрос без «;»");
  assert.equal(validateSql("SELECT 1 /* /* */ ; SELECT 2"), "Незакрытая кавычка или комментарий");
  for (const sql of ["SELECT 'abc; SELECT 2", "SELECT `a; SELECT 2", "SELECT 1 /* ; SELECT 2", "SELECT 'a\\"]) {
    assert.equal(validateSql(sql), "Незакрытая кавычка или комментарий", sql);
  }
});

test("validateSql: FORBIDDEN не обходится комментарием или кавычками", () => {
  for (const sql of [
    "SELECT * FROM url/**/('http://x', CSV)",
    "SELECT * FROM url -- x\n('http://x', CSV)",
    "SELECT * FROM `url`('http://x', CSV)",
    "SELECT * FROM `system`.tables",
    'SELECT * FROM "system".tables',
    "SELECT * FROM system .tables",
    "SELECT * FROM system/**/.tables",
  ]) assert.equal(validateSql(sql), "Запрос содержит запрещённое ключевое слово", sql);
  assert.equal(validateSql("SELECT `system` AS sys, file_name FROM t"), null, "system как имя столбца, file_name — можно");
});

test("каждый дашборд из dashboards/ проходит проверку при провижининге", async () => {
  const files = await provisionedFiles();
  assert.ok(files.length > 0, "каталог dashboards/ пуст");
  const ids = new Set<string>();
  for (const { file, id, raw } of files) {
    assert.match(id, /^[a-z0-9][a-z0-9-]{1,63}$/, `${file}: id`);
    assert.ok(!ids.has(id), `${file}: id ${id} повторяется`);
    ids.add(id);
    const spec = normalizeSpec(raw);
    assert.ok(spec.panels.length > 0, `${file}: нет панелей`);
    for (const p of spec.panels) assert.equal(validateSql(p.sql), null, `${file}, панель ${p.id}`);
  }
});

test("дашборды wazuh-* провижинятся только с модулем Wazuh", () => {
  const files = ["argus-siem.json", "waf.json", "wazuh-fim.json", "wazuh-sca.json", "readme.md"];
  assert.deepEqual(provisionableFiles(files, true), ["argus-siem.json", "waf.json", "wazuh-fim.json", "wazuh-sca.json"]);
  assert.deepEqual(provisionableFiles(files, false), ["argus-siem.json", "waf.json"]);
  const prev = process.env.ARGUS_INTEGRATION_WAZUH;
  try {
    delete process.env.ARGUS_INTEGRATION_WAZUH;
    assert.deepEqual(provisionableFiles(["wazuh-fim.json", "waf.json"]), ["waf.json"], "по умолчанию модуль выключен");
    process.env.ARGUS_INTEGRATION_WAZUH = "true";
    assert.deepEqual(provisionableFiles(["wazuh-fim.json", "waf.json"]), ["wazuh-fim.json", "waf.json"]);
  } finally {
    if (prev === undefined) delete process.env.ARGUS_INTEGRATION_WAZUH;
    else process.env.ARGUS_INTEGRATION_WAZUH = prev;
  }
});

test("провижининг (модуль Wazuh включён) создаёт запись для каждого файла, и каждый дашборд открывается", async (t) => {
  process.env.ARGUS_INTEGRATION_WAZUH = "1";
  t.after(() => delete process.env.ARGUS_INTEGRATION_WAZUH);
  // ClickHouse в памяти: INSERT кладёт строку, SELECT по LATEST отдаёт последнюю.
  const store = new Map<string, { id: string; title: string; spec: string; provisioned: number; deleted: number }>();
  t.mock.method(globalThis, "fetch", async (input: URL | string, init?: RequestInit) => {
    const url = new URL(String(input));
    const sql = String(init?.body ?? "");
    const p = (k: string) => url.searchParams.get(`param_${k}`) ?? "";
    const row = (r: { id: string; title: string; spec: string; provisioned: number; deleted: number }) =>
      JSON.stringify({ ...r, updated_by: "provisioning", updated_max: "2026-01-01 00:00:00" });
    if (sql.startsWith("INSERT INTO console_dashboards")) {
      store.set(p("id"), { id: p("id"), title: p("title"), spec: p("spec"), provisioned: Number(p("prov")), deleted: 0 });
      return new Response("");
    }
    if (sql.includes("FROM console_dashboards") && sql.includes("WHERE id = {id:String}")) {
      const r = store.get(p("id"));
      return new Response(r ? row(r) + "\n" : "");
    }
    if (sql.includes("FROM console_dashboards")) return new Response([...store.values()].map(row).join("\n"));
    return new Response("unexpected query", { status: 500 });
  });

  const files = await provisionedFiles();
  const listed = await listDashboards();
  assert.deepEqual(listed.map((d) => d.id).sort(), files.map((f) => f.id).sort(), "каждый файл стал записью");
  for (const { id } of files) {
    assert.equal(store.get(id)?.provisioned, 1, `${id}: provisioned`);
    const spec = await getDashboard(id);
    assert.ok(spec, `/dashboards/${id} — 404`);
    assert.equal(spec.id, id);
  }
});
