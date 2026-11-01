// Контракт SQL панели: в ClickHouse уходит `SELECT * FROM (<запрос>) FORMAT JSONEachRow`.
// Выходной FORMAT, INTO OUTFILE внутри подзапроса ClickHouse отклоняет синтаксической
// ошибкой — текст запроса на FORMAT не разбирается (прежний текстовый запрет обходился
// кавычками, «AS format FORMAT Null», «//» и давал ложные отказы на format/CASE).
// Сценарии — из ревью codex #27/#38. Живой блок проверяет сам ClickHouse 24.8.
import { test } from "node:test";
import assert from "node:assert/strict";
import { liveSkip as skip, liveUrl } from "./_ch-live";

process.env.CLICKHOUSE_URL = "http://127.0.0.1:9/";
process.env.CLICKHOUSE_RO_USER = "fixture-ro";
process.env.CLICKHOUSE_RO_PASSWORD = "fixture-password";

const OUTPUT_FORMAT = [
  "SELECT 7 AS n FORMAT JSONCompactEachRow",
  "SELECT 7 AS n fOrMaT/**/TabSeparated",
  "SELECT 7 /* outer /* inner */ outer */ FORMAT JSONEachRow",
  "SELECT 7 AS n -- comment\nFORMAT JSONEachRow",
  "SELECT 7 AS n // '\nFORMAT JSONCompactEachRow -- '",
  "SELECT 7 AS format FORMAT Null",
  "SELECT 7 AS format /* alias */ fOrMaT/**/Null",
  'SELECT 7 FORMAT "Null"',
  "SELECT 7 FORMAT `Null`",
  'SELECT \'{"n":7}\' AS payload FORMAT "TabSeparatedRaw"',
  "SELECT 7 AS n INTO OUTFILE '/tmp/panel'",
];
const VALID: [string, Record<string, unknown>[]][] = [
  ["SELECT format('{} {}', 'Hello', 'World') AS message", [{ message: "Hello World" }]],
  ["SELECT format /* fn */ ('{}', 'ok') AS message", [{ message: "ok" }]],
  ["SELECT 1 AS format", [{ format: 1 }]],
  ["SELECT format FROM (SELECT 1 AS format)", [{ format: 1 }]],
  ["SELECT format value FROM (SELECT 7 AS format)", [{ value: 7 }]],
  ["SELECT CASE WHEN format THEN 1 ELSE 0 END AS n FROM (SELECT 1 AS format)", [{ n: 1 }]],
  ["SELECT CASE format WHEN 7 THEN 1 ELSE 0 END AS n FROM (SELECT 7 AS format)", [{ n: 1 }]],
  ["SELECT format GLOBAL IN (7, 8) AS n FROM (SELECT 7 AS format)", [{ n: 1 }]],
  ["SELECT 'FORMAT TabSeparated' AS message /* FORMAT CSV */", [{ message: "FORMAT TabSeparated" }]],
  ["WITH t AS (SELECT 1 AS n) SELECT n FROM t", [{ n: 1 }]],
  ["SELECT 1 AS n UNION ALL SELECT 2", [{ n: 1 }, { n: 2 }]],
  ["SELECT 1 AS n -- trailing comment", [{ n: 1 }]],
];

const dashboards = () => import("../src/lib/dashboards");

test("validateSql не разбирает FORMAT: решает ClickHouse", async () => {
  const { validateSql } = await dashboards();
  for (const sql of [...OUTPUT_FORMAT.filter((s) => !s.includes("INTO OUTFILE")), ...VALID.map(([s]) => s)]) {
    assert.equal(validateSql(sql), null, sql);
  }
});

test("panelQuery: запрос панели — подзапрос, формат — JSONEachRow от консоли", async () => {
  const { panelQuery } = await dashboards();
  assert.equal(panelQuery("SELECT 1 AS n -- c", "24h"), "SELECT * FROM (\nSELECT 1 AS n -- c\n) FORMAT JSONEachRow");
});

for (const sql of OUTPUT_FORMAT.slice(0, 3)) {
  test(`панель: синтаксическая ошибка ClickHouse — ошибка, без строк и без кэша — ${sql.split("\n")[0]}`, async (t) => {
    const { panelCacheGet, panelQuery, runPanelQuery } = await dashboards();
    const sent: unknown[] = [];
    t.mock.method(console, "error", () => undefined);
    t.mock.method(globalThis, "fetch", async (_input: unknown, init?: RequestInit) => {
      sent.push(init?.body);
      // Так отвечает 24.8 на FORMAT внутри подзапроса (живой блок ниже).
      return new Response("Code: 62. DB::Exception: Syntax error: failed at position 31 ('FORMAT'). (SYNTAX_ERROR)\n", {
        status: 400, headers: { "X-ClickHouse-Exception-Code": "62" },
      });
    });
    const ttlMs = 60_000;
    const result = await runPanelQuery(sql, "24h", ttlMs);
    assert.deepEqual(sent, [panelQuery(sql, "24h")]);
    assert.equal(result.error, "код 62 (SYNTAX_ERROR)");
    assert.deepEqual(result.rows, []);
    assert.equal(panelCacheGet(`24h\0${sql}`, ttlMs), null);
  });
}

test("живой ClickHouse 24.8: FORMAT/INTO OUTFILE в подзапросе — 62, корректные запросы — строки", { skip }, async () => {
  const { panelQuery } = await dashboards();
  const url = new URL(liveUrl!);
  url.searchParams.set("default_format", "JSONEachRow");
  url.searchParams.set("wait_end_of_query", "1");
  url.searchParams.set("output_format_json_quote_64bit_integers", "0");
  const auth = "Basic " + Buffer.from(`${process.env.ARGUS_TEST_CLICKHOUSE_USER ?? "default"}:${process.env.ARGUS_TEST_CLICKHOUSE_PASSWORD ?? ""}`).toString("base64");
  const run = async (sql: string) => {
    const r = await fetch(url, { method: "POST", body: panelQuery(sql, "24h"), headers: { Authorization: auth } });
    return { status: r.status, code: r.headers.get("X-ClickHouse-Exception-Code"), text: await r.text() };
  };
  for (const sql of OUTPUT_FORMAT) {
    const r = await run(sql);
    assert.deepEqual({ status: r.status, code: r.code }, { status: 400, code: "62" }, sql);
  }
  for (const [sql, rows] of VALID) {
    const r = await run(sql);
    assert.equal(r.status, 200, `${sql}: ${r.code}`);
    // Порядок строк UNION ALL в ClickHouse не гарантирован — сравнение как множеств.
    const norm = (xs: unknown[]) => xs.map((x) => JSON.stringify(x)).sort();
    assert.deepEqual(norm(r.text.trim().split("\n").map((l) => JSON.parse(l))), norm(rows), sql);
  }
});
