// Проверяется настоящий listPersons и настоящий HTTP-клиент. Подменён только
// fetch: семантика SQL здесь не эмулируется, измеряются реально отправленные поля.
import { test } from "node:test";
import assert from "node:assert/strict";
import { parseIdentitiesDoc } from "../src/lib/shared/actors";
import { FORM_VALUE_MAX_BYTES, PR74_NOW, importDocument, longIncidentQueryFixture } from "./_actors-pr74-fixtures";

process.env.CLICKHOUSE_URL = "http://127.0.0.1:9";
process.env.CLICKHOUSE_DB = "argus";
process.env.CLICKHOUSE_USER = "pr74-fixture";
process.env.CLICKHOUSE_PASSWORD = "";

test("PR #74: multipart не понижает допустимый размер SQL до 128 КиБ", async (t) => {
  const fixture = longIncidentQueryFixture();
  assert.equal(parseIdentitiesDoc(importDocument(fixture)).ok, true);
  const persons = fixture.map((p) => ({ person_id: p.id, display: p.id, kind: "person", team: "", note: "" }));
  const aliases = fixture.flatMap((p) => p.aliases.map((a) => ({ person_id: p.id,
    alias_kind: a.kind, alias_value: a.value, valid_from: a.valid_from, valid_to_raw: a.valid_to,
    source: a.source, confidence: a.confidence, note: a.note })));
  const oversized: { name: string; bytes: number }[] = [];
  let incidentQueries = 0;
  const rows = (data: object[]) => new Response(data.map((r) => JSON.stringify(r)).join("\n"));
  t.mock.method(globalThis, "fetch", async (input: URL | string | Request, init?: RequestInit) => {
    const url = new URL(input instanceof Request ? input.url : String(input));
    const headers = new Headers(init?.headers);
    let sql = String(init?.body ?? "");
    if (headers.get("content-type")?.startsWith("multipart/form-data")) {
      const form = await new Response(init?.body, { headers }).formData();
      const queryParts: string[] = [];
      for (const [name, value] of form) {
        assert.equal(typeof value, "string", "ожидается обычное поле, не внешняя таблица");
        const text = String(value), bytes = Buffer.byteLength(text, "utf8");
        if (bytes > FORM_VALUE_MAX_BYTES) oversized.push({ name, bytes });
        if (name === "query") queryParts.push(text);
      }
      sql = (url.searchParams.get("query") ?? "") + queryParts.join("");
    } else if (url.searchParams.has("query")) {
      sql = url.searchParams.get("query") + "\n" + sql;
    }
    assert.ok(Buffer.byteLength(url.pathname + url.search) <= 1024 * 1024, "URI также должен оставаться допустимым");
    if (/\bFROM identity_aliases\b/.test(sql)) return rows(aliases);
    if (/\bFROM identities\b/.test(sql)) return rows(persons);
    if (/\bFROM events\b/.test(sql)) return rows([]);
    if (/\bFROM incidents_current\b/.test(sql)) {
      incidentQueries++;
      return rows([Object.fromEntries([...sql.matchAll(/\bAS (i\d+)\b/g)].map((m) => [m[1], 0]))]);
    }
    assert.fail(`неожиданный запрос: ${sql.slice(0, 100)}`);
  });
  const { listPersons } = await import("../src/lib/actors");
  const list = await listPersons("7d", PR74_NOW);
  assert.equal(list.length, 100);
  assert.ok(incidentQueries > 0, "подсчёт инцидентов не должен исчезнуть");
  assert.ok(list.every((p) => p.aliases === 8 && p.events === 0 && p.incidents === 0));
  assert.deepEqual(oversized, [], "query — тоже поле HTMLForm и ограничено 128 КиБ");
});
