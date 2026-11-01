// PR #70: постоянный размер SQL не ограничивает размер HTTP URI. listPersons
// передаёт значения всех персон в параметрах одного запроса, а chFetch кладёт
// параметры в URL. Стандартный http_max_uri_size ClickHouse — 1 MiB:
// https://clickhouse.com/docs/interfaces/http
// Подменён только fetch: вызываются настоящий listPersons и HTTP-клиент.
// Сеть не используется, семантика SQL здесь не эмулируется.
import { test } from "node:test";
import assert from "node:assert/strict";
import { parseIdentitiesDoc } from "../src/lib/shared/actors";

process.env.CLICKHOUSE_URL = "http://127.0.0.1:9";
process.env.CLICKHOUSE_USER = "pr70-fixture";
process.env.CLICKHOUSE_PASSWORD = "";
process.env.CLICKHOUSE_DB = "argus";

const MAX_URI_BYTES = 1024 * 1024;
const NOW = Date.UTC(2026, 10, 1, 12);
const FROM = "2026-10-25 12:00:00.000";

function fixture(count: number) {
  const persons = Array.from({ length: count }, (_, i) => ({
    person_id: `person-${String(i).padStart(4, "0")}`,
    display: `Person ${String(i).padStart(4, "0")}`,
    kind: "person", team: "fixture", note: "",
  }));
  // Пять разных uid длиной 128 символов на человека: существенно ниже лимитов
  // 1000 алиасов / 256 символов. В старом listPersons в запрос попадали 100 персон.
  const aliases = persons.flatMap((person) => Array.from({ length: 5 }, (_, i) => ({
    person_id: person.person_id, alias_kind: "uid",
    alias_value: `${person.person_id}-${i}-`.padEnd(128, "x"),
    valid_from: FROM, valid_to_raw: null, source: "fixture", confidence: 1, note: "",
  })));
  return { persons, aliases };
}

for (const count of [100, 1000]) {
  test(`PR #70: listPersons с ${count} персонами помещается в HTTP URI ClickHouse`, async (t) => {
    const { persons, aliases } = fixture(count);
    const input = { persons: Object.fromEntries(persons.map((person) => [person.person_id, {
      display: person.display,
      aliases: aliases.filter((alias) => alias.person_id === person.person_id).map((alias) => ({
        kind: alias.alias_kind, value: alias.alias_value, from: "2026-10-25T12:00:00Z",
      })),
    }])) };
    assert.equal(parseIdentitiesDoc(input).ok, true, "фикстура допустима по контракту импорта");
    assert.ok(persons.length <= 5000 && aliases.length <= 100000, "фикстура не обрезается лимитами чтения");

    const eventRequests: Array<{ sql: string; uriBytes: number }> = [];
    const rows = (values: object[]) => new Response(values.map((value) => JSON.stringify(value)).join("\n"));
    t.mock.method(console, "error", () => undefined);
    t.mock.method(globalThis, "fetch", async (input: URL | string | Request, init?: RequestInit) => {
      const url = new URL(input instanceof Request ? input.url : String(input));
      const sql = String(init?.body ?? "");
      const uriBytes = Buffer.byteLength(url.pathname + url.search);
      if (/\bFROM events\b/.test(sql)) {
        eventRequests.push({ sql, uriBytes });
        t.diagnostic(`events: HTTP URI ${uriBytes} байт, предел ${MAX_URI_BYTES}`);
      }
      if (uriBytes > MAX_URI_BYTES) {
        return new Response("URI too large", { status: 414 });
      }
      if (/\bFROM identity_aliases\b/.test(sql)) return rows(aliases);
      if (/\bFROM identities\b/.test(sql)) return rows(persons);
      if (/\bFROM incidents_current\b/.test(sql)) {
        return rows([Object.fromEntries([...sql.matchAll(/\bAS (i\d+)\b/g)].map((match) => [match[1], 0]))]);
      }
      if (/\bFROM events\b/.test(sql)) return rows([]);
      assert.fail(`неожиданный запрос: ${sql.slice(0, 100)}`);
    });

    const { listPersons } = await import("../src/lib/actors");
    await assert.doesNotReject(async () => {
      const list = await listPersons("7d", NOW);
      assert.equal(list.length, count, "нельзя исправить размер запроса потерей персон");
      assert.ok(list.every((person) => person.events === 0 && person.last_ts === null && person.aliases === 5));
    }, "допустимый справочник должен читаться без HTTP 414");
    assert.equal(eventRequests.length, 1, "сохраняется один запрос активности на всех персон");
    assert.ok(eventRequests[0].uriBytes <= MAX_URI_BYTES);
  });
}
