// Предел поля в URL применяется к percent-encoded строке. Часть массива на
// ~60 КБ UTF-8 может занять ~180 КБ в URI, даже если весь URI меньше 960 КиБ.
import { test } from "node:test";
import assert from "node:assert/strict";
import { PR74_NOW, fixtureAlias, type ActivityFixture } from "./_actors-pr74-fixtures";
import { captureActorReads, invalidEnvelopes } from "./_actors-pr74-http-budget";

process.env.CLICKHOUSE_URL = "http://127.0.0.1:9";
process.env.CLICKHOUSE_DB = "argus";
process.env.CLICKHOUSE_USER = "pr74-fixture";
process.env.CLICKHOUSE_PASSWORD = "";

test("PR #74: длинный SQL паспорта не переносит в URL слишком большое поле Array(String)", async (t) => {
  const id = "unicode-passport";
  // Много коротких алиасов делают SQL длиннее 120 КиБ, но короче 128 КиБ.
  // 80 длинных Unicode-значений заполняют хотя бы одну часть pf_in0_*.
  const fixture: ActivityFixture = [{ id, aliases: Array.from({ length: 820 }, (_, i) =>
    fixtureAlias(id, "uid", i < 80 ? "漢".repeat(252) + String(i).padStart(4, "0") : `uid-${i}`)) }];
  const { requests, persons } = captureActorReads(t, fixture);
  const { actorReport } = await import("../src/lib/actors");
  const report = await actorReport(persons[0], fixture[0].aliases, "7d", 1, { now: PR74_NOW });
  assert.equal(report.aliases.length, 820);
  assert.deepEqual(report.missing, []);
  assert.ok(requests.some((r) => /\bFROM events\b/.test(r.sql)), "данные паспорта должны запрашиваться");
  assert.deepEqual(invalidEnvelopes(requests), [],
    "HTMLForm проверяет размер percent-encoded поля до декодирования, а не только общий размер URI");
});
