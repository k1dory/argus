// Одна персона тоже может превысить оба транспортных бюджета: разбиение только
// между персонами оставляет её длинный SQL в слишком большом поле query.
import { test } from "node:test";
import assert from "node:assert/strict";
import { PR74_NOW, fixtureAlias, type ActivityFixture } from "./_actors-pr74-fixtures";
import { captureActorReads, invalidEnvelopes } from "./_actors-pr74-http-budget";

process.env.CLICKHOUSE_URL = "http://127.0.0.1:9";
process.env.CLICKHOUSE_DB = "argus";
process.env.CLICKHOUSE_USER = "pr74-fixture";
process.env.CLICKHOUSE_PASSWORD = "";

test("PR #74: одна персона с 1000 Unicode uid не обходит лимит партии инцидентов", async (t) => {
  const fixture: ActivityFixture = [{ id: "many-uids", aliases: Array.from({ length: 1000 }, (_, i) =>
    fixtureAlias("many-uids", "uid", "漢".repeat(252) + String(i).padStart(4, "0"))) }];
  const { requests } = captureActorReads(t, fixture);
  const { listPersons } = await import("../src/lib/actors");
  const list = await listPersons("7d", PR74_NOW);
  assert.equal(list.length, 1);
  assert.equal(list[0].aliases, 1000, "нельзя исправить транспорт потерей алиасов");
  const incidents = requests.filter((r) => /\bFROM incidents_current\b/.test(r.sql));
  assert.ok(incidents.length > 0, "подсчёт инцидентов обязателен");
  assert.deepEqual(invalidEnvelopes(requests), [],
    "SQL одной персоны >128 КиБ, параметры >960 КиБ: поле query нельзя отправлять целиком");
  assert.ok(incidents.every((r) => Buffer.byteLength(r.sql, "utf8") <= 64 * 1024),
    "64 КиБ — предел всей партии, включая случай одной персоны");
});
