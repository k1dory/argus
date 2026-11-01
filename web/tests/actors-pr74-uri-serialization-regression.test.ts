// encodeURIComponent оставляет ~ как есть, URLSearchParams отправляет %7E.
// После увеличения бюджета URL до 960 КиБ эта разница уже превышает запас 64 КиБ.
import { test } from "node:test";
import assert from "node:assert/strict";
import { PR74_NOW, fixtureAlias, type ActivityFixture } from "./_actors-pr74-fixtures";
import { captureActorReads, HTTP_URI_MAX_BYTES, invalidEnvelopes } from "./_actors-pr74-http-budget";

process.env.CLICKHOUSE_URL = "http://127.0.0.1:9";
process.env.CLICKHOUSE_DB = "argus";
process.env.CLICKHOUSE_USER = "pr74-fixture";
process.env.CLICKHOUSE_PASSWORD = "";

test("PR #74: бюджет URI учитывает фактическую сериализацию URLSearchParams", async (t) => {
  const id = "escaped-uids";
  // 750 допустимых uid длиной 256: SQL инцидентов помещается в поле 128 КиБ.
  // Оценка encodeURIComponent <960 КиБ, фактический URI с %7E >1 MiB.
  const fixture: ActivityFixture = [{ id, aliases: Array.from({ length: 750 }, (_, i) =>
    fixtureAlias(id, "uid", "漢".repeat(95) + "~".repeat(157) + String(i).padStart(4, "0"))) }];
  const { requests } = captureActorReads(t, fixture);
  const { listPersons } = await import("../src/lib/actors");
  const list = await listPersons("7d", PR74_NOW);
  assert.equal(list.length, 1);
  assert.equal(list[0].aliases, 750);
  const incidents = requests.filter((r) => /\bFROM incidents_current\b/.test(r.sql));
  assert.ok(incidents.length > 0, "подсчёт инцидентов обязателен");
  assert.ok(incidents.every((r) => r.uriBytes <= HTTP_URI_MAX_BYTES),
    `ClickHouse отклонит HTTP URI: ${incidents.map((r) => r.uriBytes).join(", ")} байт`);
  assert.deepEqual(invalidEnvelopes(requests), [], "смена транспорта должна учитывать оба ограничения");
});
