// Проверки размеров без сети: реальные activityPlan/aliasPrefilter должны
// подготовить поля, которые принимает HTTP-парсер ClickHouse 24.8.
// Это предел протокола, а не повтор константы ARRAY_PARAM_CHUNK из продукта.
import { test } from "node:test";
import assert from "node:assert/strict";
import { activityPlan, aliasPrefilter, parseIdentitiesDoc } from "../src/lib/shared/actors";
import { FORM_VALUE_MAX_BYTES, PR74_WINDOW, importDocument, largeClassFixture, unicodeFixture } from "./_actors-pr74-fixtures";

function oversized(params: Record<string, string | number>) {
  return Object.entries(params).map(([name, value]) => ({ name, bytes: Buffer.byteLength(String(value), "utf8") }))
    .filter(({ bytes }) => bytes > FORM_VALUE_MAX_BYTES);
}

test("PR #74: части массива Unicode укладываются в байтовый предел поля формы", () => {
  const fixture = unicodeFixture();
  assert.equal(parseIdentitiesDoc(importDocument(fixture)).ok, true, "240 uid по 256 символов — допустимый импорт");
  const aliases = fixture.flatMap((p) => p.aliases);
  const plan = activityPlan(fixture, PR74_WINDOW);
  const pf = aliasPrefilter(aliases);
  assert.equal(plan.owners.length, aliases.length, "нельзя исправить размер потерей классов");
  assert.notEqual(pf.sql, "0");
  assert.deepEqual(oversized({ ...plan.params, ...pf.params }), [],
    "UTF-16 length не ограничивает UTF-8: часть из 231 такого uid занимает 176254 байта");
});

test("PR #74: одна большая группа классов тоже укладывается в предел поля формы", () => {
  const fixture = largeClassFixture();
  assert.equal(parseIdentitiesDoc(importDocument(fixture)).ok, true, "по 1000 исторических IP-алиасов у 25 персон допустимы");
  const plan = activityPlan(fixture, PR74_WINDOW);
  assert.equal(plan.persons.length, 25);
  assert.equal(plan.owners.length, 25_000, "разные интервалы нельзя терять при делении");
  assert.deepEqual(oversized(plan.params), [],
    "разбиение только между элементами оставляет один вложенный массив размером 138897 байт");
});
