// Страница «Источники» и «Обзор»: группы «Молчат / Работают», фраза статуса, склонение.
import test from "node:test";
import assert from "node:assert/strict";
import { flowText, parseSourceStatus, sourceStatusPhrase, splitByStatus } from "../src/lib/shared/source-status";
import { countOf, plural, SOURCES_FORMS } from "../src/lib/shared/plural";

const row = (alive: number, silent_for_sec: number, rhythm_sec: number | null = 30) => ({ alive, silent_for_sec, rhythm_sec, eps_60s: 0, events_1h: 0 });

test("молчащие — отдельной группой, дольше всех молчащий сверху", () => {
  const g = splitByStatus([row(1, 5), row(0, 60), row(0, 3600), row(1, 2)]);
  assert.deepEqual(g.silent.map((r) => r.silent_for_sec), [3600, 60]);
  assert.equal(g.alive.length, 2);
});

test("статус одной фразой: «Молчит 2 ч · обычно шлёт непрерывно»", () => {
  assert.deepEqual(sourceStatusPhrase(row(0, 7200)), { head: "Молчит 2 ч", rhythm: "обычно шлёт непрерывно" });
  assert.equal(sourceStatusPhrase(row(1, 1)).head, "Работает");
  assert.equal(sourceStatusPhrase(row(1, 1, null)).rhythm, "ритм ещё не известен");
});

test("вкладки статуса: неизвестное значение — «все»; поток при нуле — прочерк", () => {
  assert.equal(parseSourceStatus("silent"), "silent");
  assert.equal(parseSourceStatus("x"), "all");
  assert.equal(flowText(0), "—");
  assert.equal(flowText(1.25), "1,3 соб/с");
});

test("склонение: 1 источник, 3 источника, 11 источников, 77 источников", () => {
  assert.equal(countOf(1, SOURCES_FORMS), "1 источник");
  assert.equal(countOf(3, SOURCES_FORMS), "3 источника");
  assert.equal(plural(11, SOURCES_FORMS), "источников");
  assert.equal(plural(77, SOURCES_FORMS), "источников");
  assert.equal(plural(21, SOURCES_FORMS), "источник");
});
