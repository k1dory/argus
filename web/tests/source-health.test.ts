import { test } from "node:test";
import assert from "node:assert/strict";
import { describeThreshold, formatDuration, formatRhythm, isAlive, RHYTHM_WINDOW_DAYS, SILENCE_FACTOR, SILENCE_MIN_SEC, silenceThresholdSec } from "../src/lib/shared/source-health";

const DAY = 86400;

// Сам ритм считает SQL sourcesHealthReport — его проверяет sources-rhythm-ch.test.ts на живом ClickHouse.

test("порог тишины: три ритма, не меньше 5 минут; без ритма — минимум", () => {
  assert.equal(silenceThresholdSec(null), SILENCE_MIN_SEC);
  assert.equal(silenceThresholdSec(60), SILENCE_MIN_SEC, "непрерывный → 5 мин");
  assert.equal(silenceThresholdSec(3600), SILENCE_FACTOR * 3600, "раз в час → 3 часа");
  assert.equal(silenceThresholdSec(DAY), 3 * DAY, "суточный → трое суток");
  assert.ok(RHYTHM_WINDOW_DAYS >= 28, "окно вмещает несколько недельных разрывов");
});

test("жив/молчит: по порогу источника", () => {
  const now = 100_000;
  const sshd = silenceThresholdSec(7200); // раз в 2 ч → 6 ч
  assert.ok(isAlive(now, now - 2400, sshd));
  assert.ok(!isAlive(now, now - 7 * 3600, sshd));
  const nf = silenceThresholdSec(60);
  assert.ok(!isAlive(now, now - 360, nf));
  assert.ok(isAlive(now, now - 299, nf));
});

test("подписи: ритм, длительности, подсказка из констант", () => {
  assert.equal(formatRhythm(null), "мало данных");
  assert.equal(formatRhythm(60), "непрерывно");
  assert.equal(formatRhythm(240), "раз в 4 мин");
  assert.match(formatRhythm(9000), /^раз в 2,5 ч$/);
  assert.match(formatRhythm(2 * DAY), /^раз в 2 сут$/);
  assert.equal(formatDuration(20), "20 с", "меньше минуты — секунды, а не «0 мин»");
  assert.equal(formatDuration(300), "5 мин");
  assert.match(formatDuration(1.5 * DAY), /^1,5 сут$/);
  const hint = describeThreshold(3 * 3600, 20);
  assert.match(hint, /3 ч/); assert.match(hint, new RegExp(`${SILENCE_FACTOR} × ритм`)); assert.match(hint, /5 мин/); assert.match(hint, /20 с/);
});
