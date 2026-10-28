import { test } from "node:test";
import assert from "node:assert/strict";
import { describeThreshold, formatDuration, formatRhythm, isAlive, rhythmFromGaps, RHYTHM_WINDOW_DAYS, SILENCE_FACTOR, SILENCE_MIN_SEC, silenceThresholdSec } from "../src/lib/shared/source-health";

const DAY = 86400;

test("ритм — квантиль разрывов: пачечный суточный источник не становится «раз в 4 часа», одиночный сбой не ломает непрерывный", () => {
  assert.equal(rhythmFromGaps([]), null, "одна активная минута — разрывов нет");
  assert.equal(rhythmFromGaps([60, 60, 60]), 60, "каждую минуту");
  // CI пишет 5 минут раз в сутки неделю: 28 разрывов по минуте и 6 суточных.
  const ci = [...Array(28).fill(60), ...Array(6).fill(DAY - 240)];
  assert.ok(rhythmFromGaps(ci)! > 20 * 3600, `суточный CI → ~сутки, а не среднее: ${rhythmFromGaps(ci)}`);
  // Непрерывный источник с одним двухдневным провалом: квантиль не видит провал.
  const outage = [...Array(5000).fill(60), 2 * DAY];
  assert.equal(rhythmFromGaps(outage), 60);
  // Недельная выгрузка за 30 суток: три разрыва по неделе.
  assert.equal(rhythmFromGaps([7 * DAY, 7 * DAY, 7 * DAY]), 7 * DAY);
  assert.equal(rhythmFromGaps([0, -5, NaN, 120]), 120, "мусор отбрасывается");
  assert.equal(rhythmFromGaps([30]), 60, "меньше минуты не бывает — гранулярность heartbeat");
});

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
