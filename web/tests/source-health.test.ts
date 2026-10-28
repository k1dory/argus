import { test } from "node:test";
import assert from "node:assert/strict";
import { formatRhythm, isAlive, rhythmSec, SILENCE_MIN_SEC, silenceThresholdSec } from "../src/lib/shared/source-health";

test("ритм: секунд на активную минуту; одна активная минута — ритма нет; залп в одну минуту не делает источник непрерывным", () => {
  assert.equal(rhythmSec(1, 0), null);
  assert.equal(rhythmSec(1, 3600), null, "тысяча событий за одну минуту — всё равно одна активная минута");
  assert.equal(rhythmSec(2, 600), 300);
  assert.equal(rhythmSec(1440, 86400), 60, "событие каждую минуту");
  assert.equal(rhythmSec(5, -10), null);
});

test("порог тишины: непрерывный источник — 5 минут, редкий — три ритма; с первого события — минимум", () => {
  assert.equal(silenceThresholdSec(1, 0), SILENCE_MIN_SEC);
  assert.equal(silenceThresholdSec(1440, 86400), SILENCE_MIN_SEC, "каждую минуту → 5 мин");
  assert.equal(silenceThresholdSec(24, 86400), 3 * 3600, "раз в час → 3 часа");
  assert.equal(silenceThresholdSec(5, 7 * 86400), Math.round(3 * 7 * 86400 / 5), "пять минут за неделю → три ритма");
});

test("жив/молчит: по порогу источника, а не по общим 5 минутам", () => {
  const now = 100_000;
  // sshd: 12 активных минут за сутки → ритм 2 ч, порог 6 ч: тишина 40 минут — жив
  const sshd = silenceThresholdSec(12, 86400);
  assert.ok(isAlive(now, now - 2400, sshd));
  // netflow: каждая минута активна → порог 5 мин: тишина 6 минут — молчит
  const nf = silenceThresholdSec(1440, 86400);
  assert.ok(!isAlive(now, now - 360, nf));
  assert.ok(isAlive(now, now - 299, nf));
});

test("formatRhythm: единицы по величине интервала", () => {
  assert.equal(formatRhythm(null), "одно событие");
  assert.equal(formatRhythm(60), "непрерывно");
  assert.equal(formatRhythm(240), "раз в 4 мин");
  assert.match(formatRhythm(9000), /^раз в 2,5 ч$/);
  assert.match(formatRhythm(2 * 86400), /^раз в 2 сут$/);
});
