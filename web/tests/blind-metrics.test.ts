// Метрики слепой выборки без ClickHouse: интервал Уилсона, окно, сборка строк SQL
// по правилам (слепые и неслепые раздельно, кандидаты на тюнинг сверху).
import { test } from "node:test";
import assert from "node:assert/strict";
import { LOW_DATA_N, VERDICT_DISPOSITION, assembleAgreement, parseAgreementWindow, share, wilson, type AgreementSqlRow } from "../src/lib/shared/blind-metrics";
import { DISPOSITIONS } from "../src/lib/shared/closure-label";

const close = (a: number, b: number) => assert.ok(Math.abs(a - b) < 5e-4, `${a} ≈ ${b}`);

test("wilson: известные значения 95 % и края", () => {
  const half = wilson(5, 10)!;
  close(half.low, 0.2366); close(half.high, 0.7634);
  const zero = wilson(0, 10)!;
  assert.equal(zero.low, 0); close(zero.high, 0.2775);
  const all = wilson(20, 20)!;
  close(all.low, 0.8389); assert.equal(all.high, 1);
  assert.equal(wilson(0, 0), null, "n = 0 — интервала нет");
  assert.equal(wilson(3, 2), null, "k > n — не доля");
});

test("share: доля, интервал и «мало данных» при n < 20", () => {
  assert.deepEqual(share(0, 0), { k: 0, n: 0, share: null, ci: null, low_data: true });
  assert.equal(share(1, LOW_DATA_N - 1).low_data, true);
  assert.equal(share(1, LOW_DATA_N).low_data, false);
});

test("окно: 7d и 30d, по умолчанию 30d, прочее отклоняется", () => {
  assert.equal(parseAgreementWindow(undefined), "30d");
  assert.equal(parseAgreementWindow(""), "30d");
  assert.equal(parseAgreementWindow("7d"), "7d");
  for (const bad of ["24h", "90d", "toString", "__proto__"]) assert.equal(parseAgreementWindow(bad), null, bad);
});

test("сопоставление вердиктов агента — только в существующие ответы человека", () => {
  for (const d of Object.values(VERDICT_DISPOSITION)) assert.ok(Object.hasOwn(DISPOSITIONS, d), d);
  assert.ok(!Object.hasOwn(VERDICT_DISPOSITION, "undetermined"), "undetermined не сравнивается");
});

test("assembleAgreement: слепые и неслепые раздельно, итог, порядок по доле ложных", () => {
  const row = (rule_id: string, blind: boolean, labeled: number, fp: number, compared: number, agreed: number, extra: Partial<AgreementSqlRow> = {}): AgreementSqlRow =>
    ({ rule_id, rule_title: `T ${rule_id}`, blind, labeled: String(labeled), fp: String(fp), compared, agreed, undetermined: 0, no_verdict: 0, ...extra });
  const { rules, total } = assembleAgreement([
    row("quiet", false, 30, 3, 30, 27),
    row("noisy", true, 10, 9, 10, 8), row("noisy", false, 20, 15, 18, 17, { undetermined: 2 }),
    row("rare", true, 2, 2, 2, 1),
  ]);
  assert.deepEqual(rules.map((r) => r.rule_id), ["noisy", "quiet", "rare"], "мало данных — после правил с достаточным n");
  const noisy = rules[0];
  assert.equal(noisy.labeled, 30);
  assert.deepEqual([noisy.false_positive.k, noisy.false_positive.n], [24, 30]);
  assert.deepEqual([noisy.blind.labeled, noisy.blind.agreement.k, noisy.blind.agreement.n], [10, 8, 10]);
  assert.deepEqual([noisy.sighted.labeled, noisy.sighted.agreement.k, noisy.sighted.agreement.n, noisy.sighted.undetermined], [20, 17, 18, 2]);
  assert.equal(noisy.blind.agreement.low_data, true);
  assert.equal(rules[2].false_positive.low_data, true);
  assert.deepEqual([total.labeled, total.false_positive.k, total.blind.agreement.k, total.blind.agreement.n, total.sighted.agreement.n], [62, 29, 9, 12, 48]);
  assert.equal(total.rule_id, "");
});
