// Порядок «сначала шумные» на страницах правил:
// - «Правила корреляции»: доля ложных по убыванию, без инцидентов — в конце;
// - «Согласие с агентом»: по нижней границе 95 % интервала, малые выборки — отдельно
//   (1 ложное из 2 не должно обгонять 3 из 7 и тем более 15 из 30).
import { test } from "node:test";
import assert from "node:assert/strict";
import { isNoisy, sortByNoise } from "../src/lib/shared/rules-noise";
import { splitForTuning } from "../src/lib/shared/agreement-view";
import { share, type AgreementRule } from "../src/lib/shared/blind-metrics";

test("правила: сначала большая доля ложных, без инцидентов — в конце, подсветка с 5 инцидентов", () => {
  const stats = {
    a: { total: 4, false_positive: 1 },
    b: { total: 10, false_positive: 8 },
    c: { total: 2, false_positive: 2 },
  };
  const ids = sortByNoise(["z", "a", "b", "c"], (x) => x, stats);
  assert.deepEqual(ids, ["c", "b", "a", "z"]);
  assert.equal(isNoisy(stats.b), true);
  assert.equal(isNoisy(stats.c), false, "2 из 2 — мало инцидентов для подсветки");
});

const rule = (id: string, fp: number, n: number): AgreementRule => {
  const blank = { labeled: n, compared: 0, agreed: 0, undetermined: 0, no_verdict: 0, agreement: share(0, 0) };
  return { rule_id: id, rule_title: id, labeled: n, false_positive: share(fp, n), blind: blank, sighted: blank } as unknown as AgreementRule;
};

test("согласие: сортировка по нижней границе интервала, малые выборки — в отдельной группе", () => {
  const { enough, lowData } = splitForTuning([rule("one-of-two", 1, 2), rule("half-big", 15, 30), rule("fifth-big", 10, 50), rule("three-of-seven", 3, 7)]);
  assert.deepEqual(enough.map((r) => r.rule_id), ["half-big", "fifth-big"]);
  assert.deepEqual(lowData.map((r) => r.rule_id), ["three-of-seven", "one-of-two"], "3 из 7 выше 1 из 2: нижняя граница больше");
});
