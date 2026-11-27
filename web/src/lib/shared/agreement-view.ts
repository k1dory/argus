// Порядок таблицы «Согласие с агентом» на странице: кандидаты на тюнинг —
// по нижней границе 95 % интервала доли ложных, а не по сырой доле (1 из 2
// иначе выше 3 из 7). Правила с малой выборкой — отдельной группой.
// Порядок ответа API (assembleAgreement) не меняется.
import type { AgreementRule } from "./blind-metrics";

const low = (r: AgreementRule) => r.false_positive.ci?.low ?? 0;

/** Нижняя граница доли ложных по убыванию; при равенстве — больше ответов выше, затем по id. */
export function byFalsePositiveLowerBound(a: AgreementRule, b: AgreementRule): number {
  return low(b) - low(a) || b.labeled - a.labeled || a.rule_id.localeCompare(b.rule_id);
}

/** Делит правила на «достаточно данных» и «мало данных», каждую группу сортирует по нижней границе. */
export function splitForTuning(rules: readonly AgreementRule[]): { enough: AgreementRule[]; lowData: AgreementRule[] } {
  const enough = rules.filter((r) => !r.false_positive.low_data).sort(byFalsePositiveLowerBound);
  const lowData = rules.filter((r) => r.false_positive.low_data).sort(byFalsePositiveLowerBound);
  return { enough, lowData };
}
