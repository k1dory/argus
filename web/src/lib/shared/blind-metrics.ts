// Метрики слепой выборки: согласие человека с вердиктом агента по правилам и доля
// ложных срабатываний правила. Считаются только по завершённым инцидентам с ответом
// человека (labeled_by_human), поэтому вердикт по открытому слепому инциденту в
// агрегаты не попадает. Слепые и неслепые — отдельно: у неслепых человек видел
// подсказку агента до закрытия, и согласие с ней может быть завышено.

/** Окна метрик: по времени завершения инцидента. */
export const AGREEMENT_WINDOWS = { "7d": { days: 7, label: "7 дней" }, "30d": { days: 30, label: "30 дней" } } as const;
export type AgreementWindow = keyof typeof AGREEMENT_WINDOWS;

export function parseAgreementWindow(raw: string | null | undefined): AgreementWindow | null {
  if (raw === null || raw === undefined || raw === "") return "30d";
  return Object.hasOwn(AGREEMENT_WINDOWS, raw) ? (raw as AgreementWindow) : null;
}

/** Категория вердикта агента (argus-triage/v3) → ответ человека (миграция 0033).
 *  undetermined и неизвестные значения ни с чем не сравниваются. */
export const VERDICT_DISPOSITION = {
  true_positive: "malicious",
  benign_true_positive: "benign_authorized",
  false_positive: "false_positive",
} as const;

/** Меньше стольких наблюдений доля не показывается без пометки «мало данных». */
export const LOW_DATA_N = 20;

/** Доверительный интервал Уилсона, 95 % (z = 1,96). n = 0 — интервала нет. */
export function wilson(k: number, n: number, z = 1.959964): { low: number; high: number } | null {
  if (!(n > 0) || k < 0 || k > n) return null;
  const p = k / n, z2 = z * z;
  const denom = 1 + z2 / n;
  const center = (p + z2 / (2 * n)) / denom;
  const half = (z * Math.sqrt((p * (1 - p)) / n + z2 / (4 * n * n))) / denom;
  return { low: Math.max(0, center - half), high: Math.min(1, center + half) };
}

export type Share = { k: number; n: number; share: number | null; ci: { low: number; high: number } | null; low_data: boolean };

export function share(k: number, n: number): Share {
  return { k, n, share: n > 0 ? k / n : null, ci: wilson(k, n), low_data: n < LOW_DATA_N };
}

/** Строка SQL: правило × признак слепого разбора. */
export type AgreementSqlRow = {
  rule_id: string; rule_title: string; blind: boolean | number;
  labeled: number | string; fp: number | string;
  compared: number | string; agreed: number | string;
  undetermined: number | string; no_verdict: number | string;
};

export type AgreementSide = {
  /** Завершено с ответом человека. */
  labeled: number;
  /** Согласие: вердикт агента совпал с ответом человека, из сравнимых. */
  agreement: Share;
  /** Агент ответил undetermined — не сравнивается. */
  undetermined: number;
  /** Вердикта агента до завершения не было. */
  no_verdict: number;
};

export type AgreementRule = {
  rule_id: string; rule_title: string;
  labeled: number;
  /** Доля false_positive в ответах людей (слепые и неслепые вместе). */
  false_positive: Share;
  blind: AgreementSide;
  sighted: AgreementSide;
};

const num = (v: number | string) => Number(v) || 0;

function side(rows: AgreementSqlRow[]): AgreementSide {
  const sum = (f: keyof AgreementSqlRow) => rows.reduce((n, r) => n + num(r[f] as number | string), 0);
  return { labeled: sum("labeled"), agreement: share(sum("agreed"), sum("compared")), undetermined: sum("undetermined"), no_verdict: sum("no_verdict") };
}

const isBlind = (r: AgreementSqlRow) => r.blind === true || Number(r.blind) === 1;

/** Сводка по правилам и итог. Правила — по доле false_positive (кандидаты на
 *  тюнинг сверху), затем по числу ответов; «мало данных» — в конце своей доли. */
export function assembleAgreement(rows: AgreementSqlRow[]): { rules: AgreementRule[]; total: AgreementRule } {
  const byRule = new Map<string, AgreementSqlRow[]>();
  for (const r of rows) byRule.set(r.rule_id, [...(byRule.get(r.rule_id) ?? []), r]);
  const build = (rule_id: string, rule_title: string, list: AgreementSqlRow[]): AgreementRule => {
    const labeled = list.reduce((n, r) => n + num(r.labeled), 0);
    return {
      rule_id, rule_title, labeled,
      false_positive: share(list.reduce((n, r) => n + num(r.fp), 0), labeled),
      blind: side(list.filter(isBlind)),
      sighted: side(list.filter((r) => !isBlind(r))),
    };
  };
  const rules = [...byRule].map(([id, list]) => build(id, list.find((r) => r.rule_title)?.rule_title ?? "", list));
  rules.sort((a, b) => Number(a.false_positive.low_data) - Number(b.false_positive.low_data)
    || (b.false_positive.share ?? 0) - (a.false_positive.share ?? 0)
    || b.labeled - a.labeled || a.rule_id.localeCompare(b.rule_id));
  return { rules, total: build("", "Все правила", rows) };
}
