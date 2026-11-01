// Метка ответа человека при завершении инцидента (миграция 0033). Набор значений
// общий с движком (engine/cmd/engine/labels.go): движок проверяет её ещё раз и
// сам решает, входит ли инцидент в слепую выборку.

export const DISPOSITIONS = {
  malicious: "вредоносная активность",
  benign_authorized: "легитимно, разрешено",
  false_positive: "ложное срабатывание",
} as const;
export type Disposition = keyof typeof DISPOSITIONS;

export const OPS_CAUSES = {
  real_failure: "реальная неисправность",
  planned_work: "плановые работы",
  monitoring_noise: "шум мониторинга",
  wrong_threshold: "неверный порог правила",
} as const;
export type OpsCause = keyof typeof OPS_CAUSES;

export const OPS_ACTIONS = {
  fixed: "устранено",
  no_action: "действий не требуется",
  rule_tuned: "правило поправлено",
  handed_over: "передано владельцу системы",
} as const;
export type OpsAction = keyof typeof OPS_ACTIONS;

export type ClosureLabel =
  | { disposition: Disposition; escalate: boolean; severity_correct: boolean }
  | { ops_cause: OpsCause; ops_action: OpsAction };

/** Эксплуатационное правило (теги ops.*): вместо вердикта ИБ — причина и действие. */
export function isOpsIncident(tags: readonly string[]): boolean {
  return tags.some((t) => t.startsWith("ops."));
}

const has = <T extends object>(dict: T, key: string): key is Extract<keyof T, string> => Object.hasOwn(dict, key);
const yesNo = (v: string): boolean | null => v === "yes" ? true : v === "no" ? false : null;

/** Метка из полей формы завершения; строка — ошибка для пользователя. */
export function parseClosureLabel(get: (name: string) => string, opts: { ops: boolean; status: string }): ClosureLabel | string {
  if (opts.ops) {
    const cause = get("ops_cause"), action = get("ops_action");
    if (!has(OPS_CAUSES, cause) || !has(OPS_ACTIONS, action)) return "Укажите причину и действие";
    return { ops_cause: cause, ops_action: action };
  }
  const disposition = get("disposition");
  const escalate = yesNo(get("escalate")), severity = yesNo(get("severity_correct"));
  if (!has(DISPOSITIONS, disposition) || escalate === null || severity === null) {
    return "Укажите характер срабатывания, нужна ли эскалация и верен ли уровень";
  }
  if ((opts.status === "false_positive") !== (disposition === "false_positive")) {
    return "Статус «ложное срабатывание» ставится вместе с меткой «ложное срабатывание» и только с ней";
  }
  return { disposition, escalate, severity_correct: severity };
}

/** Метка из события истории одной строкой; пусто — метки нет. */
export function closureLabelText(e: { disposition?: string; escalate?: boolean | null; severity_correct?: boolean | null; ops_cause?: string; ops_action?: string; blind?: boolean }): string {
  const parts: string[] = [];
  if (e.disposition) parts.push(DISPOSITIONS[e.disposition as Disposition] ?? e.disposition);
  if (e.escalate != null) parts.push(e.escalate ? "нужна эскалация" : "без эскалации");
  if (e.severity_correct != null) parts.push(e.severity_correct ? "уровень верен" : "уровень неверен");
  if (e.ops_cause) parts.push(OPS_CAUSES[e.ops_cause as OpsCause] ?? e.ops_cause);
  if (e.ops_action) parts.push(OPS_ACTIONS[e.ops_action as OpsAction] ?? e.ops_action);
  if (parts.length && e.blind) parts.push("вслепую");
  return parts.join(" · ");
}
