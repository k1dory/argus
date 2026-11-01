// Метка ответа человека при завершении инцидента (миграции 0033, 0036; вопросы — план
// разметки в вики argus-laya-данные-и-разметка). Набор значений общий с движком
// (engine/cmd/engine/labels.go) и конвейером датасета: движок проверяет метку ещё раз,
// вычисляет severity_correct и сам решает, входит ли инцидент в слепую выборку.
import { ATTACK_OTHER, ATTACK_TACTICS, isAttackTactic, isAttackTechnique } from "./attack";

export const DISPOSITIONS = {
  malicious: "вредоносная активность",
  benign_authorized: "легитимно, разрешено",
  false_positive: "ложное срабатывание",
} as const;
export type Disposition = keyof typeof DISPOSITIONS;

/** Какой уровень правильный (severity_level 1–4); severity_correct вычисляется:
 *  совпал ли ответ с уровнем правила. */
export const SEVERITY_LEVELS = { 1: "low", 2: "medium", 3: "high", 4: "critical" } as const;
export const SEVERITY_LABELS: Record<string, string> = { 1: "низкий (low)", 2: "средний (medium)", 3: "высокий (high)", 4: "критический (critical)" };

export function severityCorrect(level: number | null | undefined, ruleLevel: string): boolean | null {
  const rank = Object.entries(SEVERITY_LEVELS).find(([, name]) => name === ruleLevel)?.[0];
  return level == null || rank === undefined ? null : Number(rank) === level;
}

export const OPS_CAUSES = {
  disk: "диск",
  memory: "память",
  network: "сеть",
  process_crash: "процесс упал",
  config: "конфигурация",
  deploy: "деплой",
  external_dependency: "внешняя зависимость",
  false_positive: "ложное срабатывание",
} as const;
export type OpsCause = keyof typeof OPS_CAUSES;

/** «Что сделали» — необязательно, для метрик. */
export const OPS_ACTIONS = {
  fixed: "устранено",
  no_action: "действий не требуется",
  rule_tuned: "правило поправлено",
  handed_over: "передано владельцу системы",
} as const;
export type OpsAction = keyof typeof OPS_ACTIONS;

/** Срочность DevOps 1–4. */
export const OPS_URGENCY: Record<string, string> = { 1: "низкая", 2: "средняя", 3: "высокая", 4: "немедленно" };

export type SecurityLabel = {
  disposition: Disposition; escalate: boolean; severity_level: number;
  /** Пусто — только при false_positive: у ложного срабатывания тактики нет. */
  attack_tactic: string; attack_technique: string;
};
export type OpsLabel = { ops_cause: OpsCause; ops_act_now: boolean; ops_urgency: number; ops_action: OpsAction | "" };
export type ClosureLabel = SecurityLabel | OpsLabel;

/** Эксплуатационное правило (теги ops.*): вместо вердикта ИБ — причина, срочность и действие. */
export function isOpsIncident(tags: readonly string[]): boolean {
  return tags.some((t) => t.startsWith("ops."));
}

const has = <T extends object>(dict: T, key: string): key is Extract<keyof T, string> => Object.hasOwn(dict, key);
const yesNo = (v: string): boolean | null => v === "yes" ? true : v === "no" ? false : null;
const score = (v: string): number | null => /^[1-4]$/.test(v) ? Number(v) : null;

/** Метка из полей формы завершения; строка — ошибка для пользователя. Та же проверка — в
 *  движке (engine/cmd/engine/labels.go). */
export function parseClosureLabel(get: (name: string) => string, opts: { ops: boolean; status: string }): ClosureLabel | string {
  if (opts.ops) {
    const cause = get("ops_cause"), actNow = yesNo(get("ops_act_now")), urgency = score(get("ops_urgency")), action = get("ops_action");
    if (!has(OPS_CAUSES, cause) || actNow === null || urgency === null) return "Укажите причину, нужно ли действовать сейчас и срочность";
    if (action !== "" && !has(OPS_ACTIONS, action)) return "Неизвестное действие";
    if ((opts.status === "false_positive") !== (cause === "false_positive")) {
      return "Статус «ложное срабатывание» ставится вместе с причиной «ложное срабатывание» и только с ней";
    }
    return { ops_cause: cause, ops_act_now: actNow, ops_urgency: urgency, ops_action: action as OpsAction | "" };
  }
  const disposition = get("disposition");
  const escalate = yesNo(get("escalate")), level = score(get("severity_level"));
  if (!has(DISPOSITIONS, disposition) || escalate === null || level === null) {
    return "Укажите характер срабатывания, нужна ли эскалация и правильный уровень";
  }
  if ((opts.status === "false_positive") !== (disposition === "false_positive")) {
    return "Статус «ложное срабатывание» ставится вместе с меткой «ложное срабатывание» и только с ней";
  }
  const tactic = get("attack_tactic"), technique = get("attack_technique");
  if (disposition !== "false_positive" && (!tactic || !technique)) return "Укажите тактику и технику ATT&CK (или «другое»)";
  if ((tactic && !isAttackTactic(tactic)) || (technique && !isAttackTechnique(technique)) || (technique && !tactic)) {
    return "Тактика и техника — из справочника ATT&CK или «другое»";
  }
  return { disposition, escalate, severity_level: level, attack_tactic: tactic, attack_technique: technique };
}

export type ClosureLabelView = {
  disposition?: string; escalate?: boolean | null; severity_correct?: boolean | null; severity_level?: number | null;
  attack_tactic?: string; attack_technique?: string;
  ops_cause?: string; ops_act_now?: boolean | null; ops_urgency?: number | null; ops_action?: string; blind?: boolean;
};

/** Метка из события истории одной строкой; пусто — метки нет. */
export function closureLabelText(e: ClosureLabelView): string {
  const parts: string[] = [];
  if (e.disposition) parts.push(DISPOSITIONS[e.disposition as Disposition] ?? e.disposition);
  if (e.escalate != null) parts.push(e.escalate ? "нужна эскалация" : "без эскалации");
  if (e.severity_level != null) parts.push(`уровень: ${SEVERITY_LEVELS[e.severity_level as keyof typeof SEVERITY_LEVELS] ?? e.severity_level}`);
  else if (e.severity_correct != null) parts.push(e.severity_correct ? "уровень верен" : "уровень неверен");
  if (e.attack_tactic) parts.push(e.attack_tactic === ATTACK_OTHER ? "тактика: другое" : ATTACK_TACTICS[e.attack_tactic] ?? e.attack_tactic);
  if (e.attack_technique) parts.push(e.attack_technique === ATTACK_OTHER ? "техника: другое" : e.attack_technique);
  if (e.ops_cause) parts.push(OPS_CAUSES[e.ops_cause as OpsCause] ?? e.ops_cause);
  if (e.ops_act_now != null) parts.push(e.ops_act_now ? "действовать сейчас: да" : "действовать сейчас: нет");
  if (e.ops_urgency != null) parts.push(`срочность ${e.ops_urgency}`);
  if (e.ops_action) parts.push(OPS_ACTIONS[e.ops_action as OpsAction] ?? e.ops_action);
  if (parts.length && e.blind) parts.push("вслепую");
  return parts.join(" · ");
}
