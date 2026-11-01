// Метка ответа при завершении и слепая выборка. Векторы выборки — те же, что в
// движке (engine/cmd/engine/workflow_test.go, TestBlindIncident): консоль
// скрывает подсказки ровно у тех инцидентов, которые движок пометит blind.
import { test } from "node:test";
import assert from "node:assert/strict";
import fs from "node:fs";
import path from "node:path";
import { DISPOSITIONS, OPS_ACTIONS, OPS_CAUSES, SEVERITY_LEVELS, closureLabelText, isOpsIncident, parseClosureLabel, severityCorrect } from "../src/lib/shared/closure-label";
import { BLIND_PERCENT, hideVerdicts, isBlindIncident } from "../src/lib/blind";

const form = (fields: Record<string, string>) => (name: string) => fields[name] ?? "";

test("словари меток совпадают с движком", () => {
  const src = fs.readFileSync(path.resolve(__dirname, "../../engine/cmd/engine/labels.go"), "utf8");
  const list = (name: string) => {
    const m = src.match(new RegExp(`${name}\\s*=\\s*\\[\\]string\\{([^}]*)\\}`));
    assert.ok(m, name);
    return [...m[1].matchAll(/"([a-z_]+)"/g)].map((x) => x[1]);
  };
  assert.deepEqual(list("dispositions"), Object.keys(DISPOSITIONS));
  assert.deepEqual(list("opsCauses"), Object.keys(OPS_CAUSES));
  assert.deepEqual(list("opsActions"), Object.keys(OPS_ACTIONS));
  assert.deepEqual(list("severityLevels"), Object.values(SEVERITY_LEVELS));
  assert.match(src, new RegExp(`const blindPercent = ${BLIND_PERCENT}\\b`));
});

test("слепая выборка — те же векторы, что в движке, и около 25 %", () => {
  const want: Record<string, boolean> = { "INC-1": false, "INC-2": false, "INC-3": false, "INC-4": true, "INC-6": true, "INC-8": true, "INC-12": false };
  for (const [id, w] of Object.entries(want)) assert.equal(isBlindIncident(id), w, id);
  let n = 0;
  for (let i = 1; i <= 10_000; i++) if (isBlindIncident(`INC-${i}`)) n++;
  assert.equal(n, 2502);
  assert.equal(hideVerdicts({ incident_id: "INC-4", status: "in_progress" }), true);
  assert.equal(hideVerdicts({ incident_id: "INC-4", status: "closed" }), false, "после завершения подсказки видны");
  assert.equal(hideVerdicts({ incident_id: "INC-1", status: "new" }), false);
});

const sec = { disposition: "malicious", escalate: "yes", severity_level: "2", attack_tactic: "credential-access", attack_technique: "T1110.001" };

test("метка ИБ: исход, эскалация, правильный уровень, тактика и техника; ложное — согласовано со статусом", () => {
  assert.deepEqual(parseClosureLabel(form(sec), { ops: false, status: "closed" }),
    { disposition: "malicious", escalate: true, severity_level: 2, attack_tactic: "credential-access", attack_technique: "T1110.001" });
  assert.deepEqual(parseClosureLabel(form({ ...sec, attack_tactic: "other", attack_technique: "other" }), { ops: false, status: "closed" }),
    { disposition: "malicious", escalate: true, severity_level: 2, attack_tactic: "other", attack_technique: "other" });
  for (const [name, fields] of Object.entries<Record<string, string>>({
    "без эскалации": { ...sec, escalate: "" },
    "без уровня": { ...sec, severity_level: "" },
    "уровень 0": { ...sec, severity_level: "0" },
    "уровень 5": { ...sec, severity_level: "5" },
    "уровень дробный": { ...sec, severity_level: "2.5" },
    "старое поле severity_correct вместо уровня": { disposition: "malicious", escalate: "yes", severity_correct: "yes", attack_tactic: "other", attack_technique: "other" },
    "неизвестный исход": { ...sec, disposition: "maybe" },
    "ключ прототипа": { ...sec, disposition: "toString" },
    "без тактики": { ...sec, attack_tactic: "" },
    "без техники": { ...sec, attack_technique: "" },
    "тактика с подчёркиванием": { ...sec, attack_tactic: "credential_access" },
    "техника не из справочника": { ...sec, attack_technique: "T9999" },
    "техника в нижнем регистре": { ...sec, attack_technique: "t1110" },
    "ложное при статусе closed": { ...sec, disposition: "false_positive" },
  })) assert.equal(typeof parseClosureLabel(form(fields), { ops: false, status: "closed" }), "string", name);
  assert.equal(typeof parseClosureLabel(form(sec), { ops: false, status: "false_positive" }), "string", "статус ложного без метки ложного");
  // У ложного срабатывания тактика и техника необязательны.
  assert.deepEqual(parseClosureLabel(form({ disposition: "false_positive", escalate: "no", severity_level: "1" }), { ops: false, status: "false_positive" }),
    { disposition: "false_positive", escalate: false, severity_level: 1, attack_tactic: "", attack_technique: "" });
  assert.equal(typeof parseClosureLabel(form({ disposition: "false_positive", escalate: "no", severity_level: "1", attack_technique: "T1046" }), { ops: false, status: "false_positive" }), "string",
    "техника без тактики");
});

test("severity_correct вычисляется из ответа и уровня правила", () => {
  assert.equal(severityCorrect(3, "high"), true);
  assert.equal(severityCorrect(4, "high"), false);
  assert.equal(severityCorrect(1, "low"), true);
  assert.equal(severityCorrect(2, ""), null, "уровень правила вне шкалы — нет ответа, а не «неверно»");
  assert.equal(severityCorrect(null, "high"), null);
  assert.deepEqual(Object.values(SEVERITY_LEVELS), ["low", "medium", "high", "critical"]);
});

test("метка DevOps: причина, действовать сейчас, срочность; «что сделали» — необязательно", () => {
  assert.equal(isOpsIncident(["argus.system", "ops.storage"]), true);
  assert.equal(isOpsIncident(["attack.t1110"]), false);
  const ops = { ops_cause: "disk", ops_act_now: "yes", ops_urgency: "3" };
  assert.deepEqual(parseClosureLabel(form(ops), { ops: true, status: "closed" }), { ops_cause: "disk", ops_act_now: true, ops_urgency: 3, ops_action: "" });
  assert.deepEqual(parseClosureLabel(form({ ...ops, ops_action: "fixed" }), { ops: true, status: "closed" }), { ops_cause: "disk", ops_act_now: true, ops_urgency: 3, ops_action: "fixed" });
  assert.deepEqual(parseClosureLabel(form({ ...ops, ops_cause: "false_positive" }), { ops: true, status: "false_positive" }),
    { ops_cause: "false_positive", ops_act_now: true, ops_urgency: 3, ops_action: "" });
  for (const [name, fields, status] of [
    ["старая причина", { ...ops, ops_cause: "planned_work" }, "closed"],
    ["без «сейчас»", { ...ops, ops_act_now: "" }, "closed"],
    ["без срочности", { ...ops, ops_urgency: "" }, "closed"],
    ["срочность 5", { ...ops, ops_urgency: "5" }, "closed"],
    ["неизвестное действие", { ...ops, ops_action: "rebooted" }, "closed"],
    ["ложное при closed", { ...ops, ops_cause: "false_positive" }, "closed"],
    ["статус ложного с другой причиной", ops, "false_positive"],
    ["вопросы ИБ", sec, "closed"],
  ] as const) assert.equal(typeof parseClosureLabel(form(fields as Record<string, string>), { ops: true, status }), "string", name);
});

test("метка в истории одной строкой; автоматика и старые события — без неё", () => {
  assert.equal(closureLabelText({ disposition: "benign_authorized", escalate: false, severity_level: 3, severity_correct: true, attack_tactic: "discovery", attack_technique: "T1046", blind: true }),
    "легитимно, разрешено · без эскалации · уровень: high · Discovery · T1046 · вслепую");
  assert.equal(closureLabelText({ disposition: "benign_authorized", escalate: false, severity_correct: true, blind: false }), "легитимно, разрешено · без эскалации · уровень верен",
    "событие 0033 без severity_level");
  assert.equal(closureLabelText({ ops_cause: "network", ops_act_now: true, ops_urgency: 4, ops_action: "fixed", blind: false }), "сеть · действовать сейчас: да · срочность 4 · устранено");
  assert.equal(closureLabelText({ disposition: "", escalate: null, severity_correct: null, ops_cause: "", ops_action: "", blind: false }), "");
});
