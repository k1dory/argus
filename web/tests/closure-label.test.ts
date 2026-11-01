// Метка ответа при завершении и слепая выборка. Векторы выборки — те же, что в
// движке (engine/cmd/engine/workflow_test.go, TestBlindIncident): консоль
// скрывает подсказки ровно у тех инцидентов, которые движок пометит blind.
import { test } from "node:test";
import assert from "node:assert/strict";
import fs from "node:fs";
import path from "node:path";
import { DISPOSITIONS, OPS_ACTIONS, OPS_CAUSES, closureLabelText, isOpsIncident, parseClosureLabel } from "../src/lib/shared/closure-label";
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

test("метка ИБ: все три ответа обязательны, ложное срабатывание согласовано со статусом", () => {
  const ok = parseClosureLabel(form({ disposition: "malicious", escalate: "yes", severity_correct: "no" }), { ops: false, status: "closed" });
  assert.deepEqual(ok, { disposition: "malicious", escalate: true, severity_correct: false });
  assert.equal(typeof parseClosureLabel(form({ disposition: "malicious", escalate: "yes" }), { ops: false, status: "closed" }), "string");
  assert.equal(typeof parseClosureLabel(form({ disposition: "maybe", escalate: "yes", severity_correct: "yes" }), { ops: false, status: "closed" }), "string");
  assert.equal(typeof parseClosureLabel(form({ disposition: "false_positive", escalate: "no", severity_correct: "no" }), { ops: false, status: "closed" }), "string");
  assert.equal(typeof parseClosureLabel(form({ disposition: "malicious", escalate: "no", severity_correct: "no" }), { ops: false, status: "false_positive" }), "string");
  assert.deepEqual(parseClosureLabel(form({ disposition: "false_positive", escalate: "no", severity_correct: "no" }), { ops: false, status: "false_positive" }),
    { disposition: "false_positive", escalate: false, severity_correct: false });
  assert.equal(typeof parseClosureLabel(form({ disposition: "toString", escalate: "no", severity_correct: "no" }), { ops: false, status: "closed" }), "string", "ключи прототипа — не значения словаря");
});

test("метка DevOps: причина и действие", () => {
  assert.equal(isOpsIncident(["argus.system", "ops.storage"]), true);
  assert.equal(isOpsIncident(["attack.t1110"]), false);
  assert.deepEqual(parseClosureLabel(form({ ops_cause: "planned_work", ops_action: "no_action" }), { ops: true, status: "closed" }), { ops_cause: "planned_work", ops_action: "no_action" });
  assert.equal(typeof parseClosureLabel(form({ ops_cause: "planned_work" }), { ops: true, status: "closed" }), "string");
  assert.equal(typeof parseClosureLabel(form({ disposition: "malicious", escalate: "no", severity_correct: "yes" }), { ops: true, status: "closed" }), "string");
});

test("метка в истории одной строкой; автоматика и старые события — без неё", () => {
  assert.equal(closureLabelText({ disposition: "benign_authorized", escalate: false, severity_correct: true, blind: true }), "легитимно, разрешено · без эскалации · уровень верен · вслепую");
  assert.equal(closureLabelText({ ops_cause: "wrong_threshold", ops_action: "rule_tuned", blind: false }), "неверный порог правила · правило поправлено");
  assert.equal(closureLabelText({ disposition: "", escalate: null, severity_correct: null, ops_cause: "", ops_action: "", blind: false }), "");
});
