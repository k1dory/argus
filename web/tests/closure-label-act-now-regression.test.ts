// PR #63: ops_act_now и ops_urgency — независимые ответы. Срочный инцидент
// уже устранён: действовать сейчас не требуется, но срочность остаётся 4.
import { test } from "node:test";
import assert from "node:assert/strict";
import { closureLabelText, parseClosureLabel, type OpsLabel } from "../src/lib/shared/closure-label";
import { incidentMarkdown, type WikiChange, type WikiIncident } from "../src/lib/shared/incident-wiki";

function resolvedUrgentLabel(): OpsLabel {
  const fields: Record<string, string> = {
    ops_cause: "network", ops_act_now: "no", ops_urgency: "4", ops_action: "fixed",
  };
  const label = parseClosureLabel((name) => fields[name] ?? "", { ops: true, status: "closed" });
  assert.ok(typeof label !== "string" && "ops_cause" in label, "форма разрешает эти независимые ответы");
  assert.equal(label.ops_act_now, false);
  assert.equal(label.ops_urgency, 4);
  return label;
}

test("история: ops_act_now=false не превращает срочный инцидент в несрочный", () => {
  const label = resolvedUrgentLabel();
  const text = closureLabelText(label);
  assert.match(text, /срочность 4/);
  assert.notEqual(text, closureLabelText({ ...label, ops_act_now: null }),
    "ответ «нет» должен оставаться видимым и отличаться от отсутствующего ответа");
  assert.doesNotMatch(text, /не срочно/i,
    "отказ от действия сейчас не означает низкую срочность");
});

test("Markdown: ответ о действии сейчас не переименовывается в ответ о срочности", () => {
  const incident: WikiIncident = {
    incident_id: "INC-63006", rule_id: "ops.network", rule_title: "Network failure",
    level: "critical", status: "closed", owner: "qa",
    created_at: "2026-11-01 10:00:00.000", note: "",
  };
  const change: WikiChange = {
    ...resolvedUrgentLabel(), changed_at: "2026-11-01 10:10:00.000", actor: "qa",
    kind: "status", status: "closed", owner: "qa", revision: 2,
    reason: "Сеть восстановлена, дополнительных действий не требуется",
  };
  const markdown = incidentMarkdown(incident, null, [change], []);
  assert.match(markdown, /срочность 4/);
  assert.notEqual(markdown, incidentMarkdown(incident, null, [{ ...change, ops_act_now: null }], []));
  assert.doesNotMatch(markdown, /не срочно/i,
    "выгруженный отчёт не должен противоречить сохранённой срочности 4");
});
