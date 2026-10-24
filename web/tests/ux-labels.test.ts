import { test } from "node:test";
import assert from "node:assert/strict";
import {
  AGENT_STATUS_LABELS,
  ALERT_LEVEL_FILTERS,
  COMPLIANCE_LABELS,
  DASHBOARD_ORIGIN_LABELS,
  INCIDENT_LEVEL_LABELS,
  OUTCOME_LABELS,
  SOURCE_ALIVE_LABELS,
  VULN_SEVERITY_LABELS,
  VULN_STATUS_LABELS,
  agentStatusLabel,
  incidentLevelLabel,
  ruleLevelLabel,
  vulnSeverityLabel,
  vulnStatusLabel,
} from "../src/lib/shared/labels";
import { AGENT_STATUS_TONE, LEVEL_TONE, STATUS_TONE, VULN_TONE } from "../src/components/console/tone";
import { INCIDENT_STATUSES } from "../src/lib/shared/incidents";

const cyrillic = /[а-яё]/i;
const allRussian = (m: Record<string, string>) => Object.values(m).every((v) => cyrillic.test(v));

test("все словари — по-русски и без сырых английских кодов", () => {
  for (const m of [INCIDENT_LEVEL_LABELS, VULN_SEVERITY_LABELS, VULN_STATUS_LABELS, AGENT_STATUS_LABELS, COMPLIANCE_LABELS, DASHBOARD_ORIGIN_LABELS, SOURCE_ALIVE_LABELS, OUTCOME_LABELS, INCIDENT_STATUSES]) {
    assert.ok(allRussian(m), JSON.stringify(m));
  }
  for (const f of ALERT_LEVEL_FILTERS) assert.ok(cyrillic.test(f.label) && !/Level|LVL/.test(f.label), f.label);
});

test("уровни инцидентов: словарь и тона покрывают одни и те же значения", () => {
  assert.deepEqual(Object.keys(INCIDENT_LEVEL_LABELS).sort(), Object.keys(LEVEL_TONE).sort());
  assert.equal(incidentLevelLabel("CRITICAL"), "критический");
  assert.equal(incidentLevelLabel("custom"), "custom");
});

test("статусы инцидентов: у каждого есть тон", () => {
  assert.deepEqual(Object.keys(INCIDENT_STATUSES).sort(), Object.keys(STATUS_TONE).sort());
});

test("серьёзность и статус CVE", () => {
  assert.deepEqual(Object.keys(VULN_SEVERITY_LABELS).map((k) => k.toLowerCase()).sort(), Object.keys(VULN_TONE).sort());
  assert.equal(vulnSeverityLabel("Critical"), "критическая");
  assert.equal(vulnSeverityLabel(""), "—");
  assert.equal(vulnStatusLabel("Solved"), "устранена");
  assert.equal(vulnStatusLabel("Active"), "активна");
});

test("статусы агентов Wazuh: active/disconnected/never_connected/pending", () => {
  for (const s of ["active", "disconnected", "never_connected", "pending"]) {
    assert.ok(cyrillic.test(agentStatusLabel(s)), s);
    assert.ok(s in AGENT_STATUS_TONE, s);
  }
  assert.equal(agentStatusLabel("weird"), "weird");
});

test("вердикты политик: три состояния, «неизвестно» не равно нарушению", () => {
  assert.deepEqual(Object.keys(COMPLIANCE_LABELS).sort(), ["fail", "pass", "unknown"]);
  assert.notEqual(COMPLIANCE_LABELS.unknown, COMPLIANCE_LABELS.fail);
  assert.notEqual(COMPLIANCE_LABELS.unknown, COMPLIANCE_LABELS.pass);
});

test("уровень правила Wazuh — «уровень N», не LVL", () => {
  assert.equal(ruleLevelLabel(12), "уровень 12");
});
