// Выгрузка меток ответа (GET /api/incidents/labels) на живом ClickHouse: метка
// пишется в incident_state_events (миграция 0033) и читается обратно; автозакрытие
// пишет тот же статус closed, но в выгрузку не попадает.
import { after, before, test } from "node:test";
import assert from "node:assert/strict";
import { randomUUID } from "node:crypto";
import { applyAllMigrations, ch, liveSkip as skip, serializeLiveFile } from "./_ch-live";

serializeLiveFile({ before, after });

/* eslint-disable @typescript-eslint/no-require-imports -- модуль читает env при загрузке */
const q = () => require("../src/lib/argus-queries") as typeof import("../src/lib/argus-queries");
/* eslint-enable @typescript-eslint/no-require-imports */

test("incidentLabels: только ответы людей, с правилом инцидента и признаком blind", { skip }, async () => {
  await applyAllMigrations();
  const run = Date.now().toString(36);
  const human = `INC-9${run.length}${Math.floor(Math.random() * 1e6)}`, auto = `${human}1`, open = `${human}2`;
  const since = new Date(Date.now() - 1000).toISOString().slice(0, 19);
  for (const [id, rule] of [[human, `r-${run}`], [auto, `r-${run}-auto`], [open, `r-${run}`]]) {
    await ch().chCommand(`INSERT INTO incidents (incident_id, created_at, updated_at, rule_id, rule_title, level, tags, status, first_ts, last_ts)
      VALUES ({id:String}, now(), now(), {rule:String}, 'Перебор паролей', 'high', ['attack.t1110'], 'new', now64(3), now64(3))`, { id, rule });
  }
  const state = (id: string, kind: string, status: string, label: string) => ch().chCommand(
    `INSERT INTO incident_state_events (event_id, incident_id, revision, changed_at, actor, kind, status, owner, reason${label ? ", disposition, escalate, severity_correct, blind, labeled_by_human, severity_level, attack_tactic, attack_technique, attack_version, ops_act_now, ops_urgency" : ""})
     VALUES ({e:String}, {id:String}, 1, now64(3), 'anna', {k:String}, {s:String}, 'anna', 'проверено по журналу'${label})`,
    { e: randomUUID(), id, k: kind, s: status });
  await state(human, "status", "closed", ", 'benign_authorized', false, NULL, true, true, 2, 'discovery', 'T1046', '20.0', NULL, NULL");
  await state(auto, "auto_close", "closed", "");
  await state(open, "take", "in_progress", "");
  const rows = (await q().incidentLabels(since, 1000)).filter((r) => [human, auto, open].includes(r.incident_id));
  assert.deepEqual(rows.map((r) => r.incident_id), [human], "автозакрытие и незавершённые не выдаются");
  const [r] = rows;
  assert.equal(r.disposition, "benign_authorized");
  assert.equal(r.escalate, false);
  assert.equal(r.severity_correct, null, "null отличим от false");
  // Поля плана разметки (0036) выгружаются как есть; DevOps-поля у ИБ — null.
  assert.deepEqual([r.severity_level, r.attack_tactic, r.attack_technique, r.attack_version, r.ops_act_now, r.ops_urgency],
    [2, "discovery", "T1046", "20.0", null, null]);
  assert.equal(r.blind, true);
  assert.equal(r.rule_id, `r-${run}`);
  assert.deepEqual(r.tags, ["attack.t1110"]);
  const history = await q().incidentStateHistory(human);
  assert.equal(history[0].labeled_by_human, true);
  assert.equal(history[0].disposition, "benign_authorized");
});
