// Метрики слепой выборки на живом ClickHouse: настоящий AGREEMENT_SQL по фикстурам
// в incidents / incident_state_events / agent_verdicts. Открытые инциденты,
// автозакрытия, метки DevOps и закрытия вне окна в агрегаты не входят; вердикт
// после закрытия не учитывается. Тот же запрос от argus_ro (политики argus_ro_blind
// из migrate.sh) даёт те же числа, а сырой агрегат по agent_verdicts у argus_ro не
// видит вердикт открытого слепого инцидента.
import { after, before, test } from "node:test";
import assert from "node:assert/strict";
import { randomBytes, randomUUID } from "node:crypto";
import { applyAllMigrations, ch, liveSkip as skip, serializeLiveFile } from "./_ch-live";
import { createBlindRo, queryAs } from "./_ro-blind";
import { isBlindIncident } from "../src/lib/blind";
import { chTs } from "../src/lib/shared/log-query";
import type { AgreementSqlRow } from "../src/lib/shared/blind-metrics";

serializeLiveFile({ before, after });

/* eslint-disable @typescript-eslint/no-require-imports -- модуль читает env при загрузке */
const metrics = () => require("../src/lib/blind-metrics") as typeof import("../src/lib/blind-metrics");
/* eslint-enable @typescript-eslint/no-require-imports */

const DAY = 86_400_000;

test("agreement: только завершённые с ответом человека, слепые отдельно, совпадает у argus_ro", { skip }, async () => {
  await applyAllMigrations();
  const run = randomBytes(5).toString("hex");
  const rule = `agreement-${run}`, opsRule = `ops.agreement-${run}`;
  const now = Date.now();
  let seq = Number.parseInt(run.slice(0, 6), 16) * 100;
  const pick = (blind: boolean): string => {
    for (;;) { const id = `INC-AG${++seq}`; if (isBlindIncident(id) === blind) return id; }
  };
  type Case = {
    blind: boolean; rule?: string; closeAgo?: number; kind?: string; human?: boolean;
    disposition?: string; status?: string; verdicts?: [string, number][];
  };
  const cases: Record<string, Case> = {
    blindAgree: { blind: true, disposition: "malicious", verdicts: [["true_positive", 2 * DAY]] },
    blindDisagree: { blind: true, disposition: "malicious", verdicts: [["false_positive", 2 * DAY]] },
    // Последний вердикт до закрытия — true_positive; поздний false_positive не считается.
    blindLateVerdict: { blind: true, disposition: "malicious", verdicts: [["true_positive", 2 * DAY], ["false_positive", -1000]] },
    sightedAgree: { blind: false, disposition: "benign_authorized", verdicts: [["benign_true_positive", 2 * DAY]] },
    sightedUndetermined: { blind: false, disposition: "false_positive", status: "false_positive", verdicts: [["undetermined", 2 * DAY]] },
    sightedNoVerdict: { blind: false, disposition: "false_positive", status: "false_positive" },
    // 10 дней назад: в окне 30 дней, не в окне 7.
    sightedOlder: { blind: false, disposition: "false_positive", status: "false_positive", closeAgo: 10 * DAY, verdicts: [["false_positive", 11 * DAY]] },
    outside: { blind: false, disposition: "malicious", closeAgo: 40 * DAY, verdicts: [["true_positive", 41 * DAY]] },
    autoClose: { blind: true, kind: "auto_close", human: false, disposition: "", verdicts: [["true_positive", 2 * DAY]] },
    // Закрытие с видом status, но не от человека: учитывать нельзя, даже с disposition.
    unlabeled: { blind: false, human: false, disposition: "malicious", verdicts: [["true_positive", 2 * DAY]] },
    blindOpen: { blind: true, status: "", verdicts: [["false_positive", 2 * DAY]] },
    ops: { blind: false, rule: opsRule, disposition: "", verdicts: [["true_positive", 2 * DAY]] },
  };
  const ids = Object.fromEntries(Object.entries(cases).map(([name, c]) => [name, pick(c.blind)])) as Record<keyof typeof cases, string>;
  const all = Object.values(ids);

  for (const [name, c] of Object.entries(cases)) {
    const id = ids[name];
    const closeAt = now - (c.closeAgo ?? DAY);
    await ch().chCommand(`INSERT INTO incidents (incident_id, created_at, updated_at, rule_id, rule_title, level, tags, status, first_ts, last_ts)
      SELECT {id:String}, parseDateTime64BestEffort({at:String}, 3, 'UTC'), parseDateTime64BestEffort({at:String}, 3, 'UTC'), {rule:String}, 'Agreement fixture', 'high', [], 'new', parseDateTime64BestEffort({at:String}, 3, 'UTC'), parseDateTime64BestEffort({at:String}, 3, 'UTC')`,
    { id, rule: c.rule ?? rule, at: chTs(closeAt - 3 * DAY) });
    if (c.status !== "") {
      await ch().chCommand(`INSERT INTO incident_state_events (event_id, incident_id, revision, changed_at, actor, kind, status, owner, reason,
          disposition, escalate, severity_correct, ops_cause, ops_action, blind, labeled_by_human)
        SELECT {e:String}, {id:String}, 1, parseDateTime64BestEffort({at:String}, 3, 'UTC'), 'anna', {kind:String}, {status:String}, 'anna', 'fixture',
          {d:String}, false, true, {oc:String}, {oa:String}, {blind:Bool}, {human:Bool}`,
      { e: randomUUID(), id, at: chTs(closeAt), kind: c.kind ?? "status", status: c.status ?? "closed", d: c.disposition ?? "",
        oc: name === "ops" ? "planned_work" : "", oa: name === "ops" ? "no_action" : "",
        blind: String(c.blind), human: String(c.human ?? true) });
    }
    for (const [verdict, before] of c.verdicts ?? []) {
      await ch().chCommand(`INSERT INTO agent_verdicts (incident_id, session_id, agent, created_at, verdict, confidence, human_needed, verdict_json, markdown)
        SELECT {id:String}, 'fixture', 'fixture-bot', parseDateTime64BestEffort({at:String}, 3, 'UTC'), {v:String}, 0.9, 0, '{}', 'fixture'`,
      { id, at: chTs(closeAt - before), v: verdict });
    }
  }

  const ours = (rows: AgreementSqlRow[]) => rows.filter((r) => r.rule_id === rule || r.rule_id === opsRule)
    .map((r) => ({ ...r, blind: Number(r.blind), labeled: Number(r.labeled), fp: Number(r.fp), compared: Number(r.compared),
      agreed: Number(r.agreed), undetermined: Number(r.undetermined), no_verdict: Number(r.no_verdict) }));
  const expected30 = [
    { rule_id: rule, rule_title: "Agreement fixture", blind: 0, labeled: 4, fp: 3, compared: 2, agreed: 2, undetermined: 1, no_verdict: 1 },
    { rule_id: rule, rule_title: "Agreement fixture", blind: 1, labeled: 3, fp: 0, compared: 3, agreed: 2, undetermined: 0, no_verdict: 0 },
  ];
  const sql = metrics().AGREEMENT_SQL;
  const p30 = metrics().agreementParams("30d", now + 1000);
  assert.deepEqual(ours(await ch().chQuery<AgreementSqlRow>(sql, p30)), expected30,
    "открытый, автозакрытие, метка DevOps и закрытие вне окна не входят; поздний вердикт не считается");
  const p7 = metrics().agreementParams("7d", now + 1000);
  assert.deepEqual(ours(await ch().chQuery<AgreementSqlRow>(sql, p7)).map((r) => [r.blind, r.labeled, r.fp]), [[0, 3, 2], [1, 3, 0]],
    "закрытие десятидневной давности в окно 7 дней не входит");

  const m = await metrics().agreementMetrics("30d", now + 1000);
  const mine = m.rules.find((r) => r.rule_id === rule);
  assert.ok(mine);
  assert.deepEqual([mine.labeled, mine.false_positive.k, mine.blind.agreement.k, mine.blind.agreement.n, mine.sighted.agreement.k, mine.sighted.agreement.n],
    [7, 3, 2, 3, 2, 2]);
  assert.equal(mine.false_positive.low_data, true, "n < 20 помечается");
  assert.ok(!m.rules.some((r) => r.rule_id === opsRule), "метки DevOps не участвуют");

  const user = `agreement_ro_${run}`, policy = `agreement_ro_${run}`, password = `fixture-${randomBytes(16).toString("hex")}`;
  const cleanup = await createBlindRo(user, policy, password);
  try {
    assert.deepEqual(ours(await queryAs<AgreementSqlRow>(user, password, sql, p30)), expected30,
      "argus_ro: политики слепого разбора не меняют метрики по завершённым инцидентам");
    const countSql = "SELECT count() AS n FROM agent_verdicts WHERE has(splitByChar(',', {ids:String}), incident_id)";
    const [admin] = await ch().chQuery<{ n: string | number }>(countSql, { ids: all.join(",") });
    const [ro] = await queryAs<{ n: string | number }>(user, password, countSql, { ids: all.join(",") });
    // autoClose завершён движком — вердикт виден; скрыт только открытый слепой.
    assert.equal(Number(ro.n), Number(admin.n) - cases.blindOpen.verdicts!.length,
      "argus_ro: сырой агрегат не видит вердикт открытого слепого инцидента");
  } finally {
    await cleanup();
  }
});
