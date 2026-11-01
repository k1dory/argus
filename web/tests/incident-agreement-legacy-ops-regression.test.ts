// PR #63: миграция 0036 сохраняет метки 0033. Старый DevOps false_positive
// определяется статусом: причины monitoring_noise / wrong_threshold разрешались
// и при closed, и при false_positive. Нельзя включать эти ответы в знаменатель,
// считая каждый из них истинным срабатыванием только из-за старого ops_cause.
// Настоящий AGREEMENT_SQL выполняется на CTE-фикстурах: таблицы не читаются и
// не изменяются, миграции не запускаются. Нужен тестовый ClickHouse, как в *-ch.test.ts.
import { test } from "node:test";
import assert from "node:assert/strict";
import { ch, liveSkip as skip } from "./_ch-live";
import { assembleAgreement, type AgreementSqlRow } from "../src/lib/shared/blind-metrics";

const FIXTURES = `
  incident_state_events AS (
    SELECT *, toUInt64(1) AS revision,
           toDateTime64('2026-10-31 12:00:00.000', 3, 'UTC') AS changed_at,
           'status' AS kind, '' AS disposition, true AS labeled_by_human,
           {blind:Bool} AS blind,
           CAST(NULL AS Nullable(UInt8)) AS severity_level,
           CAST(NULL AS Nullable(Bool)) AS severity_correct,
           CAST(NULL AS Nullable(Bool)) AS escalate,
           '' AS attack_tactic, '' AS attack_technique, '' AS attack_version,
           'no_action' AS ops_action
    FROM values(
      'incident_id String, status String, ops_cause String, ops_act_now Nullable(Bool), ops_urgency Nullable(UInt8)',
      ('INC-63001', 'false_positive', 'monitoring_noise', NULL, NULL),
      ('INC-63002', 'closed',         'monitoring_noise', NULL, NULL),
      ('INC-63003', 'false_positive', 'wrong_threshold',  NULL, NULL),
      ('INC-63004', 'closed',         'wrong_threshold',  NULL, NULL),
      ('INC-63005', 'false_positive', 'false_positive',   false, 1),
      ('INC-63006', 'closed',         'disk',             true,  3)
    )
  ),
  incidents_current AS (
    SELECT incident_id, status, 'ops.pr63-legacy-labels' AS rule_id,
           'Legacy DevOps labels' AS rule_title, ['ops.storage'] AS tags
    FROM incident_state_events
  ),
  agent_verdicts AS (
    SELECT incident_id, 'fixture-session' AS session_id,
           changed_at - INTERVAL 1 HOUR AS created_at,
           'false_positive' AS verdict, '{}' AS verdict_json
    FROM incident_state_events
  ),`;

test("agreement: ложные DevOps-ответы 0033 сохраняют смысл после 0036", { skip }, async (t) => {
  // _ch-live выставляет тестовое окружение до загрузки серверного модуля.
  // eslint-disable-next-line @typescript-eslint/no-require-imports
  const { AGREEMENT_SQL, agreementParams } = require("../src/lib/blind-metrics") as typeof import("../src/lib/blind-metrics");
  assert.match(AGREEMENT_SQL, /^\s*WITH\b/, "фикстуры должны войти в общий WITH запроса");
  const sql = AGREEMENT_SQL.replace(/^\s*WITH\b/, `WITH ${FIXTURES}`);
  const now = Date.parse("2026-11-01T12:00:00.000Z");

  for (const blind of [false, true]) {
    for (const window of ["7d", "30d"] as const) {
      await t.test(`${blind ? "blind" : "sighted"}, ${window}`, async () => {
        const rows = await ch().chQuery<AgreementSqlRow>(sql, {
          ...agreementParams(window, now), blind: String(blind),
        });
        assert.equal(rows.length, 1);
        assert.equal(Number(rows[0].labeled), 6, "все шесть закрытий размечены человеком");
        assert.equal(Number(rows[0].fp), 3,
          "два false_positive из 0033 и один из 0036; одинаковая старая причина при closed не является FP");

        const { total } = assembleAgreement(rows);
        assert.deepEqual([total.false_positive.k, total.false_positive.n, total.false_positive.share], [3, 6, 0.5]);
        assert.equal(total.blind.agreement.n + total.sighted.agreement.n, 0,
          "DevOps не сравнивается с вердиктом агента даже при совпадении false_positive");
      });
    }
  }
});
