// PR #13: SQL-предпросмотр и панели дашбордов — любой SELECT от argus_ro. Слепой
// разбор держат политики строк из scripts/migrate.sh (блок argus_ro_blind): тест
// исполняет ровно этот блок для временного пользователя с профилем argus_ro и гоняет
// настоящий previewPanelAction против живого ClickHouse — без подмены ответа.
// (Первая версия codex подменяла fetch: защиту на стороне ClickHouse так не проверить.)
import { after, before, test } from "node:test";
import assert from "node:assert/strict";
import { execFileSync } from "node:child_process";
import { randomBytes } from "node:crypto";
import { readFileSync } from "node:fs";
import path from "node:path";
import { applyAllMigrations, ch, liveSkip as skip, root, serializeLiveFile } from "./_ch-live";
import { formData, installNextMocks, loadAuth } from "./_next-mock";
import { hideVerdicts, isBlindIncident } from "../src/lib/blind";

serializeLiveFile({ before, after });

const suffix = randomBytes(6).toString("hex");
const user = `blind_ro_test_${suffix}`;
const policy = `blind_ro_test_${suffix}`;
process.env.CLICKHOUSE_RO_USER = user;
process.env.CLICKHOUSE_RO_PASSWORD = `fixture-${randomBytes(16).toString("hex")}`;
installNextMocks();
// _next-mock глушит сеть (CLICKHOUSE_URL → :9); этому тесту нужен живой сервер.
if (process.env.ARGUS_TEST_CLICKHOUSE_URL) process.env.CLICKHOUSE_URL = process.env.ARGUS_TEST_CLICKHOUSE_URL;
const auth = loadAuth();
/* eslint-disable @typescript-eslint/no-require-imports -- RO-учётка задана до загрузки настоящего action */
const { previewPanelAction } = require("../src/lib/dashboard-actions") as typeof import("../src/lib/dashboard-actions");
/* eslint-enable @typescript-eslint/no-require-imports */

const script = readFileSync(path.join(root, "scripts/migrate.sh"), "utf8");

/** Профиль argus_ro: настройки и гранты вызова mkuser. */
function roProfile(): { settings: string; grants: string[] } {
  const call = script.match(/^mkuser argus_ro\b(?:.*\\\n)*.*$/m);
  assert.ok(call, "production профиль argus_ro найден");
  const quoted = [...call[0].matchAll(/"((?:\\.|[^"\\])*)"/g)].map((m) => m[1]);
  const [, settings, ...grants] = quoted;
  return { settings, grants };
}

/** SQL блока политик: bash исполняет блок с ch(), который только печатает запрос. */
function policyStatements(): string[] {
  const block = script.match(/^if \[ -n "\$\{CLICKHOUSE_RO_PASSWORD:-\}" \]; then\n[\s\S]*?\nfi$/m);
  assert.ok(block && block[0].includes("ROW POLICY"), "блок политик argus_ro найден в migrate.sh");
  const out = execFileSync("bash", ["-c", `ch() { printf '%s\\0' "$2"; }\n${block[0]}`], {
    env: { ...process.env, CLICKHOUSE_RO_PASSWORD: "x" }, encoding: "utf8",
  });
  const stmts = out.split("\0").filter((s) => s.includes("ROW POLICY"));
  assert.equal(stmts.length, 4);
  return stmts.map((s) => s.replaceAll("argus_ro_blind", policy).replace(/\bTO argus_ro$/, `TO ${user}`));
}

const pick = (blind: boolean, from = 870_000_000): number => {
  for (let i = from; ; i++) if (isBlindIncident(`INC-${i}`) === blind) return i;
};
const blindOpen = `INC-${pick(true)}`;
const blindClosed = `INC-${pick(true, pick(true) + 1)}`;
const plainOpen = `INC-${pick(false)}`;
// Вердикт есть, а строки инцидента нет (удалён TTL, запись раньше инцидента): слепой
// скрыт — «завершён» не доказан; не слепой виден.
const blindOrphan = `INC-${pick(true, pick(true, pick(true) + 1) + 1)}`;
const plainOrphan = `INC-${pick(false, pick(false) + 1)}`;
const marker = `BlindRo${suffix}`;

test("blind: argus_ro не читает вердикт и его копии по слепому открытому инциденту", { skip }, async () => {
  await applyAllMigrations();
  const { settings, grants } = roProfile();
  const policies = policyStatements();
  const tables = ["incident_verdicts", "agent_verdicts", "incident_comments", "console_audit"];
  let created = false;
  try {
    await ch().chCommand(`CREATE USER ${user} IDENTIFIED WITH plaintext_password BY '${process.env.CLICKHOUSE_RO_PASSWORD}'`);
    created = true;
    await ch().chCommand(`ALTER USER ${user} SETTINGS ${settings}`);
    for (const grant of grants) await ch().chCommand(`GRANT ${grant} TO ${user}`);
    for (const sql of policies) await ch().chCommand(sql);

    const statuses: [string, string][] = [[blindOpen, "in_progress"], [blindClosed, "closed"], [plainOpen, "new"]];
    for (const [id, status] of statuses) {
      assert.equal(hideVerdicts({ incident_id: id, status }), id === blindOpen);
      await ch().chCommand(`INSERT INTO incidents (incident_id, created_at, updated_at, rule_id, rule_title, level, tags, status, first_ts, last_ts)
        VALUES ({id:String}, now(), now(), 'fixture-blind-ro', 'Blind RO fixture', 'high', [], {status:String}, now64(3), now64(3))`, { id, status });
      const p = { id, m: `${marker}-${id}` };
      await ch().chCommand("INSERT INTO incident_verdicts (incident_id, evaluated_at, summary_ru) VALUES ({id:String}, now(), {m:String})", p);
      await ch().chCommand(`INSERT INTO agent_verdicts (incident_id, session_id, agent, created_at, verdict, markdown)
        VALUES ({id:String}, 'fixture', 'fixture-bot', now(), 'true_positive', {m:String})`, p);
      await ch().chCommand(`INSERT INTO incident_comments (comment_id, incident_id, created_at, author, body) VALUES
        (generateUUIDv4(), {id:String}, now(), 'agent:fixture-bot', {m:String}),
        (generateUUIDv4(), {id:String}, now(), 'analyst', concat('human-', {m:String}))`, p);
      await ch().chCommand(`INSERT INTO console_audit (user, action, target, detail) VALUES
        ('triage:fixture', 'triage.verdict', {id:String}, {m:String}),
        ('analyst', 'incident.comment', {id:String}, concat('human-', {m:String}))`, p);
    }

    for (const id of [blindOrphan, plainOrphan]) {
      await ch().chCommand("INSERT INTO agent_verdicts (incident_id, session_id, agent, created_at, verdict, markdown) VALUES ({id:String}, 'fixture', 'fixture-bot', now(), 'true_positive', {m:String})",
        { id, m: `${marker}-${id}` });
    }

    await auth.createSession(`sso:blind-ro-${suffix}`, "analyst", true);
    const preview = async (sql: string) => {
      const result = await previewPanelAction({ data: null, error: null }, formData({ sql, range: "24h" }));
      assert.equal(result.error, null, `${sql}: ${result.error}`);
      return JSON.stringify(result.data?.rows);
    };
    for (const [table, column] of [["incident_verdicts", "summary_ru"], ["agent_verdicts", "markdown"], ["incident_comments", "body"], ["console_audit", "detail"]]) {
      const text = await preview(`SELECT ${column} FROM ${table} WHERE position(${column}, '${marker}') > 0`);
      assert.ok(!text.includes(`"${marker}-${blindOpen}"`), `${table}: слепой открытый инцидент скрыт`);
      assert.ok(text.includes(`${marker}-${blindClosed}`), `${table}: после завершения доступен`);
      assert.ok(text.includes(`${marker}-${plainOpen}`), `${table}: не слепой инцидент доступен`);
      if (table === "incident_comments" || table === "console_audit") {
        assert.ok(text.includes(`human-${marker}-${blindOpen}`), `${table}: записи людей по слепому инциденту остаются`);
      }
    }
    // Политика действует на чтение таблицы в любом месте запроса: JOIN, подзапрос, merge().
    const hiddenVia = async (label: string, sql: string) => {
      const text = await preview(sql);
      assert.ok(!text.includes(`${marker}-${blindOpen}`), `${label}: слепой открытый инцидент скрыт`);
      assert.ok(text.includes(`${marker}-${plainOpen}`), `${label}: контроль — не слепой виден`);
    };
    await hiddenVia("JOIN", `SELECT v.markdown FROM incidents AS i INNER JOIN agent_verdicts AS v ON v.incident_id = i.incident_id
      WHERE position(v.markdown, '${marker}') > 0`);
    await hiddenVia("подзапрос", `SELECT markdown FROM (SELECT * FROM agent_verdicts) WHERE position(markdown, '${marker}') > 0`);
    // Табличные функции argus_ro не доступны вовсе (нужен CREATE TEMPORARY TABLE): отказ.
    const merged = await previewPanelAction({ data: null, error: null },
      formData({ sql: `SELECT markdown FROM merge('argus', '^agent_verdicts$') WHERE position(markdown, '${marker}') > 0`, range: "24h" }));
    assert.match(String(merged.error), /497|ACCESS_DENIED|запрещ/i, "merge() отклонён");
    assert.ok(!JSON.stringify(merged).includes(`${marker}-${blindOpen}`));
    const orphans = await preview(`SELECT markdown FROM agent_verdicts WHERE position(markdown, '${marker}') > 0`);
    assert.ok(!orphans.includes(`${marker}-${blindOrphan}`), "слепой вердикт без строки инцидента скрыт");
    assert.ok(orphans.includes(`${marker}-${plainOrphan}`), "не слепой вердикт без строки инцидента виден");
    // Системные таблицы (query_log хранит текст INSERT с вердиктом) закрыты дважды:
    // validateSql отвергает «system.», а у argus_ro нет грантов на system.*.
    const sys = await previewPanelAction({ data: null, error: null },
      formData({ sql: `SELECT query FROM system.query_log WHERE position(query, '${marker}') > 0`, range: "24h" }));
    assert.ok(sys.error, "system.query_log недоступен предпросмотру");
    assert.ok(!JSON.stringify(sys).includes(`${marker}-${blindOpen}`));
    const [{ allowed }] = await ch().chQuery<{ allowed: number }>(
      `SELECT count() AS allowed FROM system.grants WHERE user_name = {user:String} AND (database = 'system' OR database IS NULL)`, { user });
    assert.equal(Number(allowed), 0, "у профиля argus_ro нет грантов на system.*");

    // Агрегаты встроенного дашборда argus-siem по-прежнему считаются.
    assert.match(await preview(`SELECT count() AS n FROM incident_verdicts WHERE position(summary_ru, '${marker}') > 0`), /"n":2\b/);
  } finally {
    for (const table of tables) await ch().chCommand(`DROP ROW POLICY IF EXISTS ${policy} ON argus.${table}`);
    if (created) await ch().chCommand(`DROP USER IF EXISTS ${user}`);
  }
});
