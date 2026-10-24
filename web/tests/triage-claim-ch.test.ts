// Реальная конкурентность claim вердикта на живом ClickHouse. Мок с порядковым
// номером вставок порядок гарантирует и ничего не доказывает; здесь
// параллельные запросы идут и из одного процесса, и из нескольких отдельных
// Node-процессов. Нужен сервер: ARGUS_TEST_CLICKHOUSE_URL (+ _USER, _PASSWORD),
// БД argus; без него тест пропускается.
//   docker run -d -p 8123:8123 -e CLICKHOUSE_DB=argus -e CLICKHOUSE_PASSWORD=x clickhouse/clickhouse-server:24.8
import { test } from "node:test";
import assert from "node:assert/strict";
import { spawn } from "node:child_process";
import { readFileSync } from "node:fs";
import path from "node:path";

const url = process.env.ARGUS_TEST_CLICKHOUSE_URL;
const skip = url ? false : "нет ARGUS_TEST_CLICKHOUSE_URL — тест живого ClickHouse пропущен";
if (url) {
  process.env.CLICKHOUSE_URL = url;
  process.env.CLICKHOUSE_USER = process.env.ARGUS_TEST_CLICKHOUSE_USER ?? "default";
  process.env.CLICKHOUSE_PASSWORD = process.env.ARGUS_TEST_CLICKHOUSE_PASSWORD ?? "";
  process.env.CLICKHOUSE_DB = "argus";
}

/* eslint-disable @typescript-eslint/no-require-imports -- модуль читает env при загрузке */
const q = () => require("../src/lib/argus-queries") as typeof import("../src/lib/argus-queries");
const ch = () => require("../src/lib/clickhouse") as typeof import("../src/lib/clickhouse");
/* eslint-enable @typescript-eslint/no-require-imports */

const root = path.resolve(__dirname, "../..");
const RUN = `t${Date.now()}`;
const sid = (n: number) => `${n.toString(16).padStart(4, "0")}-${RUN.slice(1)}`;
/** Уникальный id инцидента на прогон: таблицы между прогонами не чистятся. */
const inc = (n: number) => `INC-${String(Date.now() % 1_000_000)}${n}`;

/** Строк claim по инциденту: атомарная отметка оставляет ровно одну, а не победителя «по порядку». */
async function claimRows(incidentId: string): Promise<number> {
  const rows = await ch().chQuery<{ n: string }>("SELECT count() AS n FROM triage_verdict_claims_v2 WHERE incident_id = {i:String}", { i: incidentId });
  return Number(rows[0].n);
}

/** Файл миграции — по одному оператору (migrate.sh применяет его --multiquery). */
async function runMigration(f: string): Promise<void> {
  const text = readFileSync(path.join(root, "clickhouse/migrations", f), "utf8").replace(/^--.*$/gm, "");
  for (const stmt of text.split(/;\s*\n/).map((s) => s.trim()).filter(Boolean)) await ch().chCommand(stmt);
}

async function applyMigrations(): Promise<void> {
  for (const f of ["0013_incident_comments.sql", "0017_webhook_deliveries.sql", "0018_webhook_task_id.sql", "0020_triage_verdicts.sql", "0021_triage_verdict_claims.sql", "0024_agent_verdicts.sql", "0025_drop_task_id.sql"]) await runMigration(f);
}

/** Строка журнала с заданным временем (reopened пишется с пустым task_id, как в консоли). */
const journal = (incidentId: string, state: "published" | "reopened", session: string, ts: string, taskId = "") =>
  ch().chCommand(
    "INSERT INTO triage_verdicts (task_id, incident_id, state, session_id, actor, updated_at) VALUES ({t:String}, {i:String}, {st:String}, {s:String}, 'old', {ts:String})",
    { t: taskId, i: incidentId, st: state, s: session, ts },
  );

test("claim: 32 параллельных сессий одного инцидента — один победитель, все видят его", { skip }, async () => {
  await applyMigrations();
  const { claimTriageVerdict, triageVerdictWinner, triageVerdictClaim } = q();
  for (let round = 0; round < 10; round++) {
    const incidentId = inc(round);
    const sessions = Array.from({ length: 32 }, (_, i) => sid(i));
    const winners = await Promise.all(sessions.map((sessionId) => claimTriageVerdict({ incidentId, sessionId, actor: "triage-issuer" })));
    assert.equal(new Set(winners).size, 1, `раунд ${round}: все получили одного победителя: ${[...new Set(winners)]}`);
    assert.ok(sessions.includes(winners[0]));
    assert.equal(await triageVerdictWinner(incidentId), winners[0]);
    assert.equal(await claimRows(incidentId), 1, `раунд ${round}: в claim ровно одна строка`);
    const claim = await triageVerdictClaim(incidentId);
    assert.equal(claim?.session_id, winners[0]);
  }
});

test("claim: победитель не меняется позже и переживает слияние кусков", { skip }, async () => {
  const { claimTriageVerdict, triageVerdictWinner } = q();
  const incidentId = inc(90);
  const first = await claimTriageVerdict({ incidentId, sessionId: sid(0xbbbb), actor: "a" });
  assert.equal(first, sid(0xbbbb));
  // Сессия с «меньшим» session_id приходит позже — сценарий, ломавший журнал по (updated_at, session_id).
  assert.equal(await claimTriageVerdict({ incidentId, sessionId: sid(0xaaaa), actor: "a" }), sid(0xbbbb));
  await ch().chCommand("OPTIMIZE TABLE triage_verdict_claims_v2 FINAL");
  assert.equal(await triageVerdictWinner(incidentId), sid(0xbbbb));
  assert.equal(await claimTriageVerdict({ incidentId, sessionId: sid(0xaaaa), actor: "a" }), sid(0xbbbb));
  assert.equal(await claimRows(incidentId), 1);
});

test("claim: после reopened инцидент можно отметить заново, прежний claim не мешает", { skip }, async () => {
  const { claimTriageVerdict, saveTriageVerdict, triageVerdictWinner, triageVerdictClaim } = q();
  const incidentId = inc(80);
  assert.equal(await claimTriageVerdict({ incidentId, sessionId: sid(1), actor: "a" }), sid(1));
  await saveTriageVerdict({ incidentId, state: "reopened", sessionId: sid(1), actor: "analyst" });
  assert.equal(await triageVerdictWinner(incidentId), null, "после reopened отметки нет");
  assert.equal(await triageVerdictClaim(incidentId), null);
  await new Promise((r) => setTimeout(r, 5));
  assert.equal(await claimTriageVerdict({ incidentId, sessionId: sid(2), actor: "a" }), sid(2));
  assert.equal(await claimTriageVerdict({ incidentId, sessionId: sid(3), actor: "a" }), sid(2));
  assert.equal((await triageVerdictClaim(incidentId))?.session_id, sid(2));
});

test("claim: 4 отдельных процесса Node — один победитель на каждый из 25 инцидентов", { skip, timeout: 120_000 }, async () => {
  const count = 25;
  const prefix = `INC-7${String(Date.now()).slice(-7)}`;
  const tsx = path.resolve(__dirname, "../node_modules/.bin/tsx");
  const child = (session: string) =>
    new Promise<Record<string, string>>((resolve, reject) => {
      const p = spawn(tsx, ["--require", "./tests/_server-only-hook.cjs", "--import", "./tests/_server-only-hook.mjs", "tests/_claim-child.ts", prefix, String(count), session], {
        cwd: path.resolve(__dirname, ".."), env: process.env, stdio: ["ignore", "pipe", "inherit"],
      });
      let out = "";
      p.stdout.on("data", (d) => (out += d));
      p.on("error", reject);
      p.on("close", (code) => (code === 0 ? resolve(JSON.parse(out)) : reject(new Error(`дочерний процесс: код ${code}`))));
    });
  const results = await Promise.all([sid(0xa001), sid(0xa002), sid(0xa003), sid(0xa004)].map(child));
  for (let i = 0; i < count; i++) {
    const id = `${prefix}${i}`;
    const seen = new Set(results.map((r) => r[id]));
    assert.equal(seen.size, 1, `инцидент ${id}: процессы разошлись во мнении: ${[...seen]}`);
  }
  const { triageVerdictWinner } = q();
  for (let i = 0; i < count; i++) {
    assert.equal(await triageVerdictWinner(`${prefix}${i}`), results[0][`${prefix}${i}`]);
    assert.equal(await claimRows(`${prefix}${i}`), 1, `инцидент ${prefix}${i}: ровно одна строка claim`);
  }
});

test("повторный reopened с равным и более ранним временем снимает отметку каждый раз", { skip }, async () => {
  const { claimTriageVerdict, triageVerdictWinner, triageVerdictClaim } = q();
  const incidentId = inc(20);
  const claim = (s: string) => claimTriageVerdict({ incidentId, sessionId: s, actor: "a" });
  const T = "2030-01-01 00:00:00.000";
  assert.equal(await claim("A"), "A");
  await journal(incidentId, "reopened", "", T);
  assert.equal(await triageVerdictWinner(incidentId), null);
  assert.equal(await claim("B"), "B");
  await journal(incidentId, "reopened", "", T); // то же время, что у первого reopened
  assert.equal(await triageVerdictWinner(incidentId), null, "второй reopened с равным временем снял отметку B");
  assert.equal(await triageVerdictClaim(incidentId), null);
  assert.equal(await claim("C"), "C");
  await journal(incidentId, "reopened", "", "2020-01-01 00:00:00.000"); // часы откатились
  assert.equal(await triageVerdictWinner(incidentId), null, "reopened с более ранним временем снял отметку C");
  assert.equal(await claim("D"), "D");
  assert.equal(await claim("E"), "D");
  assert.equal(await claimRows(incidentId), 4);
});

test("обновление 0025: действующий claim задачи переносится как claim инцидента; снятый — нет", { skip }, async () => {
  await applyMigrations();
  const { claimTriageVerdict, triageVerdictWinner, triageVerdictClaim } = q();
  const legacyClaim = (task: string, epoch: number, incidentId: string, session: string, ts: string) =>
    ch().chCommand(
      "INSERT INTO triage_verdict_claims (task_id, epoch, incident_id, session_id, actor, claimed_at) VALUES ({t:String}, {e:Int64}, {i:String}, {s:String}, 'old', {ts:String})",
      { t: task, e: epoch, i: incidentId, s: session, ts },
    );
  const live = inc(50);
  const reopened = inc(51);
  const task1 = `${Date.now()}1`.slice(0, 18);
  const task2 = `${Date.now()}2`.slice(0, 18);
  await legacyClaim(task1, 0, live, "old-session", "2026-10-01 10:00:00.000");
  await legacyClaim(task2, 0, reopened, "old-1", "2026-10-01 10:00:00.000");
  await journal(reopened, "reopened", "", "2026-10-01 11:00:00.000", task2); // отметка задачи снята: epoch задачи 1, claim эпохи 0 не действует
  await runMigration("0025_drop_task_id.sql");
  assert.equal(await triageVerdictWinner(live), "old-session", "действующая отметка перенесена с владельцем");
  assert.equal((await triageVerdictClaim(live))?.session_id, "old-session");
  assert.equal(await claimTriageVerdict({ incidentId: live, sessionId: "new-session", actor: "a" }), "old-session");
  assert.equal(await claimRows(live), 1);
  assert.equal(await claimRows(reopened), 0, "снятая отметка не возвращается");
  assert.equal(await triageVerdictWinner(reopened), null);
  assert.equal(await claimTriageVerdict({ incidentId: reopened, sessionId: "new-1", actor: "a" }), "new-1");
  // повтор миграции ничего не дублирует
  await runMigration("0025_drop_task_id.sql");
  assert.equal(await claimRows(live), 1);
});
