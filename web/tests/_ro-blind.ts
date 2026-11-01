// Временный пользователь с профилем argus_ro и политиками argus_ro_blind ровно из
// scripts/migrate.sh: bash исполняет блок политик с ch(), который только печатает
// запрос, имена политики и пользователя подменяются на временные.
import assert from "node:assert/strict";
import { execFileSync } from "node:child_process";
import { readFileSync } from "node:fs";
import path from "node:path";
import { ch, root } from "./_ch-live";

const script = () => readFileSync(path.join(root, "scripts/migrate.sh"), "utf8");

/** Профиль argus_ro: настройки и гранты вызова mkuser. */
export function roProfile(): { settings: string; grants: string[] } {
  const call = script().match(/^mkuser argus_ro\b(?:.*\\\n)*.*$/m);
  assert.ok(call, "production профиль argus_ro найден");
  const quoted = [...call[0].matchAll(/"((?:\\.|[^"\\])*)"/g)].map((m) => m[1]);
  const [, settings, ...grants] = quoted;
  return { settings, grants };
}

export const BLIND_POLICY_TABLES = ["incident_verdicts", "agent_verdicts", "incident_comments", "console_audit"];

/** SQL блока политик для временных пользователя и политики. */
export function policyStatements(user: string, policy: string): string[] {
  const block = script().match(/^if \[ -n "\$\{CLICKHOUSE_RO_PASSWORD:-\}" \]; then\n[\s\S]*?\nfi$/m);
  assert.ok(block && block[0].includes("ROW POLICY"), "блок политик argus_ro найден в migrate.sh");
  const out = execFileSync("bash", ["-c", `ch() { printf '%s\\0' "$2"; }\n${block[0]}`], {
    env: { ...process.env, CLICKHOUSE_RO_PASSWORD: "x" }, encoding: "utf8",
  });
  const stmts = out.split("\0").filter((s) => s.includes("ROW POLICY"));
  assert.equal(stmts.length, BLIND_POLICY_TABLES.length);
  return stmts.map((s) => s.replaceAll("argus_ro_blind", policy).replace(/\bTO argus_ro$/, `TO ${user}`));
}

/** Создать пользователя с профилем argus_ro и политиками; вернуть уборку. */
export async function createBlindRo(user: string, policy: string, password: string): Promise<() => Promise<void>> {
  const { settings, grants } = roProfile();
  const policies = policyStatements(user, policy);
  let created = false;
  const cleanup = async () => {
    for (const table of BLIND_POLICY_TABLES) await ch().chCommand(`DROP ROW POLICY IF EXISTS ${policy} ON argus.${table}`);
    if (created) await ch().chCommand(`DROP USER IF EXISTS ${user}`);
  };
  try {
    created = true;
    await ch().chCommand(`CREATE USER ${user} IDENTIFIED WITH plaintext_password BY '${password}'`);
    await ch().chCommand(`ALTER USER ${user} SETTINGS ${settings}`);
    for (const grant of grants) await ch().chCommand(`GRANT ${grant} TO ${user}`);
    for (const sql of policies) await ch().chCommand(sql);
  } catch (err) {
    await cleanup();
    throw err;
  }
  return cleanup;
}

/** Запрос от имени пользователя RO, без настроек (readonly = 1 их не принимает). */
export async function queryAs<T>(user: string, password: string, sql: string, params: Record<string, string> = {}): Promise<T[]> {
  const url = new URL(process.env.ARGUS_TEST_CLICKHOUSE_URL!);
  url.searchParams.set("database", "argus");
  url.searchParams.set("default_format", "JSONEachRow");
  for (const [k, v] of Object.entries(params)) url.searchParams.set(`param_${k}`, v);
  const response = await fetch(url, {
    method: "POST", body: sql,
    headers: { Authorization: "Basic " + Buffer.from(`${user}:${password}`).toString("base64"), "Content-Type": "text/plain" },
    signal: AbortSignal.timeout(25_000),
  });
  const text = await response.text();
  assert.equal(response.status, 200, `${user}: ${text.slice(0, 300)}`);
  return text.split("\n").filter(Boolean).map((line) => JSON.parse(line) as T);
}
