import { test } from "node:test";
import assert from "node:assert/strict";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { spawnSync } from "node:child_process";
import bcrypt from "bcryptjs";

test("офлайн-сброс admin сохраняет пользователей и 2FA, отзывает сессии и выдаёт новый пароль в файл", async () => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), "argus-recovery-"));
  try {
    const authFile = path.join(dir, "auth.json");
    const before = {
      user: "admin", passwordHash: await bcrypt.hash("OldPassw0rd.", 4),
      sessionSecret: "session-secret", generatedAt: "2025-01-01T00:00:00Z",
      passwordChanged: true, tokenVersion: 3, totpSecret: "KEEP-TOTP",
      users: [{ name: "analyst", passwordHash: "KEEP-HASH", role: "analyst" }],
    };
    fs.writeFileSync(authFile, JSON.stringify(before), { mode: 0o600 });
    const run = spawnSync(process.execPath, [path.resolve(__dirname, "../scripts/reset-admin-password.cjs")], {
      env: { ...process.env, AUTH_FILE: authFile }, encoding: "utf8",
    });
    assert.equal(run.status, 0, run.stderr);
    const after = JSON.parse(fs.readFileSync(authFile, "utf8"));
    const passwordFile = path.join(dir, "admin-password.txt");
    const newPassword = fs.readFileSync(passwordFile, "utf8").trim();
    assert.equal(await bcrypt.compare(newPassword, after.passwordHash), true);
    assert.equal(after.passwordChanged, false);
    assert.equal(after.tokenVersion, 4);
    assert.equal(after.sessionSecret, before.sessionSecret);
    assert.equal(after.totpSecret, before.totpSecret);
    assert.deepEqual(after.users, before.users);
    assert.equal(fs.statSync(passwordFile).mode & 0o777, 0o600);
    assert.ok(!run.stdout.includes(newPassword), "пароль не попадает в вывод команды");
  } finally {
    fs.rmSync(dir, { recursive: true, force: true });
  }
});
