#!/usr/bin/env node
/* eslint-disable @typescript-eslint/no-require-imports -- standalone CommonJS recovery script */
// Офлайн-восстановление встроенного admin. Запускайте при остановленном web,
// чтобы его кэш auth.json не перезаписал сброс. Пароль выводится только в файл.
const fs = require("node:fs");
const path = require("node:path");
const crypto = require("node:crypto");
const bcrypt = require("bcryptjs");

process.umask(0o077);
const authFile = path.resolve(process.env.AUTH_FILE || "/data/auth.json");
const passwordFile = path.join(path.dirname(authFile), "admin-password.txt");

function password() {
  const upper = "ABCDEFGHJKMNPQRSTUVWXYZ";
  const lower = "abcdefghjkmnpqrstuvwxyz";
  const digits = "23456789";
  const symbols = ".*+?-";
  const all = upper + lower + digits + symbols;
  const pick = (set) => set[crypto.randomInt(set.length)];
  const chars = [pick(upper), pick(lower), pick(digits), pick(symbols), ...Array.from({ length: 12 }, () => pick(all))];
  for (let i = chars.length - 1; i > 0; i--) {
    const j = crypto.randomInt(i + 1);
    [chars[i], chars[j]] = [chars[j], chars[i]];
  }
  return chars.join("");
}

function syncedFile(file, data) {
  const fd = fs.openSync(file, "wx", 0o600);
  try {
    fs.writeFileSync(fd, data);
    fs.fsyncSync(fd);
  } finally {
    fs.closeSync(fd);
  }
}

async function main() {
  const state = JSON.parse(fs.readFileSync(authFile, "utf8"));
  if (state.user !== "admin" || !state.passwordHash || !state.sessionSecret) {
    throw new Error("Некорректный auth.json: пароль не изменён");
  }
  const nextPassword = password();
  const next = {
    ...state,
    passwordHash: await bcrypt.hash(nextPassword, 12),
    passwordChanged: false,
    tokenVersion: (state.tokenVersion || 0) + 1,
  };
  const suffix = `${process.pid}.${crypto.randomBytes(4).toString("hex")}.tmp`;
  const authTmp = `${authFile}.${suffix}`;
  const passwordTmp = `${passwordFile}.${suffix}`;
  try {
    syncedFile(authTmp, JSON.stringify(next, null, 2));
    syncedFile(passwordTmp, nextPassword + "\n");
    fs.renameSync(authTmp, authFile);
    fs.renameSync(passwordTmp, passwordFile);
    const dir = fs.openSync(path.dirname(authFile), "r");
    try { fs.fsyncSync(dir); } finally { fs.closeSync(dir); }
  } finally {
    for (const file of [authTmp, passwordTmp]) {
      try { fs.unlinkSync(file); } catch (error) { if (error.code !== "ENOENT") throw error; }
    }
  }
  console.log(`Пароль admin сброшен. Новый пароль в ${passwordFile}; после входа смените его в настройках.`);
}

main().catch((error) => {
  console.error(`Сброс не выполнен: ${error.message}`);
  process.exitCode = 1;
});
