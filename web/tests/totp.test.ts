import { test } from "node:test";
import assert from "node:assert/strict";
import crypto from "node:crypto";
import { generateTotpSecret, verifyTotp, otpauthUri } from "../src/lib/totp";

function b32d(s: string): Buffer {
  const A = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";
  let bits = 0, v = 0; const out: number[] = [];
  for (const c of s) { v = (v << 5) | A.indexOf(c); bits += 5; if (bits >= 8) { out.push((v >>> (bits - 8)) & 255); bits -= 8; } }
  return Buffer.from(out);
}

test("TOTP: секрет base32, код совпадает с независимой реализацией RFC 6238", () => {
  const secret = generateTotpSecret();
  assert.match(secret, /^[A-Z2-7]{32}$/);
  const c = Math.floor(Date.now() / 30000);
  const m = Buffer.alloc(8); m.writeBigUInt64BE(BigInt(c));
  const mac = crypto.createHmac("sha1", b32d(secret)).update(m).digest();
  const o = mac[19] & 15;
  const code = String((((mac[o] & 127) << 24) | (mac[o + 1] << 16) | (mac[o + 2] << 8) | mac[o + 3]) % 1e6).padStart(6, "0");
  assert.equal(verifyTotp(secret, code), true);
  assert.equal(verifyTotp(secret, "000001"), false);
  assert.equal(verifyTotp(secret, "12345"), false);
  assert.ok(otpauthUri("admin", "ARGUS SIEM", secret).startsWith("otpauth://totp/ARGUS%20SIEM%3Aadmin?"));
});
