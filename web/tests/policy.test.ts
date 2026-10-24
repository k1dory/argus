import { test } from "node:test";
import assert from "node:assert/strict";
import { validatePasswordPolicy } from "../src/lib/auth";

test("парольная политика как у wazuh-passwords-tool", () => {
  assert.equal(validatePasswordPolicy("Abcdefg1."), null);
  assert.match(validatePasswordPolicy("short1.") ?? "", /8 до 64/);
  assert.match(validatePasswordPolicy("abcdefgh1.") ?? "", /заглавная/);
  assert.match(validatePasswordPolicy("ABCDEFGH1.") ?? "", /строчная/);
  assert.match(validatePasswordPolicy("Abcdefghi.") ?? "", /цифра/);
  assert.match(validatePasswordPolicy("Abcdefgh1") ?? "", /символ/);
});
