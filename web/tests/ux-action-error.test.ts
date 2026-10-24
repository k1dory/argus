import { test } from "node:test";
import assert from "node:assert/strict";
import { ACTION_FAILED, ACTION_FAILED_LOGGED, ACTION_FORBIDDEN, actionErrorText, isNavigationDigest } from "../src/lib/shared/action-error";

const withDigest = (digest: string, message = "внутренности") => Object.assign(new Error(message), { digest });

test("ошибка без digest показывает своё сообщение", () => {
  assert.equal(actionErrorText(new Error("Wazuh API недоступен")), "Wazuh API недоступен");
  assert.equal(actionErrorText(new Error("")), ACTION_FAILED);
  assert.equal(actionErrorText("строка"), ACTION_FAILED);
  assert.equal(actionErrorText(null), ACTION_FAILED);
});

test("FORBIDDEN → «недостаточно прав»", () => {
  assert.equal(actionErrorText(withDigest("FORBIDDEN")), ACTION_FORBIDDEN);
});

test("навигационные исключения Next → пустая строка (пробросить)", () => {
  assert.equal(actionErrorText(withDigest("NEXT_REDIRECT;replace;/settings;307;")), "");
  assert.equal(actionErrorText(withDigest("NEXT_NOT_FOUND")), "");
  assert.equal(actionErrorText(withDigest("NEXT_HTTP_ERROR_FALLBACK;404")), "");
  assert.ok(isNavigationDigest("NEXT_REDIRECT;push;/;307;"));
  assert.ok(!isNavigationDigest("1234567890"));
});

test("серверный digest (текст вырезан Next) → отсылка в журнал, не e.message", () => {
  const msg = actionErrorText(withDigest("2147483647", "An error occurred in the Server Components render"));
  assert.equal(msg, ACTION_FAILED_LOGGED);
  assert.ok(!msg.includes("Server Components"));
  // пустой digest — как без него
  assert.equal(actionErrorText(withDigest("", "Ошибка ClickHouse")), "Ошибка ClickHouse");
});
