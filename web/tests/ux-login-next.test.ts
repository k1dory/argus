import { test } from "node:test";
import assert from "node:assert/strict";
import { safeNextPath } from "../src/lib/shared/next-path";

test("относительные пути консоли принимаются", () => {
  assert.equal(safeNextPath("/incidents/1"), "/incidents/1");
  assert.equal(safeNextPath("/search?q=root&range=7d"), "/search?q=root&range=7d");
  assert.equal(safeNextPath("/"), "/");
});

test("внешние и protocol-relative адреса отклоняются", () => {
  assert.equal(safeNextPath("//evil"), "/");
  assert.equal(safeNextPath("//evil.example/x"), "/");
  assert.equal(safeNextPath("https://x"), "/");
  assert.equal(safeNextPath("http://x/y"), "/");
  assert.equal(safeNextPath("javascript:alert(1)"), "/");
  assert.equal(safeNextPath("/\\evil.example"), "/");
});

test("мусор, пустота, управляющие символы, чужие типы", () => {
  assert.equal(safeNextPath(""), "/");
  assert.equal(safeNextPath(undefined), "/");
  assert.equal(safeNextPath(["/a"]), "/");
  assert.equal(safeNextPath("/a\nb"), "/");
  assert.equal(safeNextPath("/a b"), "/");
  assert.equal(safeNextPath("/" + "x".repeat(3000)), "/");
  assert.equal(safeNextPath("relative"), "/");
});

test("петли на логин и API не допускаются, запасной путь настраивается", () => {
  assert.equal(safeNextPath("/login?next=/x"), "/");
  assert.equal(safeNextPath("/api/search"), "/");
  assert.equal(safeNextPath("//evil", "/incidents"), "/incidents");
});
