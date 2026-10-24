import { test } from "node:test";
import assert from "node:assert/strict";
import { appendTerm, parseQuery, termToString } from "../src/lib/shared/search-query";

test("свободный текст и поля", () => {
  assert.deepEqual(parseQuery("root 203.0.113.5 agent:web-01"), [
    { field: null, op: "=", value: "root", negate: false },
    { field: null, op: "=", value: "203.0.113.5", negate: false },
    { field: "agent", op: "=", value: "web-01", negate: false },
  ]);
});

test("сравнения, отрицание, кавычки, маска", () => {
  assert.deepEqual(parseQuery('level:>=10 -group:syscheck group!=sca desc:"brute force" srcip:10.0.*'), [
    { field: "level", op: ">=", value: "10", negate: false },
    { field: "group", op: "=", value: "syscheck", negate: true },
    { field: "group", op: "!=", value: "sca", negate: false },
    { field: "desc", op: "=", value: "brute force", negate: false, quoted: true },
    { field: "srcip", op: "=", value: "10.0.*", negate: false },
  ]);
  assert.deepEqual(parseQuery("level>=10 sport<=1024 level:=5"), [
    { field: "level", op: ">=", value: "10", negate: false },
    { field: "sport", op: "<=", value: "1024", negate: false },
    { field: "level", op: "=", value: "5", negate: false },
  ]);
});

test("граничные случаи: пустые значения, незакрытая кавычка, дефисы, IPv6, регистр", () => {
  assert.deepEqual(parseQuery('"Failed password" agent: level:'), [{ field: null, op: "=", value: "Failed password", negate: false, quoted: true }]);
  assert.deepEqual(parseQuery('desc:"unterminated phrase'), [{ field: "desc", op: "=", value: "unterminated phrase", negate: false, quoted: true }]);
  assert.deepEqual(parseQuery("node:web-01 from:2026-09-13 src:fe80::1 -"), [
    { field: "node", op: "=", value: "web-01", negate: false },
    { field: "from", op: "=", value: "2026-09-13", negate: false },
    { field: "src", op: "=", value: "fe80::1", negate: false },
    { field: null, op: "=", value: "-", negate: false },
  ]);
  assert.deepEqual(parseQuery("Agent:X attr.filePath:/etc/passwd ATTR.cs1Label:y"), [
    { field: "agent", op: "=", value: "X", negate: false },
    { field: "attr.filePath", op: "=", value: "/etc/passwd", negate: false },
    { field: "attr.cs1Label", op: "=", value: "y", negate: false },
  ]);
  assert.deepEqual(parseQuery('desc:"say \\"hi\\" now"'), [{ field: "desc", op: "=", value: 'say "hi" now', negate: false, quoted: true }]);
});

test("термин обратно в строку: операторы и кавычки в значениях фасетов", () => {
  assert.equal(termToString({ field: "desc", op: "=", value: "brute force", negate: false }), 'desc:"brute force"');
  assert.equal(termToString({ field: "level", op: ">=", value: "10", negate: true }), "-level>=:10");
  for (const v of ["<unknown>", ">=5", "-x", 'a "b" c', "!=z", "=cmd"]) {
    const back = parseQuery(termToString({ field: "actor", op: "=", value: v, negate: false }));
    assert.deepEqual(back, [{ field: "actor", op: "=", value: v, negate: false, quoted: true }], v);
  }
});

test("добавление фасета без дублей, в том числе с пробелами", () => {
  assert.equal(appendTerm("root", "agent", "web-01"), "root agent:web-01");
  assert.equal(appendTerm("root agent:web-01", "agent", "web-01"), "root agent:web-01");
  const q = appendTerm("root", "desc", "brute force");
  assert.equal(q, 'root desc:"brute force"');
  assert.equal(appendTerm(q, "desc", "brute force"), q);
});
