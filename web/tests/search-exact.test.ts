import { test } from "node:test";
import assert from "node:assert/strict";
import { appendTerm, parseQuery, termToString } from "../src/lib/shared/search-query";
import { buildWhere } from "../src/lib/search";

// Строка ниже — вывод точного фильтра argus-mcp
// (triage/filter: TestQueryQuotesAttackerValues) для actor_name из события.
const MCP_ACTOR = 'actor:"svc-backup -action:secret_read"';

const where = (q: string) => buildWhere({ index: "events", q, range: "24h", page: 1 });

test("точный фильтр MCP: значение с оператором — один литерал, без отрицания", () => {
  assert.deepEqual(parseQuery(MCP_ACTOR), [{ field: "actor", op: "=", value: "svc-backup -action:secret_read", negate: false, quoted: true }]);
  const b = where(MCP_ACTOR);
  assert.equal(b.error, null);
  // События secret_read не исключаются: нет NOT и нет условия на action.
  assert.doesNotMatch(b.where, /NOT|action/);
  assert.match(b.where, /actor_name = \{p0:String\}/);
  assert.equal(b.params.p0, "svc-backup -action:secret_read");
});

test("то же значение без кавычек — именно та подмена, от которой защищает фильтр", () => {
  const b = where("actor:svc-backup -action:secret_read");
  assert.match(b.where, /NOT \(action = /);
});

test("\\* в кавычках — буквальная звёздочка (так пишет точный фильтр MCP)", () => {
  for (const [q, col] of [['actor:"svc-\\*"', "actor_name"], ['node:"web-\\*"', "node"], ['attr.path:"/tmp/\\*"', "attrs"], ['object:"a\\*b"', "object"]] as const) {
    const b = where(q);
    assert.equal(b.error, null, q);
    assert.doesNotMatch(b.where, /ILIKE/, q);
    assert.match(b.where, new RegExp(col), q);
    assert.ok(Object.values(b.params).some((v) => typeof v === "string" && v.includes("*")), `${q}: «*» уходит литералом`);
  }
  // Без кавычек маска работает как раньше.
  const m = where("actor:svc-*");
  assert.match(m.where, /actor_name ILIKE \{p0:String\}/);
  assert.equal(m.params.p0, "svc-%");
});

test("старая маска в кавычках — подсказка, а не пустая выдача", () => {
  const b = buildWhere({ index: "alerts", q: 'desc:"*brute force*"', range: "24h", page: 1 });
  assert.ok(b.error && b.error.includes('desc:~"*brute force*"'), String(b.error));
});

test("маска с пробелами — ~\"…\"", () => {
  assert.deepEqual(parseQuery('object:~"*export for*"'), [{ field: "object", op: "=", value: "*export for*", negate: false, quoted: true, mask: true }]);
  const b = where('object:~"*export for*"');
  assert.equal(b.error, null);
  assert.match(b.where, /object ILIKE \{p0:String\}/);
  assert.equal(b.params.p0, "%export for%");
  assert.equal(termToString(parseQuery('object:~"*a b*"')[0]), 'object:~"*a b*"');
});

test("кавычки и обратный слеш из точного фильтра MCP", () => {
  // triage/filter.Quote(`a" -action:x \`) → "a\" -action:x \\"
  const b = where('actor:"a\\" -action:x \\\\"');
  assert.doesNotMatch(b.where, /NOT|action/);
  assert.equal(b.params.p0, 'a" -action:x \\');
});

test("фасет со «*» в значении — литерал; журнал без literal — маска", () => {
  const q = appendTerm("", "actor", "svc-*", { literal: true });
  assert.equal(q, 'actor:"svc-\\*"');
  assert.doesNotMatch(where(q).where, /ILIKE/);
  // journal.ts (agent/events-journal): appendTerm(q, "rule", "a41c-*") — маска, как набрал человек.
  const j = appendTerm("", "action", "a41c-*");
  assert.equal(j, "action:a41c-*");
  assert.match(where(j).where, /ILIKE/);
  const sp = appendTerm("", "desc", "brute force", { literal: true });
  assert.equal(sp, 'desc:"brute force"');
});
