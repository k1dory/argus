import { test } from "node:test";
import assert from "node:assert/strict";
import { normalizeSpec, panelSpanMedium, parseDashboardJson, refreshSeconds, SPEC_LIMITS, SpecError } from "../src/lib/shared/dashboard-spec";

const panel = (i: number) => ({ id: `p${i}`, title: `Панель ${i}`, type: "table", sql: "SELECT 1", w: 12, h: 8 });

test("нормализация: значения по умолчанию, клампы, whitelist полей", () => {
  const s = normalizeSpec({ id: "x", title: "  T  ", panels: [{ title: "a", type: "pie", sql: "SELECT 1", w: 99, h: 0, extra: "нет", series: " src ", unit: "" }], evil: 1 }, "my-id");
  assert.equal(s.id, "my-id");
  assert.equal(s.title, "T");
  assert.deepEqual(Object.keys(s).sort(), ["id", "panels", "title"]);
  assert.equal(s.panels.length, 1);
  const p = s.panels[0];
  assert.equal(p.id, "p1");
  assert.equal(p.type, "table");
  assert.equal(p.w, 24);
  assert.equal(p.h, 3);
  assert.equal(p.series, "src");
  assert.equal("unit" in p, false);
  assert.equal("extra" in p, false);
});

test("лимит панелей", () => {
  const ok = normalizeSpec({ panels: Array.from({ length: SPEC_LIMITS.maxPanels }, (_, i) => panel(i)) });
  assert.equal(ok.panels.length, SPEC_LIMITS.maxPanels);
  assert.throws(() => normalizeSpec({ panels: Array.from({ length: SPEC_LIMITS.maxPanels + 1 }, (_, i) => panel(i)) }), SpecError);
});

test("refresh: не чаще 10s, формат Ns", () => {
  assert.equal(normalizeSpec({ refresh: "30s", panels: [] }).refresh, "30s");
  assert.equal(normalizeSpec({ refresh: "", panels: [] }).refresh, undefined);
  assert.throws(() => normalizeSpec({ refresh: "5s", panels: [] }), /не чаще 10s/);
  assert.throws(() => normalizeSpec({ refresh: "1m", panels: [] }), /Автообновление/);
  assert.equal(refreshSeconds({ refresh: "60s" }), 60);
  assert.equal(refreshSeconds({}), 0);
});

test("дубли и мусорные id панелей заменяются", () => {
  const s = normalizeSpec({ panels: [{ id: "a", sql: "x" }, { id: "a", sql: "y" }, { id: "</b>", sql: "z" }] });
  assert.deepEqual(s.panels.map((p) => p.id), ["a", "p2", "p3"]);
});

test("не объект и не массив panels → понятная ошибка", () => {
  assert.throws(() => normalizeSpec(null), /JSON-объектом/);
  assert.throws(() => normalizeSpec([]), /JSON-объектом/);
  assert.throws(() => normalizeSpec({ panels: "x" }), /массивом/);
});

test("parseDashboardJson: битый JSON, размер, лимиты — ошибка строкой, не исключение", () => {
  assert.match(parseDashboardJson("{ не json").error ?? "", /JSON не разбирается/);
  assert.match(parseDashboardJson("[]").error ?? "", /JSON-объектом/);
  const big = JSON.stringify({ panels: [{ sql: "x".repeat(SPEC_LIMITS.maxJsonBytes) }] });
  assert.match(parseDashboardJson(big).error ?? "", /больше 256 КБ/);
  const ok = parseDashboardJson(JSON.stringify({ title: "ok", panels: [panel(1)] }), "id-1");
  assert.equal(ok.error, null);
  assert.equal(ok.spec?.id, "id-1");
  assert.equal(ok.spec?.panels[0].title, "Панель 1");
});

test("слишком длинный SQL панели", () => {
  assert.throws(() => normalizeSpec({ panels: [{ sql: "S".repeat(SPEC_LIMITS.maxSqlLen + 1) }] }), /длиннее/);
});

test("ширина на средних экранах", () => {
  assert.equal(panelSpanMedium(8), 12);
  assert.equal(panelSpanMedium(12), 24);
  assert.equal(panelSpanMedium(24), 24);
});
