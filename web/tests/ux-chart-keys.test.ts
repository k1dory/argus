import { test } from "node:test";
import assert from "node:assert/strict";
import { chartStyleCss, isSafeChartColor, isSafeChartKey, seriesSlug } from "../src/lib/shared/chart-css";

test("слаги серий — только [A-Za-z0-9_-]", () => {
  for (let i = 0; i < 20; i++) assert.match(seriesSlug(i), /^[A-Za-z0-9_-]+$/);
  assert.equal(seriesSlug(0), "s0");
  assert.equal(seriesSlug(11), "s11");
});

test("isSafeChartKey отбрасывает всё, что может закрыть <style>", () => {
  assert.equal(isSafeChartKey("low"), true);
  assert.equal(isSafeChartKey("s0"), true);
  assert.equal(isSafeChartKey("source_class-1"), true);
  assert.equal(isSafeChartKey("</style><script>alert(1)</script>"), false);
  assert.equal(isSafeChartKey("a b"), false);
  assert.equal(isSafeChartKey("a;b"), false);
  assert.equal(isSafeChartKey("}"), false);
  assert.equal(isSafeChartKey(""), false);
  assert.equal(isSafeChartKey("x".repeat(65)), false);
});

test("isSafeChartColor: токены и hex, ничего исполняемого", () => {
  assert.equal(isSafeChartColor("var(--chart-1)"), true);
  assert.equal(isSafeChartColor("#ff8800"), true);
  assert.equal(isSafeChartColor("#a6a6a6"), true);
  assert.equal(isSafeChartColor("red"), true);
  assert.equal(isSafeChartColor("url(javascript:alert(1))"), false);
  assert.equal(isSafeChartColor("red; } </style>"), false);
  assert.equal(isSafeChartColor("var(--x); background: url(x)"), false);
});

test("chartStyleCss: пользовательские ключи не попадают в CSS", () => {
  const evil = "</style><script>alert(1)</script>";
  const css = chartStyleCss("chart-r1", {
    s0: { color: "var(--chart-3)" },
    [evil]: { color: "var(--chart-2)" },
    s1: { color: "red; } </style>" },
  });
  assert.ok(!css.includes("</style>"));
  assert.ok(!css.includes("<script"));
  assert.ok(css.includes("--color-s0: var(--chart-3);"));
  assert.ok(!css.includes("--color-s1"));
  assert.match(css, /^\[data-chart=chart-r1\] \{\n/);
});

test("chartStyleCss: плохой id контейнера или пустой конфиг → пустая строка", () => {
  assert.equal(chartStyleCss("x]{", { s0: { color: "red" } }), "");
  assert.equal(chartStyleCss("chart-1", {}), "");
  assert.equal(chartStyleCss("chart-1", { s0: {} }), "");
});
