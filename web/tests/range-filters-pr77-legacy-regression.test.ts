// PR #77: применение только времени не должно снимать прежний level=.
// Вызываем настоящий onSubmit RangeFilters с детерминированными хуками;
// значения формы и router.push перехватываются без браузера и сети.
import Module from "node:module";
import { test } from "node:test";
import assert from "node:assert/strict";
import type React from "react";
import { INCIDENT_LEVELS, parseOrdinalRange } from "../src/lib/shared/filters";
import { ALERT_LEVEL_FIELD, INCIDENT_RANGE_FIELDS, parseAlertRanges } from "../src/lib/shared/page-filters";

/* eslint-disable @typescript-eslint/no-require-imports -- подмена хуков до загрузки клиентского компонента */
const realReact = require("react") as typeof import("react");
const cache = (Module as unknown as { _cache: Record<string, Module> })._cache;
let current = new URLSearchParams();
let pathname = "";
let destination = "";
const draftTime = { from: "2026-10-01T00:00", to: "2026-10-21T00:00" };

function inject(id: string, exports: object): void {
  const filename = require.resolve(id);
  const replacement = new Module(filename);
  replacement.filename = filename;
  replacement.loaded = true;
  replacement.exports = exports;
  cache[filename] = replacement;
}

inject("react", {
  ...realReact,
  useState: (initial: unknown) => {
    const value = typeof initial === "function" ? (initial as () => unknown)() : initial;
    // Пользователь меняет только даты; остальные значения берутся из формы.
    return [{ ...(value as Record<string, string>), ...draftTime }, () => undefined];
  },
  useTransition: () => [false, (work: () => void) => work()],
});
inject("next/navigation", {
  useSearchParams: () => current,
  usePathname: () => pathname,
  useRouter: () => ({ push: (href: string) => { destination = href; } }),
});
const { RangeFilters } = require("../src/components/console/range-filters") as typeof import("../src/components/console/range-filters");
/* eslint-enable @typescript-eslint/no-require-imports */

type SubmitForm = React.ReactElement<{ onSubmit: (event: { preventDefault: () => void }) => void }>;

for (const scenario of [
  { path: "/wazuh/alerts", level: "12", fields: [ALERT_LEVEL_FIELD] },
  { path: "/incidents", level: "high", fields: [INCIDENT_RANGE_FIELDS[0]] },
]) {
  test(`${scenario.path}: выбор from/to сохраняет старый level=${scenario.level}`, () => {
    pathname = scenario.path;
    current = new URLSearchParams({ level: scenario.level, q: "fixture", page: "3" });
    destination = "";
    const wrapper = RangeFilters({ time: true, fields: scenario.fields, legacy: ["level"] });
    const renderForm = wrapper.type as (props: typeof wrapper.props) => SubmitForm;
    const form = renderForm(wrapper.props);
    form.props.onSubmit({ preventDefault: () => undefined });
    assert.ok(destination, "настоящий обработчик должен вызвать router.push");
    const next = new URL(destination, "http://fixture.invalid").searchParams;
    assert.equal(next.get("from"), draftTime.from);
    assert.equal(next.get("to"), draftTime.to);
    assert.equal(next.get("q"), "fixture");
    assert.equal(next.has("page"), false);
    if (scenario.path === "/wazuh/alerts") {
      assert.deepEqual(parseAlertRanges(next).level, { min: 12 }, "порог 12 нельзя снимать при изменении только времени");
    } else {
      assert.deepEqual(parseOrdinalRange(next, "level", INCIDENT_LEVELS, "level"), { min: "high", max: "high" },
        "точный high должен сохраниться через legacy level либо эквивалентный диапазон");
    }
  });
}
