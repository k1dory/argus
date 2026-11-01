// PR #74, изменения из main: новый диапазон начинает все списки инцидентов
// с первой страницы, включая группы сканов (gpage) и раскрытую подсеть (spage).
// Вызываем настоящие обработчики компонентов; моки хуков — как в тесте #77.
import Module from "node:module";
import { test } from "node:test";
import assert from "node:assert/strict";
import type React from "react";
import { clampPage } from "../src/lib/shared/limits";
import { INCIDENT_RANGE_FIELDS } from "../src/lib/shared/page-filters";

/* eslint-disable @typescript-eslint/no-require-imports -- хуки подменяются до загрузки компонентов */
const realReact = require(require.resolve("react").replace(/index\.js$/, "cjs/react.development.js")) as typeof import("react");
const cache = (Module as unknown as { _cache: Record<string, Module> })._cache;
let current = new URLSearchParams();
let draft: Record<string, string> = {};
let destination = "";

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
    return [value && typeof value === "object" ? { ...value, ...draft } : value, () => undefined];
  },
  useTransition: () => [false, (work: () => void) => work()],
});
inject("next/navigation", {
  useSearchParams: () => current,
  usePathname: () => "/incidents",
  useRouter: () => ({ push: (href: string) => { destination = href; } }),
});
const { RangeFilters } = require("../src/components/console/range-filters") as typeof import("../src/components/console/range-filters");
const { RangePicker } = require("../src/components/console/range-picker") as typeof import("../src/components/console/range-picker");
/* eslint-enable @typescript-eslint/no-require-imports */

type ClickProps = { children?: React.ReactNode; onClick?: () => void };
type Form = React.ReactElement<{ children?: React.ReactNode; onSubmit: (event: { preventDefault: () => void }) => void }>;

function click(tree: React.ReactElement<{ children?: React.ReactNode }>, label: string): void {
  const button = realReact.Children.toArray(tree.props.children).find((child) =>
    realReact.isValidElement<ClickProps>(child) && realReact.Children.toArray(child.props.children).includes(label));
  assert.ok(realReact.isValidElement<ClickProps>(button), `кнопка «${label}» должна существовать`);
  assert.equal(typeof button.props.onClick, "function");
  button.props.onClick!();
}

for (const pagedGroups of [false, true]) {
  for (const action of ["preset", "apply", "reset"] as const) {
    test(`инциденты: ${action}, ${pagedGroups ? "группы и подсеть на следующих страницах" : "контроль обычной пагинации"}`, () => {
      current = new URLSearchParams({
        queue: "open", page: "4", range: "30d", events_min: "10",
      });
      if (pagedGroups) {
        current.set("gpage", "3");
        current.set("spage", "2");
        current.set("subnet", "203.0.113.0/24");
      }
      draft = action === "apply" ? { from: "2026-10-01T00:00", to: "2026-10-02T00:00", events_min: "20" } : {};
      destination = "";
      if (action === "preset") {
        click(RangePicker({ value: "30d", keys: ["24h", "7d", "30d"] }), "24 часа");
      } else {
        const wrapper = RangeFilters({ time: true, fields: INCIDENT_RANGE_FIELDS });
        const render = wrapper.type as (props: typeof wrapper.props) => Form;
        const form = render(wrapper.props);
        if (action === "apply") form.props.onSubmit({ preventDefault: () => undefined });
        else click(form, "сбросить диапазоны");
      }

      assert.ok(destination, "обработчик должен вызвать router.push");
      const next = new URL(destination, "http://fixture.invalid").searchParams;
      assert.equal(next.get("queue"), "open", "очередь сохраняется");
      if (action === "preset") {
        assert.equal(next.get("range"), "24h");
        assert.equal(next.get("events_min"), "10");
      } else if (action === "apply") {
        assert.equal(next.get("from"), draft.from);
        assert.equal(next.get("events_min"), "20");
      } else {
        assert.equal(next.has("events_min"), false);
      }
      // scanGroups/scanGroupIncidents используют эти страницы для OFFSET без
      // коррекции по размеру новой выборки. Старый OFFSET даёт ложное «сканов нет».
      assert.deepEqual(["page", "gpage", "spage"].map((key) => clampPage(next.get(key))), [1, 1, 1],
        "смена диапазона должна сбрасывать страницы очереди, групп и раскрытой подсети");
    });
  }
}
