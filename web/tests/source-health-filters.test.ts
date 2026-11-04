// Exercise the actual component handlers with deterministic hooks. Page rendering
// and row selection are covered separately by source-filter-zero-regression.
import Module from "node:module";
import { beforeEach, test } from "node:test";
import assert from "node:assert/strict";
import type React from "react";
import { parseSourceRanges } from "../src/lib/shared/page-filters";

/* eslint-disable @typescript-eslint/no-require-imports -- install hooks before importing the client component */
const realReact = require(require.resolve("react").replace(/index\.js$/, "cjs/react.development.js")) as typeof import("react");
const cache = (Module as unknown as { _cache: Record<string, Module> })._cache;
let params = new URLSearchParams();
let states: unknown[] = [];
let cursor = 0;
let pending = false;
let pushed: { href: string; options: { scroll: boolean } }[] = [];

function inject(id: string, exports: object) {
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
    const index = cursor++;
    if (!(index in states)) states[index] = typeof initial === "function" ? initial() : initial;
    return [states[index], (next: unknown) => {
      states[index] = typeof next === "function" ? next(states[index]) : next;
    }];
  },
  useRef: () => ({ current: null }),
  useTransition: () => [pending, (work: () => void) => work()],
});
inject("next/navigation", {
  useSearchParams: () => params,
  usePathname: () => "/sources",
  useRouter: () => ({ push: (href: string, options: { scroll: boolean }) => pushed.push({ href, options }) }),
});
const { SourceHealthFilters } = require("../src/components/console/source-health-filters") as typeof import("../src/components/console/source-health-filters");
/* eslint-enable @typescript-eslint/no-require-imports */

type Props = {
  children?: React.ReactNode; id?: string; hidden?: boolean; value?: string;
  disabled?: boolean; "aria-controls"?: string; "aria-label"?: string; "aria-labelledby"?: string;
  onClick?: () => void;
  onValueChange?: (value: string) => void;
  onChange?: (event: { target: { value: string } }) => void;
  onSubmit?: (event: { preventDefault: () => void }) => void;
  onKeyDown?: (event: { key: string; preventDefault: () => void }) => void;
};
type Element = React.ReactElement<Props>;

function render(): Element {
  cursor = 0;
  const wrapper = SourceHealthFilters({ shown: 3, total: 10, ranges: parseSourceRanges(params, Date.parse("2026-11-03T09:00:00Z")) });
  return (wrapper.type as (props: typeof wrapper.props) => Element)(wrapper.props);
}
function nodes(node: React.ReactNode): Element[] {
  return realReact.Children.toArray(node).flatMap((child) => realReact.isValidElement<Props>(child)
    ? [child, ...nodes(child.props.children)] : []);
}
function find(predicate: (element: Element) => boolean): Element {
  const element = nodes(render()).find(predicate);
  assert.ok(element, "control exists in the actual component");
  return element;
}
const labelled = (text: string) => find((element) => realReact.Children.toArray(element.props.children).includes(text));
const input = (id: string) => find((element) => element.props.id === `src-health-${id}`);
const toggle = () => find((element) => element.props["aria-controls"] === "src-health-conditions");
const activity = () => find((element) => element.props["aria-labelledby"] === "src-health-activity-label");
const form = () => find((element) => element.type === "form");
const panel = () => find((element) => element.props.id === "src-health-conditions");
function destination(): URLSearchParams {
  assert.equal(pushed.length, 1);
  assert.deepEqual(pushed[0].options, { scroll: false }, "filtering keeps the current scroll position");
  const next = new URL(pushed[0].href, "https://fixture.invalid").searchParams;
  for (const key of ["page", "gpage", "spage"]) assert.equal(next.has(key), false);
  for (const [key, value] of Object.entries(feed)) assert.equal(next.get(key), value, `${key} belongs to the feed`);
  return next;
}
const feed = { source: "collector.s3", range: "7d", level_min: "4", from: "2026-11-01T00:00", to: "2026-11-02T12:00" };
beforeEach(() => {
  params = new URLSearchParams({ ...feed, page: "4", gpage: "3", spage: "2", eps_max: "0" });
  states = [];
  pushed = [];
  pending = false;
});

for (const [selected, expected] of [["empty", { events_max: "0" }], ["active", { events_min: "1" }], ["all", {}]] as const) {
  test(`activity ${selected}: changes only the hourly event range`, () => {
    params.set("events_min", "10");
    params.set("events_max", "20");
    params.set("seen_from", "2026-11-01T05:00");
    activity().props.onValueChange!(selected);
    const next = destination();
    assert.equal(next.get("eps_max"), "0");
    assert.equal(next.get("seen_from"), "2026-11-01T05:00");
    assert.deepEqual(Object.fromEntries([...next].filter(([key]) => key.startsWith("events_"))), expected);
  });
}

test("activity reflects zero, nonzero and custom ranges from the URL", () => {
  assert.equal(activity().props.value, "all");
  params.set("events_max", "0");
  assert.equal(activity().props.value, "empty");
  params.delete("events_max");
  params.set("events_min", "1");
  assert.equal(activity().props.value, "active");
  params.set("events_min", "100");
  assert.equal(activity().props.value, "", "a custom range must not look like All");
  activity().props.onValueChange!("");
  assert.deepEqual(pushed, [], "clicking the selected choice does not clear it");
});

for (const dismiss of ["cancel", "escape", "toggle"] as const) {
  test(`${dismiss}: discards edits without changing the URL`, () => {
    assert.equal(panel().props.hidden, true);
    toggle().props.onClick!();
    assert.equal(panel().props.hidden, false);
    input("eps-max").props.onChange!({ target: { value: "12.5" } });
    assert.equal(input("eps-max").props.value, "12.5");
    if (dismiss === "cancel") labelled("Отмена").props.onClick!();
    if (dismiss === "escape") form().props.onKeyDown!({ key: "Escape", preventDefault() {} });
    if (dismiss === "toggle") toggle().props.onClick!();
    assert.equal(panel().props.hidden, true);
    toggle().props.onClick!();
    assert.equal(input("eps-max").props.value, "0");
    assert.deepEqual(pushed, []);
  });
}

test("apply: zero and UTC dates survive, empty bounds clear, feed remains intact", () => {
  toggle().props.onClick!();
  input("events-max").props.onChange!({ target: { value: "0" } });
  input("eps-max").props.onChange!({ target: { value: "" } });
  input("seen-from").props.onChange!({ target: { value: "2026-11-01T05:00" } });
  input("seen-to").props.onChange!({ target: { value: "2026-11-02T05:00" } });
  assert.deepEqual(pushed, [], "editing does not apply the draft");
  form().props.onSubmit!({ preventDefault() {} });
  const next = destination();
  assert.equal(next.get("events_max"), "0");
  assert.equal(next.has("eps_max"), false);
  assert.equal(next.get("seen_from"), "2026-11-01T05:00");
  assert.equal(next.get("seen_to"), "2026-11-02T05:00");
  assert.equal(panel().props.hidden, true);
});

test("remove a time chip: clears both seen bounds, preserves feed dates and numeric filters", () => {
  params.set("seen_from", "2026-11-01T05:00");
  params.set("seen_to", "2026-11-02T05:00");
  params.set("events_max", "0");
  find((element) => element.props["aria-label"]?.startsWith("Убрать условие: последний приём:") === true).props.onClick!();
  const next = destination();
  assert.equal(next.has("seen_from"), false);
  assert.equal(next.has("seen_to"), false);
  assert.equal(next.get("events_max"), "0");
  assert.equal(next.get("eps_max"), "0");
});

test("reset all: clears only collector conditions", () => {
  params.set("seen_from", "2026-11-01T05:00");
  params.set("events_max", "0");
  labelled("Сбросить всё").props.onClick!();
  const next = destination();
  assert.deepEqual(Object.fromEntries(next), feed);
});

test("pending navigation: controls disabled and a second navigation is ignored", () => {
  pending = true;
  assert.equal(toggle().props.disabled, true);
  assert.equal(activity().props.disabled, true);
  assert.equal(labelled("Сбросить всё").props.disabled, true);
  activity().props.onValueChange!("empty");
  form().props.onSubmit!({ preventDefault() {} });
  assert.deepEqual(pushed, []);
});
