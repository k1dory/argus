// PR #51: предупреждение о малой выборке нужно и у крупных итоговых процентов.
// Проверяем именно каждую плитку: предупреждение в таблице ниже её не заменяет.
import { test } from "node:test";
import assert from "node:assert/strict";
import { installNextMocks, loadAuth } from "./_next-mock";
import { pageText } from "./_render";
import type { AgreementSqlRow } from "../src/lib/shared/blind-metrics";

installNextMocks();
const auth = loadAuth();
/* eslint-disable @typescript-eslint/no-require-imports -- Next mocks до страницы */
const page = require("../src/app/(console)/rules/agreement/page") as {
  default: (props: { searchParams: Promise<Record<string, string>> }) => Promise<unknown>;
};
const { StatTile } = require("../src/components/console/panel") as typeof import("../src/components/console/panel");
/* eslint-enable @typescript-eslint/no-require-imports */

type Element = { type: unknown; props: { children?: unknown; label?: string } };
function statTiles(node: unknown): Element[] {
  if (Array.isArray(node)) return node.flatMap(statTiles);
  if (node === null || typeof node !== "object" || !("type" in node) || !("props" in node)) return [];
  const element = node as Element;
  return element.type === StatTile ? [element] : statTiles(element.props.children);
}

test("agreement: итоговые доли с n < 20 помечены как мало данных", async (t) => {
  const rows: AgreementSqlRow[] = [true, false].map((blind) => ({
    rule_id: "review-small-sample", rule_title: "Review fixture", blind,
    labeled: 1, fp: 1, compared: 1, agreed: 1, undetermined: 0, no_verdict: 0,
  }));
  t.mock.method(globalThis, "fetch", async () => new Response(rows.map((r) => JSON.stringify(r)).join("\n")));
  await auth.createSession("sso:agreement-review-small-sample", "analyst", true);
  const tree = await page.default({ searchParams: Promise.resolve({}) });
  const tiles = statTiles(tree);
  const missing: string[] = [];
  for (const label of ["Согласие · слепые", "Согласие · неслепые", "Ложных срабатываний"]) {
    const tile = tiles.find((element) => element.props.label === label);
    assert.ok(tile, label);
    const text = await pageText(tile);
    assert.match(text, /100\s*%/, "контроль: итоговая доля действительно отрисована");
    if (!/мало данных/i.test(text)) missing.push(label);
  }
  assert.deepEqual(missing, [], "каждая доля при n=1 или n=2 требует собственной пометки");
});
