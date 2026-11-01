// PR #52: предупреждение должно быть текстом самой плитки, доступным без
// наведения. pageText() включает title/hint и пропускает отсутствие видимого текста.
import { test } from "node:test";
import assert from "node:assert/strict";
import { isValidElement, type ReactElement, type ReactNode } from "react";
import { installNextMocks, loadAuth } from "./_next-mock";
import { html, stripTags } from "./_render";
import type { AgreementSqlRow } from "../src/lib/shared/blind-metrics";

installNextMocks();
const auth = loadAuth();
/* eslint-disable @typescript-eslint/no-require-imports -- Next mocks до страницы */
const page = require("../src/app/(console)/rules/agreement/page") as {
  default: (props: { searchParams: Promise<Record<string, string>> }) => Promise<unknown>;
};
const { StatTile } = require("../src/components/console/panel") as typeof import("../src/components/console/panel");
/* eslint-enable @typescript-eslint/no-require-imports */

type TileProps = { children?: ReactNode; label?: string };
function statTiles(node: unknown): ReactElement<TileProps>[] {
  if (Array.isArray(node)) return node.flatMap(statTiles);
  if (!isValidElement<TileProps>(node)) return [];
  return node.type === StatTile ? [node] : statTiles(node.props.children);
}

// Согласие имеет собственный знаменатель для каждой группы, а доля ложных —
// общий: границы 19/20 проверяются для каждой из трёх плиток независимо.
for (const [blindN, sightedN] of [[1, 1], [9, 10], [10, 10], [19, 20], [20, 20]]) {
  test(`agreement: видимая пометка при n слепых=${blindN}, неслепых=${sightedN}`, async (t) => {
    const rows: AgreementSqlRow[] = [
      { blind: true, n: blindN }, { blind: false, n: sightedN },
    ].map(({ blind, n }) => ({
      rule_id: "pr52-visible-low-data", rule_title: "Review fixture", blind,
      labeled: n, fp: n, compared: n, agreed: n, undetermined: 0, no_verdict: 0,
    }));
    t.mock.method(globalThis, "fetch", async () => new Response(rows.map((row) => JSON.stringify(row)).join("\n")));
    await auth.createSession(`sso:pr52-visible-${blindN}-${sightedN}`, "analyst", true);
    const tree = await page.default({ searchParams: Promise.resolve({}) });
    const tiles = statTiles(tree);
    assert.equal(tiles.length, 4, "контроль: отрисованы все итоговые плитки");

    const proportions = [
      { label: "Согласие · слепые", n: blindN },
      { label: "Согласие · неслепые", n: sightedN },
      { label: "Ложных срабатываний", n: blindN + sightedN },
    ];
    const visiblyWarned: string[] = [];
    for (const { label } of proportions) {
      const tile = tiles.find((element) => element.props.label === label);
      assert.ok(tile, label);
      // Настоящий SSR StatTile; stripTags исключает атрибуты (включая title),
      // поэтому tooltip не может выдать себя за предупреждение рядом с числом.
      const text = stripTags(html(tile));
      assert.match(text, /100\s*%/, `${label}: итоговая доля действительно видна`);
      if (/мало данных/i.test(text)) visiblyWarned.push(label);
    }
    assert.deepEqual(visiblyWarned, proportions.filter(({ n }) => n < 20).map(({ label }) => label),
      "каждая доля при n < 20 требует видимой пометки, при n >= 20 пометки быть не должно");
  });
}
