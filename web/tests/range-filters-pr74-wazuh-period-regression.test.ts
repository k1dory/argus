// PR #74, изменения из main: активный пресет должен совпадать с окном SQL.
// Настоящие страницы и запросы; транспорт ClickHouse заменён ответами в памяти.
import type React from "react";
import { beforeEach, test, type TestContext } from "node:test";
import assert from "node:assert/strict";
import { installNextMocks, loadAuth } from "./_next-mock";
import { html, stripTags } from "./_render";

const mocks = installNextMocks();
const auth = loadAuth();
process.env.ARGUS_INTEGRATION_WAZUH = "1";

/* eslint-disable @typescript-eslint/no-require-imports -- страницы после установки Next-моков */
type Props = { params: Promise<Record<string, string>>; searchParams: Promise<Record<string, string>> };
type Page = { default: (props: Props) => Promise<React.ReactNode> };
const pages: { path: string; page: Page }[] = [
  { path: "/wazuh/agents", page: require("../src/app/(console)/wazuh/agents/page") as Page },
  { path: "/wazuh/alerts", page: require("../src/app/(console)/wazuh/alerts/page") as Page },
  { path: "/wazuh/mitre", page: require("../src/app/(console)/wazuh/mitre/page") as Page },
];
/* eslint-enable @typescript-eslint/no-require-imports */

const sent: { sql: string; params: URLSearchParams }[] = [];

beforeEach(async (context) => {
  const t = context as TestContext;
  mocks.jar.clear();
  mocks.headers.clear();
  sent.length = 0;
  await auth.createSession("sso:pr74-review", "viewer", true);
  t.mock.method(globalThis, "fetch", async (input: URL | string | Request, init?: RequestInit) => {
    const url = new URL(input instanceof Request ? input.url : String(input));
    const sql = String(init?.body ?? "");
    sent.push({ sql, params: url.searchParams });
    return new Response(sql.includes("count() AS total FROM wazuh_alerts") ? '{"total":0}\n' : "");
  });
});

for (const { path, page } of pages) {
  // range=30d — положительный контроль того же рендера и того же транспорта.
  for (const key of ["range", "period"] as const) {
    test(`${path}: ${key}=30d выбирает 30 дней и в SQL, и в переключателе`, async () => {
      const sp = { [key]: "30d" };
      const tree = await page.default({ params: Promise.resolve({}), searchParams: Promise.resolve(sp) });
      const activity = sent.filter((q) => q.sql.includes("FROM wazuh_alerts"));
      assert.ok(activity.length > 0, "должен выполняться запрос данных витрины");
      for (const query of activity) {
        assert.equal(query.params.get("param_t_hours"), "720", "проверяем окно настоящего SQL-builder");
      }
      const markup = html(tree, path, new URLSearchParams(sp).toString());
      const pressed = [...markup.matchAll(/<button\b([^>]*)>([\s\S]*?)<\/button>/g)]
        .filter((match) => /\baria-pressed="true"/.test(match[1]))
        .map((match) => stripTags(match[2]));
      assert.deepEqual(pressed, ["30 дней"],
        "при SQL за 720 часов нельзя показывать активный пресет «24 часа»");
    });
  }
}
