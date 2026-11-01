// PR #77: API поиска обязан передавать то же окно, что новый парсер страницы.
// Маршрут и SQL-builder настоящие; перехватываем только транспорт ClickHouse.
import { test } from "node:test";
import assert from "node:assert/strict";
import { installNextMocks, loadAuth } from "./_next-mock";
import { parseTimeFilter, toChParam, parseDtParam } from "../src/lib/shared/filters";

installNextMocks();
loadAuth();
const API = "pr77-time-regression-" + "a".repeat(40);
process.env.ARGUS_API_TOKEN = API;
delete process.env.ARGUS_INTEGRATION_WAZUH;

/* eslint-disable @typescript-eslint/no-require-imports -- Next/auth mocks до импорта маршрута */
const { GET } = require("../src/app/api/search/route") as typeof import("../src/app/api/search/route");
/* eslint-enable @typescript-eslint/no-require-imports */

const scenarios: { name: string; params: Record<string, string> }[] = [
  { name: "только to — сутки перед заданным концом", params: { to: "2026-10-20T12:00" } },
  { name: "точное окно не шире 400 дней", params: { from: "2020-01-01T00:00", to: "2026-10-20T12:00" } },
  { name: "несуществующее число месяца отбрасывается", params: { from: "2026-02-31T00:00", to: "2026-03-05T00:00" } },
  { name: "period — синоним range", params: { period: "30d" } },
];

for (const scenario of scenarios) {
  test(`/api/search: ${scenario.name}`, async (t) => {
    const sent: { sql: string; params: URLSearchParams }[] = [];
    t.mock.method(globalThis, "fetch", async (input: URL | string | Request, init?: RequestInit) => {
      const url = new URL(input instanceof Request ? input.url : String(input));
      sent.push({ sql: String(init?.body ?? ""), params: url.searchParams });
      return new Response("");
    });
    const qs = new URLSearchParams({ index: "events", ...scenario.params });
    const res = await GET(new Request(`http://fixture.invalid/api/search?${qs}`, {
      headers: { authorization: `Bearer ${API}` },
    }));
    assert.equal(res.status, 200);
    const expected = parseTimeFilter(qs, { defaultRange: "24h" });
    assert.equal(sent.length, 3, "проверяем строки, гистограмму и фасеты");
    for (const query of sent) {
      if (expected.from) {
        assert.equal(query.params.get("param_from"), toChParam(parseDtParam(expected.from)!), scenario.name);
        assert.equal(query.params.get("param_to"), toChParam(parseDtParam(expected.to!)!), scenario.name);
        assert.match(query.sql, /ts >= toDateTime\(\{from:String\}, 'UTC'\)/);
        assert.match(query.sql, /ts <= toDateTime\(\{to:String\}, 'UTC'\)/);
      } else {
        assert.equal(query.params.get("param_hours"), "720", "period=30d нельзя молча заменять на 24h");
        assert.match(query.sql, /ts >= now\(\) - INTERVAL \{hours:UInt32\} HOUR/);
      }
    }
  });
}
