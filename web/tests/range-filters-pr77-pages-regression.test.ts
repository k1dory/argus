// PR #77: значения диапазонов должны доходить до запросов и сохраняться
// при смене одного фильтра. Используем существующие Next/React-хелперы;
// страницы и SQL-builder настоящие, ClickHouse полностью заменён транспортом.
import type React from "react";
import path from "node:path";
import { beforeEach, test, type TestContext } from "node:test";
import assert from "node:assert/strict";
import { installNextMocks, loadAuth } from "./_next-mock";
import { html } from "./_render";

const mocks = installNextMocks();
const auth = loadAuth();
process.env.CLICKHOUSE_RO_USER = "pr77-fixture-ro";
process.env.CLICKHOUSE_RO_PASSWORD = "fixture-password";
process.env.DASHBOARDS_DIR = path.join(path.dirname(mocks.authFile), "no-provisioned-dashboards");

/* eslint-disable @typescript-eslint/no-require-imports -- моки и RO-учётка до загрузки страниц */
type Props = { params: Promise<Record<string, string>>; searchParams: Promise<Record<string, string>> };
type Page = { default: (props: Props) => Promise<React.ReactNode> };
const actors = require("../src/app/(console)/actors/page") as Page;
const dashboard = require("../src/app/(console)/dashboards/[id]/page") as Page;
const sources = require("../src/app/(console)/sources/page") as Page;
/* eslint-enable @typescript-eslint/no-require-imports */

const props = (searchParams: Record<string, string>, params: Record<string, string> = {}): Props => ({
  params: Promise.resolve(params), searchParams: Promise.resolve(searchParams),
});
const spec = {
  id: "pr77-window", title: "Окно проверки", refresh: "",
  panels: [{ id: "count", title: "События", type: "stat", w: 6, h: 3,
    sql: "SELECT count() AS total FROM events WHERE $__timeFilter(ts)" }],
};
const sent: { sql: string; params: URLSearchParams }[] = [];
const json = (...rows: unknown[]) => new Response(rows.map((r) => JSON.stringify(r)).join("\n"));

beforeEach(async (c) => {
  const t = c as TestContext; // хук верхнего уровня получает TestContext
  mocks.jar.clear();
  mocks.headers.clear();
  sent.length = 0;
  delete process.env.ARGUS_INTEGRATION_WAZUH;
  await auth.createSession("sso:pr77-review", "analyst", true);
  mocks.queries.sourcesHealthReport = async () => ({ sources: [{
    source: "fixture.ssh", source_class: "syslog", events_1h: 20, eps_60s: 0.5,
    last_ts: "2026-10-20 10:00:00", pii_share: 0, alive: 1, events_window: 100,
    rhythm_sec: 60, silence_threshold_sec: 300, silent_for_sec: 10,
  }], omitted: 0 });
  mocks.queries.eventsRecent = async () => [];
  t.mock.method(globalThis, "fetch", async (input: URL | string | Request, init?: RequestInit) => {
    const url = new URL(input instanceof Request ? input.url : String(input));
    const sql = String(init?.body ?? "");
    sent.push({ sql, params: url.searchParams });
    if (sql.includes("FROM console_dashboards") && sql.includes("WHERE id =")) {
      return json({ spec: JSON.stringify(spec), deleted: 0 });
    }
    if (sql.includes("count() AS total FROM events")) return json({ total: 1 });
    if (sql.includes("FROM identities") && !sql.includes("identity_aliases")) {
      return json({ person_id: "fixture.person", display: "Персона", kind: "person", team: "", note: "" });
    }
    if (sql.includes("FROM identity_aliases")) {
      return json({ person_id: "fixture.person", alias_kind: "login", alias_value: "fixture-login",
        valid_from: "2020-01-01 00:00:00.000", valid_to_raw: null, source: "fixture", confidence: 1, note: "" });
    }
    return new Response("");
  });
});

test("субъекты: period=30d задаёт 30 дней активности, как range=30d", async () => {
  await actors.default(props({ period: "30d" }));
  const activity = sent.find((q) => q.sql.includes("FROM events") && q.sql.includes("GROUP BY hits"));
  assert.ok(activity, "должен выполняться реальный запрос активности списка");
  const from = activity.params.get("param_from");
  const to = activity.params.get("param_to");
  assert.ok(from && to);
  const ms = (v: string) => Date.parse(v.replace(" ", "T") + "Z");
  assert.equal(ms(to) - ms(from), 30 * 86_400_000,
    "разобранный ranges.time.range теряется: listPersons получает старое значение по умолчанию 7d");
});

test("дашборд readonly: period=30d и range=30d передают макросам одно окно", async () => {
  await auth.createSession("sso:pr77-viewer", "viewer", true);
  await dashboard.default(props({ range: "30d" }, { id: spec.id }));
  const expected = sent.find((q) => q.sql.includes("count() AS total FROM events"));
  assert.ok(expected);
  assert.match(expected.sql, /INTERVAL 720 HOUR/);
  sent.length = 0;
  await dashboard.default(props({ period: "30d" }, { id: spec.id }));
  const actual = sent.find((q) => q.sql.includes("count() AS total FROM events"));
  assert.ok(actual);
  assert.equal(actual.sql, expected.sql,
    "parseTimeFilter распознаёт period, но выбор window теряет time.range и возвращается к 24h");
});

for (const range of ["constructor", "toString", "__proto__"]) {
  test(`дашборд readonly: range=${range} с одним to не расширяет окно до 1970 года`, async () => {
    await auth.createSession("sso:pr77-viewer", "viewer", true);
    await dashboard.default(props({ range, to: "2026-10-31T00:00" }, { id: spec.id }));
    const query = sent.find((q) => q.sql.includes("count() AS total FROM events"));
    assert.ok(query, "проверяем границы, реально переданные транспорту панели");
    assert.equal(query.params.get("param_argus_from"), "2026-10-30 00:00:00",
      "неизвестный пресет должен дать 24h; сейчас undefined hours → NaN → parseDtParam возвращает null → epoch");
    assert.equal(query.params.get("param_argus_to"), "2026-10-31 00:00:00");
  });
}

function links(markup: string): URL[] {
  return [...markup.matchAll(/\bhref="([^"]+)"/g)]
    .map((m) => new URL(m[1].replaceAll("&amp;", "&"), "http://fixture.invalid"));
}

const sourceFilters = {
  from: "2026-10-01T00:00", to: "2026-10-21T00:00", level_min: "7", level_max: "9",
  seen_from: "2026-10-01T00:00", seen_to: "2026-10-21T00:00", events_min: "1", eps_max: "1",
};

test("источники: выбор коллектора сохраняет диапазоны ленты и таблицы", async () => {
  const markup = html(await sources.default(props(sourceFilters)), "/sources", new URLSearchParams(sourceFilters).toString());
  const target = links(markup).find((u) => u.pathname === "/sources" && u.searchParams.get("source") === "fixture.ssh");
  assert.ok(target, "ссылка выбора источника должна присутствовать");
  for (const [key, value] of Object.entries(sourceFilters)) {
    assert.equal(target.searchParams.get(key), value, `выбор source не должен сбрасывать ${key}`);
  }
});

test("источники: сброс выбранного коллектора сохраняет диапазоны", async () => {
  const sp = { ...sourceFilters, source: "fixture.ssh" };
  const markup = html(await sources.default(props(sp)), "/sources", new URLSearchParams(sp).toString());
  const target = links(markup).find((u) => u.pathname === "/sources" && !u.searchParams.has("source"));
  assert.ok(target, "ссылка сброса source должна присутствовать");
  for (const [key, value] of Object.entries(sourceFilters)) {
    assert.equal(target.searchParams.get(key), value, `сброс source не должен сбрасывать ${key}`);
  }
});

test("субъекты: смена пресета сохраняет пороги событий и инцидентов", async () => {
  const sp = { events_min: "1", incidents_max: "2", from: "2026-10-01T00:00", to: "2026-10-21T00:00" };
  const markup = html(await actors.default(props(sp)), "/actors", new URLSearchParams(sp).toString());
  const target = links(markup).find((u) => u.pathname === "/actors" && u.searchParams.get("range") === "30d");
  assert.ok(target, "ссылка пресета 30d должна присутствовать");
  assert.equal(target.searchParams.get("events_min"), "1", "смена периода не должна сбрасывать числовые фильтры");
  assert.equal(target.searchParams.get("incidents_max"), "2");
  assert.equal(target.searchParams.has("from"), false, "пресет заменяет точное окно");
  assert.equal(target.searchParams.has("to"), false);
});
