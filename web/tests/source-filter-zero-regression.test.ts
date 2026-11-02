// Контракт панели «Коллекторы»: введённый 0 — действующая верхняя граница,
// пустое поле — отсутствие ограничения. Страница и форма настоящие;
// заменены только ответы источников и ленты, чтобы не зависеть от живых логов.
import type React from "react";
import { beforeEach, test } from "node:test";
import assert from "node:assert/strict";
import { installNextMocks, loadAuth } from "./_next-mock";
import { html } from "./_render";

const mocks = installNextMocks();
const auth = loadAuth();
/* eslint-disable @typescript-eslint/no-require-imports -- auth/Next mocks before page import */
const sources = require("../src/app/(console)/sources/page") as {
  default: (props: { searchParams: Promise<Record<string, string>> }) => Promise<React.ReactNode>;
};
/* eslint-enable @typescript-eslint/no-require-imports */

beforeEach(async () => {
  mocks.jar.clear();
  mocks.headers.clear();
  await auth.createSession("sso:source-filter-qa", "analyst", true);
  mocks.queries.sourcesHealthReport = async () => ({ sources: [
    { source: "fixture.zero", events_1h: 0, eps_60s: 0, last_ts: "2026-11-01 10:00:00" },
    { source: "fixture.active", events_1h: 1, eps_60s: 0.1, last_ts: "2026-11-01 11:00:00" },
    { source: "fixture.idle", events_1h: 1, eps_60s: 0, last_ts: "2026-11-01 12:00:00" },
    { source: "fixture.earlier", events_1h: 0, eps_60s: 0, last_ts: "2026-11-01 09:00:00" },
  ].map((row) => ({ ...row, source_class: "syslog", pii_share: 0, alive: 0,
    events_window: 10, rhythm_sec: 60, silence_threshold_sec: 300, silent_for_sec: 3600,
  })), omitted: 0 });
  mocks.queries.eventsRecent = async () => [];
});

async function page(params: Record<string, string>) {
  return html(await sources.default({ searchParams: Promise.resolve(params) }),
    "/sources", new URLSearchParams(params).toString());
}

function bound(markup: string, id: string): string {
  const input = [...markup.matchAll(/<input\b[^>]*>/g)]
    .map(([tag]) => tag).find((tag) => tag.includes(`id="${id}"`));
  assert.ok(input, `поле ${id} присутствует`);
  return input;
}

test("коллекторы: событий до 0 оставляет только нулевые строки и сохраняет 0 в поле", async () => {
  const markup = await page({ events_max: "0" });
  assert.match(markup, /fixture\.zero/);
  assert.match(markup, /fixture\.earlier/);
  assert.doesNotMatch(markup, /fixture\.(active|idle)/);
  assert.match(bound(markup, "src-health-events-max"), /\bvalue="0"/);
  assert.match(markup, /сбросить диапазоны/);
});

test("коллекторы: EPS до 0 сохраняет источник с событиями за час, но без текущего потока", async () => {
  const markup = await page({ eps_max: "0" });
  assert.match(markup, /fixture\.zero/);
  assert.match(markup, /fixture\.idle/);
  assert.doesNotMatch(markup, /fixture\.active/);
  assert.match(bound(markup, "src-health-eps-max"), /\bvalue="0"/);
});

test("коллекторы: пустые верхние границы возвращают строки с ненулевыми счётчиками", async () => {
  const markup = await page({ events_max: "", eps_max: "" });
  for (const source of ["zero", "active", "idle", "earlier"]) assert.ok(markup.includes(`fixture.${source}`));
  assert.match(bound(markup, "src-health-events-max"), /\bvalue=""/);
  assert.doesNotMatch(markup, /сбросить диапазоны/);
});

test("коллекторы: интервал последнего приёма остаётся UTC при нулевом пороге", async () => {
  const markup = await page({ seen_from: "2026-11-01T10:00", seen_to: "2026-11-01T11:00", events_max: "0" });
  assert.match(markup, /fixture\.zero/);
  assert.doesNotMatch(markup, /fixture\.(earlier|active|idle)/);
  assert.match(bound(markup, "src-health-seen-from"), /\bvalue="2026-11-01T10:00"/);
  assert.match(bound(markup, "src-health-seen-to"), /\bvalue="2026-11-01T11:00"/);
});
