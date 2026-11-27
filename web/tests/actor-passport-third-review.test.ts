import { test } from "node:test";
import assert from "node:assert/strict";
import { buildTrace, ownerScope, spanEventsHref, type TraceRow } from "../src/lib/shared/actor-trace";
import { buildFeed } from "../src/lib/shared/actor-feed";
import { classifyEvent, type Alias } from "../src/lib/shared/actors";
import { inTime } from "../src/lib/shared/filters";
import { parseJournalParams } from "../src/lib/shared/journal";
import { parseQuery } from "../src/lib/shared/search-query";

const T = Date.parse("2026-11-20T08:00:00Z");
const stamp = (ms: number) => new Date(T + ms).toISOString();
const alias = (p: Partial<Alias> = {}): Alias => ({
  person_id: "p", kind: "login", value: "alice", source: "fixture",
  confidence: 1, note: "", valid_from: stamp(-60_000), valid_to: null, ...p,
});
const row = (p: Partial<TraceRow> = {}): TraceRow => ({
  section: "host", origin: "", target: "srv", target_kind: "node",
  dst_port: 0, source: "linux.auth", action: "priv.sudo", actor: "alice",
  count: 1, fails: 0, first_ts: stamp(0), last_ts: stamp(0), ...p,
});
const feed = (rows: TraceRow[], aliases: Alias[]) =>
  buildFeed(buildTrace(rows), { owner: ownerScope(aliases) });
const params = (href: string) =>
  parseJournalParams(new URL(href, "http://test").searchParams);

test("R2: valid_to не включается в ссылку прежнего владельца", () => {
  const [it] = feed(
    [row({ first_ts: stamp(900), last_ts: stamp(900) })],
    [alias({ valid_to: stamp(1000) })],
  );
  // Если безопасное окно нельзя выразить, допустим null.
  if (it.href) assert.equal(inTime(stamp(1000), params(it.href)), false);
});

test("R2: округление valid_from не создаёт ссылку без исходного события", () => {
  const [it] = feed(
    [row({ first_ts: stamp(600), last_ts: stamp(600) })],
    [alias({ valid_from: stamp(500) })],
  );
  if (it.href) assert.equal(inTime(stamp(600), params(it.href)), true);
});

test("R3: одинаковое действие разных источников сохраняет actor и время строки", () => {
  const items = feed([
    row({ source: "linux.auth", count: 10 }),
    row({ source: "auditd", actor: "alice.admin",
      first_ts: stamp(10_000), last_ts: stamp(10_000) }),
  ], [alias(), alias({ value: "alice.admin" })]);
  const it = items.find((i) => i.meta[0] === "alice.admin")!;
  assert.notEqual(it.href, null);
  const f = params(it.href!);
  assert.equal(parseQuery(f.q).find((t) => t.field === "actor")?.value, "alice.admin");
  assert.equal(inTime(stamp(10_000), f), true);
});

test("ownerScope: actor события не отменяет действующий IP-алиас", () => {
  const [it] = feed(
    [row({ actor: "guest", origin: "10.8.0.5" })],
    [alias({ kind: "ip", value: "10.8.0.5" })],
  );
  assert.notEqual(it.href, null, "событие принадлежит субъекту по src");
});

test("ownerScope: host-алиас тоже ограничивает окно ссылки", () => {
  const [it] = feed(
    [row({ actor: "", first_ts: stamp(600), last_ts: stamp(600) })],
    [alias({ kind: "host", value: "srv", valid_from: stamp(500) })],
  );
  if (it.href) assert.equal(inTime(stamp(100), params(it.href)), false);
});

test("ownerScope: начало другого actor не скрывает действующий интервал выбранного", () => {
  const [it] = feed([
    row(),
    row({ actor: "alice.admin", count: 10,
      first_ts: stamp(600_000), last_ts: stamp(600_000) }),
  ], [alias(), alias({ value: "alice.admin", valid_from: stamp(540_000) })]);
  assert.notEqual(it.href, null);
  assert.equal(inTime(stamp(600_000), params(it.href!)), true);
});

const logout = () => row({
  section: classifyEvent("auth.logout", "success"),
  action: "auth.logout", origin: "10.8.0.5",
});

test("лента: auth.logout не называется входом", () => {
  const [it] = buildFeed(buildTrace([logout()]));
  assert.doesNotMatch(it.title, /^Вход/);
});

test("R1: logout не подтверждает предшествующий вход для sudo", () => {
  const trace = buildTrace([
    logout(), row({ first_ts: stamp(10_000), last_ts: stamp(10_000) }),
  ]);
  const host = trace.sessions.flatMap((s) => s.origins)
    .find((o) => o.spans.some((s) => s.section === "host"))!;
  assert.equal(host.origin, "");
});


test("review4: ссылка выбирает интервал с событиями выбранного actor", () => {
  const [it] = feed([
    row(),
    row({ actor: "alice.admin", count: 10,
      first_ts: stamp(600_000), last_ts: stamp(600_000) }),
  ], [
    alias(),
    alias({ value: "alice.admin", valid_to: stamp(300_000) }),
    alias({ value: "alice.admin", valid_from: stamp(540_000) }),
  ]);
  assert.notEqual(it.href, null);
  const f = params(it.href!);
  assert.equal(parseQuery(f.q).find((t) => t.field === "actor")?.value, "alice.admin");
  assert.equal(inTime(stamp(600_000), f), true,
    "единственные события alice.admin — в 08:10; старый интервал даёт пустой журнал");
});

test("review4: самая частая команда topK остаётся видимой в ленте", () => {
  // Одна корзина: systemctl выполнена 100 раз, остальные команды — по одному.
  const [it] = feed([row({
    count: 104,
    details: ["systemctl restart api", "apt update", "cat /etc/hosts", "df -h", "id"],
  })], [alias()]);
  assert.match(it.meta.join(" | "), /systemctl restart api/,
    "общий count корзины нельзя приписывать каждой детали");
});


test("review5: ссылка полосы использует время выбранного actor", () => {
  const trace = buildTrace([
    row(),
    row({ actor: "alice.admin", count: 10,
      first_ts: stamp(600_000), last_ts: stamp(600_000) }),
  ]);
  const span = trace.sessions[0].origins[0].spans[0];
  const href = spanEventsHref("", span, trace.bucketSec, undefined, ownerScope([
    alias(),
    alias({ value: "alice.admin", valid_to: stamp(300_000) }),
    alias({ value: "alice.admin", valid_from: stamp(540_000) }),
  ]));
  assert.ok(href);
  const f = params(href);
  assert.equal(parseQuery(f.q).find((t) => t.field === "actor")?.value, "alice.admin");
  assert.equal(inTime(stamp(600_000), f), true);
});

test("review5: интервал владения в паузе не создаёт пустой журнал", () => {
  const rows = [
    row({ origin: "10.8.0.5" }),
    row({ origin: "10.8.0.5",
      first_ts: stamp(600_000), last_ts: stamp(600_000) }),
  ];
  const [it] = feed(rows, [
    alias({ valid_from: stamp(180_000), valid_to: stamp(300_000) }),
    alias({ kind: "ip", value: "10.8.0.5" }),
  ]);
  assert.ok(it.href);
  const f = params(it.href);
  assert.ok(rows.some((r) => inTime(r.first_ts, f)),
    "оба события принадлежат субъекту по IP, но в 08:03–08:05 событий нет");
});

for (const actor of ["constructor", "__proto__"]) {
  test(`review5: actor ${actor} сохраняет границы владения`, () => {
    const [it] = feed([row({ actor })], [
      alias({ value: actor, valid_to: stamp(60_000) }),
    ]);
    assert.ok(it.href);
    const f = params(it.href);
    assert.equal(inTime(stamp(0), f, T + 120_000), true);
    assert.equal(inTime(stamp(70_000), f, T + 120_000), false,
      "событие следующего владельца не должно попасть в журнал");
  });
}

for (const kind of ["ip", "host"] as const) {
  for (const actionLink of [false, true]) {
    test(`review6: ${kind}, ${actionLink ? "действие" : "полоса"} — окно выбранного actor`, () => {
      const origin = kind === "ip" ? "10.8.0.5" : "";
      const rows = [
        row({ origin, count: 2 }),
        row({ origin, actor: "bob", first_ts: stamp(600_000), last_ts: stamp(600_000) }),
      ];
      const trace = buildTrace(rows);
      const span = trace.sessions[0].origins[0].spans[0];
      const owner = ownerScope([alias({ kind, value: kind === "ip" ? origin : "srv" })]);
      const href = spanEventsHref(origin, span, trace.bucketSec,
        actionLink ? span.actions[0] : undefined, owner);
      assert.ok(href);
      const f = params(href);
      assert.equal(parseQuery(f.q).find((t) => t.field === "actor")?.value, "alice");
      assert.equal(inTime(rows[0].first_ts, f), true,
        "окно bob не содержит событий выбранного alice");
    });
  }
}

test("review6: пауза внутри SQL-корзины не подтверждает окно ссылки", () => {
  // Ровно два события в одной 60-секундной корзине; между ними событий нет.
  const r = row({ origin: "10.8.0.5", count: 2, last_ts: stamp(50_000) });
  const [it] = feed([r], [
    alias({ valid_from: stamp(10_000), valid_to: stamp(20_000) }),
    alias({ kind: "ip", value: r.origin }),
  ]);
  assert.ok(it.href, "IP подтверждает оба события и позволяет построить ссылку");
  const f = params(it.href);
  assert.ok([r.first_ts, r.last_ts].some((ts) => inTime(ts, f)),
    "в окне 08:00:10–08:00:19 нет ни одного из двух событий");
});
