import { test } from "node:test";
import assert from "node:assert/strict";
import { ActorTraceView } from "../src/components/console/actor-trace";
import { buildTrace, spanEventsHref, type TraceRow } from "../src/lib/shared/actor-trace";
import { parseQuery } from "../src/lib/shared/search-query";
import { html, stripTags } from "./_render";
import { journalQuery, parseJournalParams } from "../src/lib/shared/journal";

const T0 = Date.parse("2026-11-20T08:00:00Z");
const at = (min: number) => new Date(T0 + min * 60_000).toISOString();
const ssh = (min: number, origin = "10.8.0.5"): TraceRow => ({
  section: "login", origin, target: "trace-host", target_kind: "node",
  dst_port: 0, source: "sshd", action: "auth.ssh", count: 1, fails: 0,
  first_ts: at(min), last_ts: at(min),
});
const sudo = (min: number): TraceRow => ({
  ...ssh(min), section: "host", origin: "", source: "sudo", action: "priv.sudo",
});

for (const [name, rows] of [
  ["F2: вход из будущего", [sudo(0), ssh(5)]],
  ["F2: только неудачный вход", [{ ...ssh(0), fails: 1 }, sudo(5)]],
  ["F2: два конкурирующих источника входа", [
    ssh(0, "10.8.0.5"), ssh(1, "10.8.0.6"), sudo(2),
  ]],
] as const) {
  test(name, () => {
    const origins = buildTrace([...rows]).sessions.flatMap((s) => s.origins);
    const owners = origins.filter((o) => o.spans.some((s) => s.section === "host"));
    assert.deepEqual(owners.map((o) => o.origin), [""]);
    assert.ok(owners.every((o) => o.spans.every((s) => !s.attached)));
  });
}

function originLink(origin = "10.8.0.5"): URL {
  const markup = html(ActorTraceView({ trace: buildTrace([ssh(0, origin)]) }));
  const links = [...markup.matchAll(/href="([^"]+)"/g)]
    .map((m) => new URL(m[1].replaceAll("&amp;", "&"), "http://test"));
  const link = links.find((u) => {
    const terms = parseQuery(u.searchParams.get("q") ?? "");
    return u.pathname === "/events" && terms.some((t) => t.field === "src")
      && !terms.some((t) => t.field === "node");
  });
  assert.ok(link, "ссылка ветки источника присутствует");
  return link;
}

test("F5: ссылка источника сохраняет окно исторической сессии", () => {
  const url = originLink();
  const from = url.searchParams.get("from");
  const to = url.searchParams.get("to");
  assert.ok(from && to);
  assert.ok(Date.parse(from + "Z") <= T0);
  assert.ok(Date.parse(to + "Z") >= T0);
});

test("F5: src_ip из события не добавляет условия языка поиска", () => {
  const origin = "198.51.100.7 action:flow";
  const terms = parseQuery(originLink(origin).searchParams.get("q")!);
  assert.deepEqual(terms.filter((t) => t.field === "src").map((t) => t.value), [origin]);
  assert.ok(!terms.some((t) => t.field === "action"));
});


test("R1: ранний отказ не делает поздний успех предшествующим входом", () => {
  // Одна SQL-корзина: отказ в :00, успех в :48, sudo в :18.
  const trace = buildTrace([
    { ...ssh(0), actor: "alice", count: 2, fails: 1, last_ts: at(0.8) },
    { ...sudo(0.3), actor: "alice" },
  ]);
  const owner = trace.sessions[0].origins.find((o) =>
    o.spans.some((s) => s.section === "host"))!;
  assert.equal(owner.origin, "");
  assert.ok(owner.spans.every((s) => !s.attached));
});

test("R1: sudo с адресом не является подтверждением входа", () => {
  const trace = buildTrace([
    { ...sudo(0), origin: "10.8.0.5", actor: "alice" },
    { ...sudo(0.3), actor: "alice" },
  ]);
  assert.equal(trace.sessions[0].origins.find((o) => o.origin === "")?.count, 1);
});

test("R3: ссылка действия выбирает actor, выполнявшего это действие", () => {
  const trace = buildTrace([
    { ...sudo(0), actor: "alice", count: 10 },
    { ...sudo(1), actor: "alice.admin", action: "session.open" },
  ]);
  const span = trace.sessions[0].origins[0].spans[0];
  const url = new URL(spanEventsHref("", span, 60, "session.open")!, "http://test");
  const terms = parseQuery(url.searchParams.get("q")!);
  assert.equal(terms.find((t) => t.field === "actor")?.value, "alice.admin");
});

test("R4: условия длиннее лимита журнала — ссылки нет (журнал обрезал бы объект и потерял действие)", () => {
  const target = "https://example.test/" + "x".repeat(2100) + "/a";
  const trace = buildTrace([{
    ...sudo(0), section: "app", target_kind: "object", target,
    actor: "alice", action: "app.open",
  }]);
  const span = trace.sessions[0].origins[0].spans[0];
  assert.equal(spanEventsHref("", span, 60, "app.open"), null);
  assert.equal(spanEventsHref("", span, 60), null);
});

test("R4: на границе лимита ссылка есть и переживает парсер журнала целиком", () => {
  const target = "https://example.test/" + "x".repeat(1800);
  const trace = buildTrace([{
    ...sudo(0), section: "app", target_kind: "object", target,
    actor: "alice", action: "app.open",
  }]);
  const span = trace.sessions[0].origins[0].spans[0];
  const url = new URL(spanEventsHref("", span, 60, "app.open")!, "http://test");
  const terms = parseQuery(journalQuery(parseJournalParams(url.searchParams)));
  assert.ok(terms.some((t) => t.field === "object" && t.value === target));
  assert.ok(terms.some((t) => t.field === "action" && t.value === "app.open"));
});

test("PR130: отказы сетевого сеанса видны до раскрытия блоков", () => {
  const trace = buildTrace([{
    ...ssh(0), section: "network", target: "198.51.100.10",
    target_kind: "dst", source: "ngfw", action: "net.firewall",
    count: 3, fails: 3,
  }]);
  assert.equal(trace.sessions[0].networkOnly, true);
  const markup = html(ActorTraceView({ trace }));
  const summary = /<details\b([^>]*)>\s*<summary\b[^>]*>([\s\S]*?)<\/summary>/.exec(markup);
  assert.ok(summary);
  const expanded = /\bopen(?:[=\s]|$)/.test(summary[1]);
  const warns = /3\s+отказ|отказов\s+3/.test(stripTags(summary[2]));
  assert.ok(expanded || warns, "закрытая группа не должна скрывать наличие отказов");
});
