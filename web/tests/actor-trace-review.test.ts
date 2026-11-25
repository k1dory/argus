import { test } from "node:test";
import assert from "node:assert/strict";
import { ActorTraceView } from "../src/components/console/actor-trace";
import { buildTrace, type TraceRow } from "../src/lib/shared/actor-trace";
import { parseQuery } from "../src/lib/shared/search-query";
import { html } from "./_render";

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
