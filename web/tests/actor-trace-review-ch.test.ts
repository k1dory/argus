import { after, before, test } from "node:test";
import assert from "node:assert/strict";
import { randomBytes } from "node:crypto";
import { applyAllMigrations, ch, liveSkip as skip, serializeLiveFile } from "./_ch-live";
import { spanEventsHref, type ActorTrace } from "../src/lib/shared/actor-trace";
import type { Alias } from "../src/lib/shared/actors";
import { chTs } from "../src/lib/shared/log-query";
import { journalQuery, parseJournalParams } from "../src/lib/shared/journal";

serializeLiveFile({ before, after });
before(async () => { if (skip === false) await applyAllMigrations(); });

/* eslint-disable @typescript-eslint/no-require-imports -- env установлен _ch-live */
const actors = () => require("../src/lib/actors") as typeof import("../src/lib/actors");
const search = () => require("../src/lib/search") as typeof import("../src/lib/search");
/* eslint-enable @typescript-eslint/no-require-imports */

type Event = Record<string, string | number | undefined>;
type Fixture = { source: string; login: string; ip: string; node: string; fromMs: number };
const spans = (t: ActorTrace) => t.sessions.flatMap((s) => s.origins.flatMap((o) => o.spans));

async function withTrace(
  events: (f: Fixture) => Event[],
  check: (trace: ActorTrace, f: Fixture) => void | Promise<void>,
): Promise<void> {
  const run = randomBytes(6).toString("hex");
  const f: Fixture = {
    source: "trace.review." + run, login: "trace.review." + run,
    node: "trace-review-" + run,
    ip: "2001:db8:" + run.slice(0, 4) + ":" + run.slice(4, 8) + "::" + run.slice(8),
    fromMs: Math.floor((Date.now() - 3_600_000) / 60_000) * 60_000,
  };
  const aliases: Alias[] = [
    { kind: "login", value: f.login }, { kind: "ip", value: f.ip },
  ].map((a) => ({
    ...a, kind: a.kind as Alias["kind"], person_id: run,
    valid_from: chTs(f.fromMs), valid_to: null,
    source: "fixture", confidence: 1, note: "",
  }));
  const rows = events(f).map((e) => ({
    ts: chTs(f.fromMs + 10_000), source_class: "syslog",
    actor_name: f.login, actor_kind: "user", src_ip: "", node: "",
    dst_ip: "", dst_port: 0, object: "", action: "app.open", outcome: "success",
    ...e, source: f.source,
  }));
  try {
    await ch().chCommand("INSERT INTO events FORMAT JSONEachRow\n" + rows.map((r) => JSON.stringify(r)).join("\n"));
    const trace = await actors().actorTrace(aliases, "24h", {
      window: { fromMs: f.fromMs, toMs: f.fromMs + 60_000 },
      now: f.fromMs + 60_000,
    });
    await check(trace, f);
  } finally {
    await ch().chCommand(
      "ALTER TABLE events DELETE WHERE source = {source:String} SETTINGS mutations_sync = 1",
      { source: f.source },
    );
  }
}

test("F1: NetFlow с node экспортёра сохраняет назначения", { skip }, async () => {
  await withTrace((f) => ["192.0.2.1", "192.0.2.2"].map((dst_ip) => ({
    source_class: "netflow", actor_name: "", action: "flow",
    node: f.node, src_ip: f.ip, dst_ip, dst_port: 443,
  })), (trace) => {
    const net = spans(trace).filter((s) => s.section === "network");
    assert.deepEqual(net.map((s) => s.target).sort(), ["192.0.2.1", "192.0.2.2"]);
    assert.ok(net.every((s) => s.target_kind === "dst"));
  });
});

test("F3: ссылка sudo не включает другого субъекта на том же узле", { skip }, async () => {
  await withTrace((f) => [
    { action: "auth.ssh", node: f.node, src_ip: f.ip },
    { ts: chTs(f.fromMs + 20_000), action: "priv.sudo", node: f.node },
    { ts: chTs(f.fromMs + 21_000), action: "priv.sudo", node: f.node, actor_name: "someone.else" },
  ], async (trace, f) => {
    const span = spans(trace).find((s) => s.section === "host")!;
    assert.equal(span.count, 1, "чужое событие не попало в саму трассу");
    const url = new URL(spanEventsHref(f.ip, span, trace.bucketSec, "priv.sudo")!, "http://test");
    const b = search().buildWhere({
      index: "events", range: "24h", page: 1, q: url.searchParams.get("q")!,
      from: url.searchParams.get("from")!, to: url.searchParams.get("to")!,
    });
    assert.equal(b.error, null);
    const rows = await ch().chQuery<{ actor_name: string }>(
      "SELECT actor_name FROM events WHERE " + b.where, b.params,
    );
    assert.deepEqual(rows.map((r) => r.actor_name), [f.login]);
  });
});

test("F4: действия одного назначения не занимают весь сетевой топ", { skip }, async () => {
  await withTrace((f) => {
    const flow = { source_class: "netflow", actor_name: "", src_ip: f.ip, dst_port: 443 };
    return [
      ...Array.from({ length: 8 }, (_, i) => Array.from({ length: 10 }, () => ({
        ...flow, dst_ip: "192.0.2.1", action: "net.action" + i,
      }))).flat(),
      ...Array.from({ length: 9 }, () => ({ ...flow, dst_ip: "192.0.2.2", action: "flow" })),
    ];
  }, (trace) => {
    const net = spans(trace).filter((s) => s.section === "network");
    assert.deepEqual(net.map((s) => s.target).sort(), ["192.0.2.1", "192.0.2.2"]);
    assert.equal(net.reduce((n, s) => n + s.count, 0), 89);
  });
});

test("F6: объекты с общими первыми 160 байтами не сливаются", { skip }, async () => {
  const prefix = "https://example.test/" + "x".repeat(180);
  await withTrace(() => [
    { object: prefix + "/a" }, { object: prefix + "/b" },
  ], (trace) => {
    const app = spans(trace).filter((s) => s.section === "app");
    assert.equal(app.length, 2);
    assert.deepEqual(app.map((s) => s.count), [1, 1]);
  });
});


async function journalRows(href: string) {
  const f = parseJournalParams(new URL(href, "http://test").searchParams);
  const b = search().buildWhere({
    index: "events", page: 1, q: journalQuery(f),
    range: f.range, from: f.from, to: f.to,
  });
  assert.equal(b.error, null);
  // ts_s, а не ts: одноимённый алиас затенил бы колонку в WHERE (String против DateTime64).
  const rows = await ch().chQuery<{ ts_s: string; object: string }>(
    "SELECT toString(ts) AS ts_s, object FROM events WHERE " + b.where + " ORDER BY ts",
    b.params,
  );
  return rows.map((r) => ({ ts: r.ts_s, object: r.object }));
}

test("R1: SQL-корзина с отказом до sudo и успехом после него", { skip }, async () => {
  await withTrace((f) => [
    { ts: chTs(f.fromMs), node: f.node, src_ip: f.ip,
      action: "auth.ssh", outcome: "failure" },
    { ts: chTs(f.fromMs + 20_000), node: f.node, action: "priv.sudo" },
    { ts: chTs(f.fromMs + 50_000), node: f.node, src_ip: f.ip,
      action: "auth.ssh", outcome: "success" },
  ], (trace) => {
    const owner = trace.sessions.flatMap((s) => s.origins)
      .find((o) => o.spans.some((s) => s.section === "host"))!;
    assert.equal(owner.origin, "");
    assert.ok(owner.spans.every((s) => !s.attached));
  });
});

test("R2: журнал не возвращает события до начала владения алиасом", { skip }, async () => {
  await withTrace((f) => [
    // Тот же логин/узел до valid_from принадлежал предыдущему владельцу.
    { ts: chTs(f.fromMs - 10_000), node: f.node, action: "priv.sudo" },
    { ts: chTs(f.fromMs + 10_000), node: f.node, action: "priv.sudo" },
  ], async (trace, f) => {
    const span = spans(trace).find((s) => s.section === "host")!;
    assert.equal(span.count, 1);
    const rows = await journalRows(spanEventsHref("", span, trace.bucketSec, "priv.sudo")!);
    assert.deepEqual(rows.map((r) => r.ts), [chTs(f.fromMs + 10_000)]);
  });
});

test("R4: объект длиннее лимита журнала — ссылки нет, вместо неё не журнал по обрезанному условию", { skip }, async () => {
  const prefix = "https://example.test/" + "x".repeat(2100);
  await withTrace(() => [
    { object: prefix + "/a", action: "app.open" },
    { object: prefix + "/b", action: "app.close" },
  ], async (trace) => {
    const app = spans(trace).filter((s) => s.section === "app");
    assert.equal(app.length, 2);
    const span = app.find((s) => s.target === prefix + "/a")!;
    assert.equal(spanEventsHref("", span, trace.bucketSec, "app.open"), null);
  });
});
