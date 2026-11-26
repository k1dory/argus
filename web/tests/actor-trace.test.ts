// Трассировка субъекта: сессии по перерыву, фоновая сеть не склеивает сессии,
// события без адреса привязываются к входу на тот же узел, сеть сворачивается
// в топ, инциденты — к своей сессии, ссылки в журнал — структурными полями.
import { test } from "node:test";
import assert from "node:assert/strict";
import { attachIncidents, buildTrace, spanEventsHref, spanLabel, type TraceRow } from "../src/lib/shared/actor-trace";
import { parseQuery } from "../src/lib/shared/search-query";

const T0 = Date.parse("2026-11-20T08:00:00Z");
const at = (min: number) => new Date(T0 + min * 60_000).toISOString().slice(0, 23).replace("T", " ");

function row(p: Partial<TraceRow> & { min: number; dur?: number }): TraceRow {
  return {
    section: "other", origin: "", target: "", target_kind: "source", dst_port: 0, source: "src", action: "act", count: 1, fails: 0,
    first_ts: at(p.min), last_ts: at(p.min + (p.dur ?? 0)), ...p,
  };
}

const ssh = (min: number, origin = "10.8.0.5", node = "pve125") => row({ min, section: "login", origin, target: node, target_kind: "node", source: "sshd", action: "auth.ssh" });
const sudo = (min: number, node = "pve125") => row({ min, section: "host", target: node, target_kind: "node", source: "sudo", action: "priv.sudo" });
const flow = (min: number, dst: string, dur = 0, origin = "10.8.0.5", count = 10) => row({ min, dur, section: "network", origin, target: dst, target_kind: "dst", dst_port: 443, source: "netflow", action: "flow", count });

test("сессии делятся перерывом дольше 30 минут, свежая — первой", () => {
  const t = buildTrace([ssh(0), sudo(5), ssh(200), sudo(210)]);
  assert.equal(t.sessions.length, 2);
  assert.ok(t.sessions[0].first > t.sessions[1].first);
  assert.equal(t.sessions[1].count, 2);
});

test("фоновый поток NetFlow на сутки не склеивает две сессии и не делает их «только сеть»", () => {
  const t = buildTrace([ssh(0), flow(0, "1.1.1.1", 600), ssh(300)]);
  const interactive = t.sessions.filter((s) => !s.networkOnly);
  assert.equal(interactive.length, 2);
  // Поток пересекает окно обеих — достаётся одной, а не дублируется.
  const flows = t.sessions.flatMap((s) => s.origins.flatMap((o) => o.spans)).filter((s) => s.section === "network");
  assert.equal(flows.length, 1);
});

test("сеть без входов и команд — отдельная сессия «только сеть»", () => {
  const t = buildTrace([ssh(0), flow(500, "8.8.8.8")]);
  assert.equal(t.sessions.length, 2);
  assert.equal(t.sessions[0].networkOnly, true);
  assert.equal(t.sessions[1].networkOnly, false);
});

test("sudo без адреса привязывается к источнику входа на тот же узел", () => {
  const t = buildTrace([ssh(0, "10.8.0.5", "pve125"), sudo(3, "pve125"), sudo(4, "pve96")]);
  const [s] = t.sessions;
  const from = s.origins.find((o) => o.origin === "10.8.0.5")!;
  const attached = from.spans.find((x) => x.section === "host")!;
  assert.equal(attached.target, "pve125");
  assert.equal(attached.attached, true);
  // На pve96 входа не было — остаётся в ветке «без адреса», последней.
  const last = s.origins[s.origins.length - 1];
  assert.equal(last.origin, "");
  assert.equal(last.spans[0].target, "pve96");
});

test("одинаковые действия из разных корзин складываются в одну полосу с сегментами", () => {
  const t = buildTrace([sudo(0), sudo(1), sudo(20)], { bucketSec: 60 });
  const span = t.sessions[0].origins[0].spans[0];
  assert.equal(span.count, 3);
  assert.equal(span.actions.length, 1);
  assert.equal(span.actions[0].count, 3);
  assert.deepEqual(span.segments.length, 2, "0–1 мин склеены, 20 мин — отдельный сегмент");
});

test("сеть сворачивается в топ адресов и строку «ещё N»", () => {
  const rows = [ssh(0), ...Array.from({ length: 12 }, (_, i) => flow(1, `10.0.0.${i}`, 0, "10.8.0.5", 100 - i))];
  const t = buildTrace(rows, { networkTop: 8 });
  const spans = t.sessions[0].origins[0].spans.filter((s) => s.section === "network");
  assert.equal(spans.length, 9);
  const folded = spans.find((s) => s.folded)!;
  assert.equal(folded.folded, 4);
  assert.equal(folded.count, 92 + 91 + 90 + 89);
  assert.equal(spanLabel(folded), "ещё 4 адресов");
  assert.ok(spans.some((s) => s.target === "10.0.0.0"), "самый частый адрес остался");
});

test("отказы считаются по полосе и сессии", () => {
  const t = buildTrace([{ ...ssh(0), fails: 3, count: 4 }, sudo(1)]);
  assert.equal(t.sessions[0].fails, 3);
  assert.equal(t.sessions[0].origins[0].fails, 3);
});

test("инцидент — к ближайшей сессии в пределах перерыва, не дублируется", () => {
  const t = buildTrace([ssh(0), ssh(300)]);
  const inc = { id: "INC-1", level: "high", status: "open", rule_id: "r", rule_title: "t", created_at: at(305) };
  const far = { ...inc, id: "INC-2", created_at: at(1000) };
  attachIncidents(t.sessions, [inc, inc, far], t.gapMs);
  assert.deepEqual(t.sessions[0].incidents.map((i) => i.id), ["INC-1"]);
  assert.deepEqual(t.sessions[1].incidents, []);
});

test("строки с неразборчивым временем отбрасываются", () => {
  const t = buildTrace([{ ...ssh(0), first_ts: "мусор" }, sudo(1)]);
  assert.equal(t.sessions[0].count, 1);
});

test("ссылка в журнал: структурные поля полосы и окно с запасом в корзину", () => {
  const t = buildTrace([ssh(0, "10.8.0.5", "pve125"), sudo(3, "pve125"), flow(5, "1.2.3.4")], { bucketSec: 60 });
  const o = t.sessions[0].origins[0];
  const sudoSpan = o.spans.find((s) => s.section === "host")!;
  const url = new URL(spanEventsHref(o.origin, sudoSpan, 60, "priv.sudo")!, "http://x");
  const terms = parseQuery(url.searchParams.get("q")!);
  // sudo привязан выводом — src в журнале у него пустой, фильтровать по нему нельзя.
  assert.deepEqual(terms.map((x) => [x.field, x.value]), [["node", "pve125"], ["action", "priv.sudo"]]);
  // Окно — точное до секунды: активность действия, без запаса в корзину.
  assert.equal(url.searchParams.get("from"), "2026-11-20T08:03:00");
  assert.equal(url.searchParams.get("to"), "2026-11-20T08:03:00");
  const net = o.spans.find((s) => s.section === "network")!;
  const q = parseQuery(new URL(spanEventsHref(o.origin, net, 60)!, "http://x").searchParams.get("q")!);
  assert.deepEqual(q.map((x) => [x.field, x.value]), [["src", "10.8.0.5"], ["dst", "1.2.3.4"], ["dport", "443"]]);
});

test("значение со звёздочкой в ссылке — литерал, а не маска", () => {
  const t = buildTrace([row({ min: 0, section: "app", target: "app*", target_kind: "object" })]);
  const s = t.sessions[0].origins[0].spans[0];
  const [term] = parseQuery(new URL(spanEventsHref("", s, 60)!, "http://x").searchParams.get("q")!);
  assert.equal(term.quoted, true);
});

test("сеть дальше 5 минут от действий не растягивает сессию", () => {
  const t = buildTrace([ssh(100), sudo(110), flow(113, "1.1.1.1"), flow(125, "2.2.2.2"), flow(80, "3.3.3.3")]);
  const s = t.sessions.find((x) => !x.networkOnly)!;
  assert.equal(new Date(s.first).toISOString(), new Date(T0 + 100 * 60_000).toISOString());
  assert.equal(new Date(s.last).toISOString(), new Date(T0 + 113 * 60_000).toISOString());
  assert.equal(t.sessions.filter((x) => x.networkOnly).length, 2);
});

test("ссылка обрезается интервалом владения алиасом; вне интервала — ссылки нет", () => {
  const t = buildTrace([{ ...sudo(0), actor: "alice", last_ts: at(20) }]);
  const span = t.sessions[0].origins[0].spans[0];
  const owner = (field: "actor" | "src" | "node", v: string): [number, number][] =>
    field === "actor" && v === "alice" ? [[T0 - 3600_000, T0 + 10 * 60_000]] : [];
  const url = new URL(spanEventsHref("", span, 60, undefined, owner)!, "http://x");
  assert.equal(url.searchParams.get("to"), "2026-11-20T08:09:59", "алиас закрыт в 08:10 (исключительно) — журнал режет «<=» по секундам");
  const none = () => [] as [number, number][];
  assert.equal(spanEventsHref("", span, 60, undefined, none), null);
});
