// Лента активности: заголовки, отметка отказов и инцидентов, фильтры, дни,
// время справа, сеть не попадает, команды sudo в строке.
import { test } from "node:test";
import assert from "node:assert/strict";
import { buildTrace, type TraceRow } from "../src/lib/shared/actor-trace";
import { buildFeed, dayLabel, feedTime, filterFeed, groupByDay, parseFeedFilter } from "../src/lib/shared/actor-feed";

const T0 = Date.parse("2026-11-20T08:00:00Z");
const at = (min: number) => new Date(T0 + min * 60_000).toISOString().slice(0, 23).replace("T", " ");
const row = (p: Partial<TraceRow> & { min: number }): TraceRow => ({
  section: "other", origin: "", target: "", target_kind: "source", dst_port: 0, source: "s", action: "a", actor: "alice",
  count: 1, fails: 0, first_ts: at(p.min), last_ts: at(p.min), ...p,
});
const ssh = (min: number, fails = 0) => row({ min, section: "login", origin: "10.8.0.5", target: "pve125", target_kind: "node", action: "auth.ssh", count: 1 + fails, fails, first_ok_ts: at(min) });
const sudo = (min: number, cmd: string, fails = 0) => row({ min, section: "host", target: "pve125", target_kind: "node", action: "priv.sudo", details: [cmd], fails, count: 1 });

test("строки ленты: понятный заголовок, кто/откуда/команды, свежие первыми, без сети", () => {
  const t = buildTrace([ssh(0), sudo(1, "qm list"), sudo(2, "qm start 171"),
    row({ min: 3, section: "network", origin: "10.8.0.5", target: "1.1.1.1", target_kind: "dst", action: "flow", actor: "" })]);
  const f = buildFeed(t);
  assert.deepEqual(f.map((i) => i.title), ["sudo на pve125", "Вход по SSH на pve125"]);
  assert.deepEqual(f[0].meta, ["alice", "после входа с 10.8.0.5", "qm list · qm start 171", "×2"]);
  assert.equal(f[0].flagged, false);
  assert.ok(f[0].href?.startsWith("/events?"));
});

test("отказы отмечены, полностью неудачный вход — «Неудачный вход»", () => {
  const t = buildTrace([row({ min: 0, section: "login", origin: "10.8.0.5", target: "pve125", target_kind: "node", action: "auth.ssh", count: 2, fails: 2 })]);
  const [it] = buildFeed(t);
  assert.equal(it.title, "Неудачный вход по SSH на pve125");
  assert.equal(it.flagged, true);
  assert.equal(it.badge, "отказ");
});

test("инцидент — отмеченная строка со ссылкой на инцидент", () => {
  const t = buildTrace([ssh(0)]);
  const f = buildFeed(t, { incidents: [{ id: "INC-7", level: "high", status: "open", rule_id: "r1", rule_title: "Подбор пароля", created_at: at(5) }] });
  assert.equal(f[0].kind, "incident");
  assert.equal(f[0].href, "/incidents/INC-7");
  assert.deepEqual(filterFeed(f, "flagged").map((i) => i.key), ["inc|INC-7"]);
  assert.deepEqual(filterFeed(f, "login").map((i) => i.kind), ["login"]);
});

test("фильтр из URL: неизвестное значение — «все»", () => {
  assert.equal(parseFeedFilter("flagged"), "flagged");
  assert.equal(parseFeedFilter("<script>"), "all");
  assert.equal(parseFeedFilter(undefined), "all");
});

test("дни и время справа в UTC", () => {
  const now = Date.parse("2026-11-20T12:00:00Z");
  assert.equal(dayLabel(now - 3600_000, now), "Сегодня");
  assert.equal(dayLabel(Date.parse("2026-11-19T23:59:00Z"), now), "Вчера");
  assert.equal(dayLabel(Date.parse("2026-11-17T10:00:00Z"), now), "2026-11-17");
  assert.equal(feedTime(now - 30_000, now), "только что");
  assert.equal(feedTime(now - 16 * 60_000, now), "16 мин назад");
  assert.equal(feedTime(now - 2 * 3600_000, now), "2 ч назад");
  assert.equal(feedTime(Date.parse("2026-11-19T18:24:00Z"), now), "18:24");
  const t = buildTrace([ssh(0), row({ min: 60 * 24, section: "app", target: "grafana", target_kind: "object", action: "app.authorize" })]);
  assert.deepEqual(groupByDay(buildFeed(t), Date.parse("2026-11-21T09:00:00Z")).map((d) => [d.day, d.items.length]), [["Сегодня", 1], ["Вчера", 1]]);
});
