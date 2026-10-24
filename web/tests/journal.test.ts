import { test } from "node:test";
import assert from "node:assert/strict";
import {
  activeChips,
  advanceCursor,
  fillBars,
  formatTailCursor,
  ID_MAX,
  mergeTail,
  parseTailCursor,
  journalHref,
  journalQuery,
  matchIncidents,
  parseJournalParams,
  prettyRaw,
  TAIL_SEAL_SEC,
  tokenizeJsonLine,
  withTerm,
  type IncidentRef,
  type JournalEvent,
  type TailCursor,
} from "../src/lib/shared/journal";
import { buildWhere } from "../src/lib/search";

test("параметры URL → фильтры: мусор отбрасывается", () => {
  const f = parseJournalParams({ q: " sshd ", range: "7d", source: "waf.coraza", host: "", sev: "42", rule: "5763", from: "2026-10-12T10:00", to: "bad", page: "3" });
  assert.equal(f.range, "7d");
  assert.equal(f.source, "waf.coraza");
  assert.equal(f.host, undefined);
  assert.equal(f.sev, undefined); // вне 1..10
  assert.equal(f.from, "2026-10-12T10:00");
  assert.equal(f.to, undefined);
  assert.equal(f.page, 3);
  assert.equal(parseJournalParams(new URLSearchParams("sev=5")).sev, 5);
});

test("структурные фильтры попадают в язык запроса с кавычками", () => {
  const q = journalQuery({ q: "sshd", range: "24h", source: "wazuh.agents", host: "my host", sev: 8, rule: "a41c-auth-030" });
  assert.equal(q, 'sshd source:wazuh.agents node:"my host" rule:a41c-auth-030 severity>=8');
});

test("URL журнала: диапазон по умолчанию и первая страница не пишутся, patch сбрасывает страницу", () => {
  const f = parseJournalParams({ q: "x", source: "s", page: "4" });
  assert.equal(journalHref(f, { host: "web-01" }), "/events?q=x&source=s&host=web-01");
  assert.equal(journalHref(f, { page: 2 }), "/events?q=x&source=s&page=2");
  assert.equal(journalHref({ q: "", range: "24h" }), "/events");
  assert.deepEqual(activeChips({ ...f, sev: 5 }).map((c) => c.key), ["source", "sev"]);
});

test("withTerm: добавление и исключение без дублей", () => {
  assert.equal(withTerm("sshd", "src", "10.0.0.1"), "sshd src:10.0.0.1");
  assert.equal(withTerm("sshd", "outcome", "allow", true), "sshd -outcome:allow");
  assert.equal(withTerm("-outcome:allow", "outcome", "allow", true), "-outcome:allow");
});

test("гистограмма: пустые корзины достраиваются до границ окна, высоты из чисел", () => {
  const start = Date.parse("2026-10-12T10:00:00Z");
  const bars = fillBars(
    [{ bucket: "2026-10-12 11:00:00", low: 1, high: 2, critical: 3 }],
    30,
    start + 5 * 60_000,
    Date.parse("2026-10-12T12:10:00Z"),
  );
  assert.equal(bars[0].bucket, "2026-10-12 10:00:00");
  assert.equal(bars.at(-1)!.bucket, "2026-10-12 12:00:00");
  assert.equal(bars.length, 5);
  assert.equal(bars[2].total, 6);
  assert.equal(bars[2].from, "2026-10-12T11:00");
  assert.equal(bars[2].to, "2026-10-12T11:30");
  assert.deepEqual(fillBars([], 30, start, start + 3_600_000), []);
});

test("событие ↔ инцидент: источник, окно ±1 с, узел или субъект", () => {
  const inc: IncidentRef = {
    incident_id: "INC-18", rule_id: "a41c-waf-050", rule_title: "SQLi", level: "high", status: "new",
    node: "shop.example.org", actor_name: "203.0.113.9", sources: ["waf.modsecurity"],
    first_ts: "2026-10-12 18:11:50.000", last_ts: "2026-10-12 18:15:30.000",
  };
  const ev = (id: string, time: string, source = "waf.modsecurity", node = "other", src_ip = "") => ({ id, time, source, node, actor_name: "", src_ip, object: "" });
  const m = matchIncidents(
    [
      ev("in-window-node", "2026-10-12 18:12:00.000", "waf.modsecurity", "shop.example.org"),
      ev("by-subject", "2026-10-12 18:15:30.500", "waf.modsecurity", "x", "203.0.113.9"),
      ev("late", "2026-10-12 18:20:00.000", "waf.modsecurity", "shop.example.org"),
      ev("other-source", "2026-10-12 18:12:00.000", "waf.coraza", "shop.example.org"),
    ],
    [inc],
  );
  assert.deepEqual(Object.keys(m).sort(), ["by-subject", "in-window-node"]);
});

test("сырое событие: JSON красиво и токенизируется, текст остаётся текстом", () => {
  assert.equal(prettyRaw("Oct 12 sshd[1]: Failed password"), null);
  const pretty = prettyRaw('{"a":"x:y","n":-1.5e3,"ok":true,"z":null}')!;
  const kinds = pretty.split("\n").flatMap((l) => tokenizeJsonLine(l)).filter((t) => t.t !== "ws" && t.t !== "punct");
  assert.deepEqual(kinds.map((t) => `${t.t}:${t.v}`), ['key:"a"', 'str:"x:y"', 'key:"n"', "num:-1500", 'key:"ok"', "lit:true", 'key:"z"', "lit:null"]);
  const line = '  "k": "v",';
  assert.equal(tokenizeJsonLine(line).map((t) => t.v).join(""), line);
});

test("поле rule: правило Wazuh — по action, корреляции — через инциденты", () => {
  const wazuh = buildWhere({ index: "events", q: "rule:5763", range: "24h", page: 1 });
  assert.equal(wazuh.error, null);
  assert.match(wazuh.where, /action = concat\('rule\.', \{p0:String\}\)/);
  assert.equal(wazuh.params.p0, "5763");
  const corr = buildWhere({ index: "events", q: "-rule:a41c-*", range: "24h", page: 1 });
  assert.match(corr.where, /NOT \(arrayExists\(w -> source = w\.1 AND node = w\.2 AND ts >= w\.3 AND ts <= w\.4, /);
  assert.match(corr.where, /WHERE rule_id ILIKE \{p0:String\}/);
  assert.equal(corr.params.p0, "a41c-%");
  assert.equal(buildWhere({ index: "events", q: "rule>5", range: "24h", page: 1 }).error, "для поля «rule» допустимы только = и !=");
});

const evt = (i: number, received: string): JournalEvent => ({
  id: String(1000 + i), time: received, received, severity: 1, source: "s", source_class: "c", vendor: "", product: "", action: "a", outcome: "",
  actor_name: "", actor_kind: "", object: "", node: "n", session_id: "", src_ip: "", src_port: 0, dst_ip: "", dst_port: 0, proto: "",
  bytes: 0, packets: 0, value: 0, unit: "", pii: 0, attrs: {}, raw: "",
});

/** Модель запроса tail: (received_at, id) > курсора, по возрастанию, LIMIT; при clock —
 *  только закрытые секунды received_at < now − seal. id в тесте — числа одной длины, сравнение строк корректно. */
function serverTail(all: JournalEvent[], c: TailCursor, limit: number, clock?: { now: string; seal: number }) {
  const sealedBefore = clock ? new Date(Date.parse(clock.now.replace(" ", "T") + "Z") - clock.seal * 1000).toISOString().slice(0, 19).replace("T", " ") : null;
  const after = all
    .filter((e) => sealedBefore === null || e.received < sealedBefore)
    .filter((e) => e.received > c.at || (e.received === c.at && e.id > c.after))
    .sort((a, b) => (a.received === b.received ? (a.id < b.id ? -1 : 1) : a.received < b.received ? -1 : 1));
  const rows = after.slice(0, limit);
  return { rows, more: rows.length === limit, cursor: advanceCursor(c, rows) };
}

test("tail: всплеск 350 событий в одну секунду догоняется порциями по 100 без потерь и дублей", () => {
  const burst = Array.from({ length: 350 }, (_, i) => evt(i, "2026-10-12 19:00:01"));
  let cursor: TailCursor = { at: "2026-10-12 19:00:00", after: "0" };
  let state = { rows: [] as JournalEvent[], seen: new Set<string>() };
  let requests = 0;
  for (;;) {
    const r = serverTail(burst, cursor, 100);
    requests++;
    cursor = r.cursor;
    state = mergeTail(state, r.rows, 1000);
    if (!r.more) break;
  }
  assert.equal(requests, 4); // 100 + 100 + 100 + 50
  assert.equal(state.rows.length, 350);
  assert.equal(new Set(state.rows.map((r) => r.id)).size, 350);
  assert.equal(state.rows[0].id, "1349"); // новые сверху
  assert.deepEqual(cursor, { at: "2026-10-12 19:00:01", after: "1349" });
  assert.equal(serverTail(burst, cursor, 100).rows.length, 0);
});

test("mergeTail: дубли отброшены, лимит строк, seen пересобирается вместе с rows", () => {
  const initial = [evt(2, "2026-10-12 19:00:00"), evt(1, "2026-10-12 19:00:00")];
  const m = mergeTail({ rows: initial, seen: new Set(initial.map((r) => r.id)) }, [evt(2, "2026-10-12 19:00:00"), evt(3, "2026-10-12 19:00:01"), evt(4, "2026-10-12 19:00:02")], 3);
  assert.deepEqual(m.added.map((r) => r.id), ["1003", "1004"]);
  assert.deepEqual(m.rows.map((r) => r.id), ["1004", "1003", "1002"]);
  assert.equal(m.trimmed, 1);
  assert.deepEqual([...m.seen].sort(), ["1002", "1003", "1004"]);
});

test("курсор tail: формат «received_at|UInt64», мусор отклоняется", () => {
  const c = { at: "2026-10-12 19:00:01", after: "18446744073709551615" };
  assert.deepEqual(parseTailCursor(formatTailCursor(c)), c);
  assert.equal(parseTailCursor("2026-10-12 19:00:01|18446744073709551616"), null);
  assert.equal(parseTailCursor("2026-10-12T19:00:01|1"), null);
  assert.equal(parseTailCursor("2026-10-12 19:00:01|1; DROP"), null);
  assert.equal(parseTailCursor(null), null);
  assert.deepEqual(advanceCursor(c, []), c);
});

test("tail: пачка, ставшая видимой позже в той же секунде, не теряется — секунда читается после закрытия", () => {
  const second = "2026-10-12 19:00:01";
  // Первая пачка видна сразу; вторая фиксируется в ClickHouse позже в ту же секунду, и её id меньше.
  const first = Array.from({ length: 50 }, (_, i) => evt(500 + i, second));
  const late = Array.from({ length: 50 }, (_, i) => evt(i, second));
  const run = (seal: number | null) => {
    let cursor: TailCursor = { at: "2026-10-12 19:00:00", after: ID_MAX };
    let state = { rows: [] as JournalEvent[], seen: new Set<string>() };
    const poll = (visible: JournalEvent[], now: string) => {
      const r = serverTail(visible, cursor, 100, seal === null ? undefined : { now, seal });
      cursor = r.cursor;
      state = mergeTail(state, r.rows, 1000);
    };
    poll(first, "2026-10-12 19:00:01"); // опрос внутри секунды: видна только первая пачка
    poll([...first, ...late], "2026-10-12 19:00:02");
    poll([...first, ...late], "2026-10-12 19:00:05");
    return state.rows.length;
  };
  assert.equal(run(null), 50); // старый курсор без запаса: вторая пачка позади курсора — потеряна
  assert.equal(run(TAIL_SEAL_SEC), 100);
});
