// Паспорт субъекта — чистые функции: параметры, предикат по алиасам с
// интервалами, классификация событий, резолв, контракт identities, Markdown.
import { test } from "node:test";
import assert from "node:assert/strict";
import {
  actorMarkdown, aliasEventsQuery, aliasInterval, canonicalIp, aliasPredicate, ambiguousAliases, bucketEvents, classifyEvent, clampWindow, isIp, parseActorsParams, parseAliasInput, parseDateInput, parseIdentitiesDoc,
  primaryAlias, rangeWindow, resolveStatus, aliasKey, type ActorReport, type Alias,
} from "../src/lib/shared/actors";
import { toLogItem } from "../src/lib/shared/log-query";

const NOW = Date.parse("2026-10-24T12:00:00Z");
const DAY = 86_400_000;
const alias = (p: Partial<Alias> & Pick<Alias, "kind" | "value">): Alias => ({
  person_id: "i.petrov", valid_from: "2026-10-01 00:00:00.000", valid_to: null, source: "yaml", confidence: 1, note: "", ...p,
});

test("параметры: range 24h|7d|30d (по умолчанию 7d), limit 1…500 (по умолчанию 200)", () => {
  const def = parseActorsParams(new URLSearchParams(""));
  assert.deepEqual(def, { ok: true, params: { range: "7d", limit: 200 } });
  const full = parseActorsParams(new URLSearchParams("range=30d&limit=5"));
  assert.deepEqual(full, { ok: true, params: { range: "30d", limit: 5 } });
  for (const bad of ["range=1h", "range=90d", "limit=0", "limit=501", "limit=x"]) assert.equal(parseActorsParams(new URLSearchParams(bad)).ok, false, bad);
  const w = rangeWindow("7d", NOW);
  assert.equal(w.toMs - w.fromMs, 7 * DAY);
  const wide = clampWindow({ fromMs: NOW - 90 * DAY, toMs: NOW });
  assert.equal(wide.toMs - wide.fromMs, 30 * DAY, "окно не шире 30 дней");
});

test("предикат: колонка по виду, интервалы обрезаны окном, открытый valid_to — до конца окна, только параметры", () => {
  const w = { fromMs: NOW - 7 * DAY, toMs: NOW };
  const aliases = [
    alias({ kind: "login", value: "ipetrov" }), // открыт, начало до окна → всё окно
    alias({ kind: "ip", value: "10.77.0.11", valid_from: "2026-10-20 00:00:00.000", valid_to: "2026-10-22 00:00:00.000" }), // внутри окна
    alias({ kind: "host", value: "wks-07", valid_from: "2026-10-01 00:00:00.000", valid_to: "2026-10-10 00:00:00.000" }), // закончился до окна → пропуск
    alias({ kind: "email", value: "i.petrov@example.org", valid_from: "2026-10-23 00:00:00.000" }), // начался внутри окна
  ];
  const { sql, params } = aliasPredicate(aliases, w);
  // login/email/host сравниваются без учёта регистра (колонка приводится lowerUTF8), ip/uid — точно.
  assert.match(sql, /^\(\(lowerUTF8\(actor_name\) = \{a0:String\} AND ts >= parseDateTime64BestEffort\(\{f0:String\}, 3, 'UTC'\) AND ts < parseDateTime64BestEffort\(\{t0:String\}, 3, 'UTC'\)\) OR \(src_ip = \{a1:String\}.* OR \(lowerUTF8\(actor_name\) = \{a2:String\}.*\)$/);
  const uid = aliasPredicate([alias({ kind: "uid", value: "S-1-5-21" }), alias({ kind: "host", value: "wks-07" })], w);
  assert.ok(uid.sql.includes("(actor_name = {a0:String}") && uid.sql.includes("(lowerUTF8(node) = {a1:String}"), uid.sql);
  const inc = aliasPredicate([aliases[0]], w, "q", "first_ts");
  assert.ok(inc.sql.includes("first_ts >= parseDateTime64BestEffort({qf0:String}") && !inc.sql.includes(" ts "), "колонка времени — first_ts для инцидентов");
  assert.ok(!sql.includes("node ="), "host-алиас вне окна не попал в предикат");
  assert.ok(!sql.includes("ipetrov") && !sql.includes("10.77"), "значения не в тексте SQL");
  assert.equal(params.a0, "ipetrov");
  assert.equal(params.f0, "2026-10-17 12:00:00.000", "начало раньше окна → начало окна");
  assert.equal(params.t0, "2026-10-24 12:00:00.000", "открытый valid_to → конец окна");
  assert.equal(params.a1, "10.77.0.11");
  assert.equal(params.f1, "2026-10-20 00:00:00.000");
  assert.equal(params.t1, "2026-10-22 00:00:00.000");
  assert.equal(params.a2, "i.petrov@example.org");
  assert.equal(params.f2, "2026-10-23 00:00:00.000");
  assert.equal(Object.keys(params).length, 9);
  assert.deepEqual(aliasPredicate([], w), { sql: "0", params: {} }, "без алиасов — ни одной строки");
  const pref = aliasPredicate([aliases[0]], w, "x");
  assert.ok(pref.sql.includes("{xa0:String}") && "xa0" in pref.params, "префикс параметров");
  // Потолок 30 дней действует и внутри предиката.
  const capped = aliasPredicate([alias({ kind: "login", value: "old", valid_from: "2025-01-01 00:00:00.000" })], { fromMs: NOW - 400 * DAY, toMs: NOW });
  assert.equal(capped.params.f0, "2026-09-24 12:00:00.000");
  assert.equal(aliasInterval(alias({ kind: "login", value: "x", valid_from: "2026-10-25 00:00:00.000" }), w), null, "будущий алиас — вне окна");
});

test("неоднозначность: общий алиас с пересечением интервалов у двух персон — да, передача адреса без пересечения — нет", () => {
  const w = { fromMs: NOW - 30 * DAY, toMs: NOW };
  const handedOver = [
    alias({ kind: "ip", value: "10.0.0.5", person_id: "a", valid_from: "2026-10-01 00:00:00.000", valid_to: "2026-10-15 00:00:00.000" }),
    alias({ kind: "ip", value: "10.0.0.5", person_id: "b", valid_from: "2026-10-15 00:00:00.000" }),
  ];
  assert.equal(ambiguousAliases(handedOver, w).size, 0);
  const shared = [handedOver[0], alias({ kind: "ip", value: "10.0.0.5", person_id: "b", valid_from: "2026-10-10 00:00:00.000" })];
  assert.deepEqual([...ambiguousAliases(shared, w)], [aliasKey(shared[0])]);
  assert.equal(ambiguousAliases([alias({ kind: "login", value: "x", person_id: "a" }), alias({ kind: "login", value: "x", person_id: "a", valid_from: "2026-10-20 00:00:00.000" })], w).size, 0, "одна персона — не неоднозначность");
  // Ключ — целевая колонка + нормализованное значение: login=alice и uid=alice разных людей
  // сопоставляются с одним actor_name и получают одни события.
  const cross = [alias({ kind: "login", value: "alice", person_id: "a" }), alias({ kind: "uid", value: "alice", person_id: "b" })];
  assert.deepEqual([...ambiguousAliases(cross, w)], ["actor_name\u0000alice"]);
  assert.equal(aliasKey(cross[0]), aliasKey(cross[1]));
  // Регистр приводится только у email/login/host (как в предикате): uid=Alice и uid=alice — разные субъекты.
  assert.equal(ambiguousAliases([alias({ kind: "uid", value: "Alice", person_id: "a" }), alias({ kind: "uid", value: "alice", person_id: "b" })], w).size, 0);
  assert.equal(aliasKey(alias({ kind: "login", value: "Alice" })), aliasKey(alias({ kind: "email", value: "ALICE" })), "login/email — в нижнем регистре");
  assert.equal(aliasKey(alias({ kind: "sid", value: "S-1-5-21" })), "actor_name\u0000S-1-5-21");
  assert.notEqual(aliasKey(alias({ kind: "host", value: "alice" })), aliasKey(cross[0]), "host сравнивается с node — другая колонка");
  assert.equal(aliasKey(alias({ kind: "ip", value: "10.0.0.5" })), "src_ip\u000010.0.0.5");
});

test("классификация событий — нейтральные шаблоны, без вендоров", () => {
  const cases: [string, string, string, string][] = [
    ["auth.login", "success", "idp", "login"], ["user.logon", "failure", "windows", "login"], ["sshd.accept", "success", "syslog", "login"],
    ["priv.escalate", "success", "edr", "host"], ["sudo.run", "success", "syslog", "host"], ["session.open", "success", "syslog", "host"], ["pam.su", "failure", "syslog", "host"],
    ["flow", "allow", "netflow", "network"], ["session.allow", "allow", "ngfw", "network"], ["net.connect", "deny", "edr", "network"],
    ["app.open", "success", "idp", "app"], ["oauth.token", "success", "idp", "app"], ["authorize.application", "success", "idp", "app"],
    ["rbac.change", "success", "k8s", "change"], ["user.delete", "success", "idp", "change"], ["user.delete", "failure", "idp", "other"],
    ["process.create", "success", "edr", "change"], ["issue.resolved", "success", "ci", "other"], ["result", "success", "x", "other"],
  ];
  for (const [action, outcome, cls, want] of cases) assert.equal(classifyEvent(action, outcome, cls), want, `${action}/${outcome}/${cls}`);
  const items = [toLogItem({ action: "auth.login", outcome: "success" }), toLogItem({ action: "deploy", outcome: "success" })];
  const b = bucketEvents(items);
  assert.equal(b.login.length, 1);
  assert.equal(b.other.length, 1);
});

test("резолв: 0 → unbound, 1 → resolved, >1 персон → ambiguous (две записи одной персоны — resolved)", () => {
  assert.equal(resolveStatus([]), "unbound");
  assert.equal(resolveStatus([{ person_id: "a" }]), "resolved");
  assert.equal(resolveStatus([{ person_id: "a" }, { person_id: "a" }]), "resolved");
  assert.equal(resolveStatus([{ person_id: "a" }, { person_id: "b" }]), "ambiguous");
});

test("контракт identities: person_id, виды, адрес, нижний регистр, даты, путь ошибки", () => {
  const ok = parseIdentitiesDoc({ persons: { "i.petrov": { display: "Иван Петров", team: "platform", aliases: [
    { kind: "email", value: "I.Petrov@Example.org" }, { kind: "login", value: "IPetrov", from: "2026-10-01", to: "2026-10-20T10:00:00Z", confidence: 0.8 }, { kind: "ip", value: "10.77.0.11" }, { kind: "uid", value: "S-1-5-21" },
  ] } } });
  assert.ok(ok.ok, JSON.stringify(ok));
  const p = ok.persons[0];
  assert.equal(p.kind, "person");
  assert.equal(p.aliases[0].value, "i.petrov@example.org", "email — в нижний регистр");
  assert.equal(p.aliases[1].value, "ipetrov");
  assert.equal(p.aliases[1].valid_from, "2026-10-01 00:00:00.000");
  assert.equal(p.aliases[1].valid_to, "2026-10-20 10:00:00.000");
  assert.equal(p.aliases[1].confidence, 0.8);
  assert.equal(p.aliases[3].value, "S-1-5-21", "uid — как есть");
  const cases: [unknown, string][] = [
    [{ persons: { "Bad Id": {} } }, "persons.Bad Id"],
    [{ persons: { x: { kind: "robot" } } }, "persons.x.kind"],
    [{ persons: { x: { aliases: [{ kind: "ip", value: "10.0.0.999" }] } } }, "persons.x.aliases[0].value"],
    [{ persons: { x: { aliases: [{ kind: "ip", value: "not-an-ip" }] } } }, "persons.x.aliases[0].value"],
    [{ persons: { x: { aliases: [{ kind: "phone", value: "1" }] } } }, "persons.x.aliases[0].kind"],
    [{ persons: { x: { aliases: [{ kind: "login", value: "a", from: "вчера" }] } } }, "persons.x.aliases[0].from"],
    [{ persons: { x: { aliases: [{ kind: "login", value: "a", from: "2026-10-20", to: "2026-10-01" }] } } }, "persons.x.aliases[0].to"],
    [{ persons: { x: { aliases: [{ kind: "login", value: "a", confidence: 7 }] } } }, "persons.x.aliases[0].confidence"],
    [{ persons: { x: { aliases: [{ kind: "email", value: "nope" }] } } }, "persons.x.aliases[0].value"],
    [{ persons: {} }, "persons"],
    [[], ""],
  ];
  for (const [doc, path] of cases) {
    const r = parseIdentitiesDoc(doc);
    assert.equal(r.ok, false, JSON.stringify(doc));
    if (!r.ok) assert.equal(r.path, path, JSON.stringify(doc));
  }
  assert.ok(isIp("192.168.0.1") && isIp("2001:db8::1") && isIp("::1") && !isIp("1.2.3") && !isIp("01.2.3.4") && !isIp("2001:db8") && !isIp("a:b:c:d:e:f:g:h") && !isIp("1:2:3:4:5:6:7:8:9") && !isIp("::1::2"));
  // Каноническая форма — как netip у движка: сжатие, строчные, без зоны, mapped → IPv4.
  for (const [raw, want] of [
    ["2001:0DB8:0000:0000:0000:0000:0000:0001", "2001:db8::1"], ["2001:db8:0:0:1:0:0:1", "2001:db8::1:0:0:1"], ["fe80::1%eth0", "fe80::1"],
    ["::ffff:10.0.0.5", "10.0.0.5"], ["::ffff:a00:5", "10.0.0.5"], ["0:0:0:0:0:0:0:0", "::"], ["1:0:0:2:0:0:0:3", "1:0:0:2::3"], ["2001:db8:1:2:3:4:5:6", "2001:db8:1:2:3:4:5:6"],
    ["10.0.0.5", "10.0.0.5"],
  ] as const) assert.equal(canonicalIp(raw), want, raw);
  const ip6 = parseAliasInput({ kind: "ip", value: "2001:DB8::0001" });
  assert.ok(ip6.ok && ip6.alias.value === "2001:db8::1");
  assert.equal(parseDateInput("2026-10-24T12:00:00+03:00"), "2026-10-24 09:00:00.000");
  assert.equal(parseDateInput("24.10.2026"), null);
  const a = parseAliasInput({ kind: "host", value: "WKS-07.Example.ORG" });
  assert.ok(a.ok && a.alias.value === "wks-07.example.org" && a.alias.valid_from === null);
});

test("ссылка в журнал: по одному алиасу, поле по виду, значение в кавычках", () => {
  assert.equal(aliasEventsQuery({ kind: "login", value: "svc-*" }), 'actor:"svc-\\*"');
  assert.equal(aliasEventsQuery({ kind: "ip", value: "10.0.0.5" }), "src:10.0.0.5", "кавычки — только где нужны");
  assert.equal(aliasEventsQuery({ kind: "host", value: "wks 07" }), 'node:"wks 07"');
  const aliases = [alias({ kind: "ip", value: "10.0.0.5" }), alias({ kind: "login", value: "old", valid_to: "2026-10-02 00:00:00.000" }), alias({ kind: "login", value: "cur" })];
  assert.equal(primaryAlias(aliases)?.value, "cur", "действующий login прежде закрытого и адреса");
});

test("Markdown: значения экранированы, разделы на месте, недоступные данные отмечены", () => {
  const ev = toLogItem({ ts: "2026-10-24 11:00:00.000", source: "idp.example", source_class: "identity", action: "auth.login", outcome: "success", severity: 2, actor_name: "ipetrov", node: "web-01", src_ip: "10.0.0.9", object: "[portal] *admin* <script>" });
  const report: ActorReport = {
    person: { person_id: "i.petrov", display: "Иван *Петров* [x]", kind: "person", team: "platform", note: "строка\nс переводом" },
    aliases: [alias({ kind: "login", value: "ipetrov" }), alias({ kind: "ip", value: "10.0.0.5", valid_to: "2026-10-20 00:00:00.000" })],
    ambiguous: [aliasKey({ kind: "ip", value: "10.0.0.5" })], // ключ — колонка + значение
    range: { key: "7d", from: "2026-10-17 12:00:00.000", to: "2026-10-24 12:00:00.000" },
    summary: { events: 3, by_source_class: { identity: 2, syslog: 1 }, nodes: [{ node: "web-01", count: 3, first_ts: "", last_ts: "" }], src_ips: [], incidents: 1 },
    sources: [{ source: "idp.example", source_class: "identity", count: 2, first_ts: "2026-10-20 00:00:00.000", last_ts: "2026-10-24 11:00:00.000" }],
    sections: bucketEvents([ev]),
    incidents: [{ id: "INC-7", level: "high", status: "new", rule_id: "r-1", rule_title: "Вход _ночью_", created_at: "2026-10-23 01:00:00" }],
    timeline: [ev], limit: 200, missing: ["адреса"], generated_at: "2026-10-24 12:00:00.000",
  };
  const md = actorMarkdown(report);
  assert.ok(md.startsWith("# Паспорт субъекта — Иван \\*Петров\\* \\[x\\]\n"));
  assert.ok(md.includes("- Заметка: строка с переводом"), "перевод строки схлопнут");
  assert.ok(md.includes("| ip | 10\\.0\\.0\\.5 (неоднозначно) | 2026\\-10\\-01 00:00:00\\.000 | 2026\\-10\\-20 00:00:00\\.000 | yaml | 1 |"));
  assert.ok(md.includes("\\[portal\\] \\*admin\\* <script\\>"), "объект события экранирован");
  assert.ok(md.includes("Часть данных недоступна: адреса."));
  assert.ok(md.includes("## Входы\n\n- 2026\\-10\\-24 11:00:00\\.000 · idp\\.example · auth\\.login · success · субъект ipetrov · узел web\\-01 · с 10\\.0\\.0\\.9"));
  assert.ok(md.includes("## Хосты и сеансы\n\nНет событий этого раздела"));
  assert.ok(md.includes("- INC\\-7 · high · new · r\\-1 · Вход \\_ночью\\_ · 2026\\-10\\-23 01:00:00 UTC"));
  assert.ok(md.includes("## Источники данных и их период") && md.includes("| idp\\.example | identity | 2 |"));
  assert.ok(md.includes("## Чего нет в данных") && md.includes("неоднозначно» в окне делятся"));
  assert.ok(!md.includes("\n# ") || md.indexOf("\n# ") === -1, "никакая строка данных не стала заголовком");
});
