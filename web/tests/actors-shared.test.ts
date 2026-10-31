// Паспорт субъекта — чистые функции: параметры, предикат по алиасам с
// интервалами, классификация событий, резолв, контракт identities, Markdown.
import { test } from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import path from "node:path";
import {
  ACTOR_KEYS_EXPR, actorMarkdown, aliasEventsQuery, aliasPrefilter, aliasInterval, canonicalIp, canonicalPhone, aliasPredicate, ambiguousAliases, bucketEvents, classifyEvent, clampWindow, holdPolicy, isHeld, isIp, isPhone, normalizeAliasValue, parseActorsParams, parseAliasInput, parseDateInput, parseIdentitiesDoc,
  primaryAlias, rangeWindow, resolveStatus, aliasKey, aliasMatches, activeAliases, ACTOR_KINDS, type ActorReport, type Alias,
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
    // identity.* — всегда «Изменения», независимо от исхода: алиасы и нарушения политики идентичности движка.
    ["identity.alias", "success", "identity", "change"], ["identity.policy.violation", "hold", "identity", "change"], ["identity.policy.violation", "", "", "change"],
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
    [{ persons: { x: { aliases: [{ kind: "badge", value: "1" }] } } }, "persons.x.aliases[0].kind"],
    [{ persons: { x: { aliases: [{ kind: "phone", value: "89991234567" }] } } }, "persons.x.aliases[0].value"],
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

test("телефон: E.164 — «+» и 8–15 цифр, пробелы/дефисы/скобки отбрасываются, регистр не трогается, сравнение с actor_name точное", () => {
  for (const [raw, want] of [
    ["+7 (999) 123-45-67", "+79991234567"], ["+79991234567", "+79991234567"], ["+1 415-555-0100", "+14155550100"], [" +44.20.7946.0958 ", "+442079460958"], ["+12345678", "+12345678"], ["+123456789012345", "+123456789012345"],
  ] as const) assert.equal(canonicalPhone(raw), want, raw);
  for (const bad of ["89991234567", "0079991234567", "+1234567", "+1234567890123456", "+7 999 abc", "+", "", "7(999)1234567", "+7 999 123 45 67 ext 12"]) assert.equal(canonicalPhone(bad), null, bad);
  assert.ok(isPhone("+7 999 123-45-67") && !isPhone("+1234567"));
  assert.equal(normalizeAliasValue("phone", "+7 (999) 123-45-67"), "+79991234567");
  assert.equal(normalizeAliasValue("phone", "not a phone"), "not a phone", "не разобрался — как есть, отказ даёт parseAliasInput");
  const ok = parseAliasInput({ kind: "phone", value: "+7 (999) 123-45-67", note: "рабочий" });
  assert.ok(ok.ok && ok.alias.value === "+79991234567" && ok.alias.kind === "phone");
  const bad = parseAliasInput({ kind: "phone", value: "8 999 123-45-67" });
  assert.ok(!bad.ok && bad.field === "value" && /E\.164/.test(bad.error));
  const doc = parseIdentitiesDoc({ persons: { x: { aliases: [{ kind: "phone", value: "+7 999 123 45 67" }] } } });
  assert.ok(doc.ok && doc.persons[0].aliases[0].value === "+79991234567");
  // Телефон — субъектный вид: колонка actor_name, точное сравнение (без lowerUTF8), ключ неоднозначности по actor_name.
  assert.ok(ACTOR_KINDS.includes("phone"));
  const a = alias({ kind: "phone", value: "+79991234567" });
  assert.equal(aliasKey(a), "actor_name\u0000+79991234567");
  const w = { fromMs: NOW - 7 * DAY, toMs: NOW };
  const pred = aliasPredicate([a], w);
  assert.ok(pred.sql.startsWith("((actor_name = {a0:String}") && pred.params.a0 === "+79991234567", pred.sql);
  assert.ok(aliasMatches(a, "+7 (999) 123-45-67") && !aliasMatches(a, "+79991234568"));
  assert.equal(aliasEventsQuery(a), "actor:+79991234567", "кавычки — только где нужны");
  assert.equal(primaryAlias([a, alias({ kind: "ip", value: "10.0.0.1" })])?.kind, "phone", "телефон — субъектный, впереди хоста и адреса");
  assert.equal(primaryAlias([a, alias({ kind: "login", value: "x" })])?.kind, "login");
});

test("алиасы на удержании: confidence < 0.5 — видны, но не сшивают: предикат, неоднозначность, основной алиас, Markdown", () => {
  const held = alias({ kind: "login", value: "held_bot", confidence: 0.3, note: "policy:hold:max_logins", source: "event:idp" });
  const live = alias({ kind: "login", value: "ipetrov" });
  assert.ok(isHeld(held) && !isHeld(live) && !isHeld(alias({ kind: "login", value: "x", confidence: 0.5 })), "порог — строго меньше 0.5");
  assert.equal(holdPolicy(held), "max_logins");
  assert.equal(holdPolicy(alias({ kind: "login", value: "x", confidence: 0.2, note: "" })), null, "удержан без пометки — политика неизвестна");
  assert.equal(holdPolicy(alias({ kind: "login", value: "x", confidence: 0.2, note: "ручная заметка" })), "ручная заметка");
  assert.equal(holdPolicy(live), null);
  assert.deepEqual(activeAliases([held, live]), [live]);
  const w = { fromMs: NOW - 7 * DAY, toMs: NOW };
  const pred = aliasPredicate([held, live], w);
  assert.equal(Object.keys(pred.params).length, 3, "удержанный алиас в предикат не попал, нумерация без дыр");
  assert.equal(pred.params.a0, "ipetrov");
  assert.deepEqual(aliasPredicate([held], w), { sql: "0", params: {} }, "только удержанные — ни одной строки");
  // Удержанный алиас у второй персоны не делает значение неоднозначным.
  const other = alias({ kind: "login", value: "ipetrov", person_id: "b", confidence: 0.1, note: "policy:hold:x" });
  assert.equal(ambiguousAliases([live, other], w).size, 0);
  assert.equal(primaryAlias([held])?.value, undefined, "ссылка в журнал — не по удержанному");
  assert.equal(primaryAlias([held, alias({ kind: "ip", value: "10.0.0.5" })])?.kind, "ip");
  const report: ActorReport = {
    person: { person_id: "i.petrov", display: "Иван", kind: "person", team: "", note: "" },
    aliases: [live, held], ambiguous: [],
    range: { key: "7d", from: "2026-10-17 12:00:00.000", to: "2026-10-24 12:00:00.000" },
    summary: { events: 0, by_source_class: {}, nodes: [], src_ips: [], incidents: 0 },
    sources: [], sections: bucketEvents([]), incidents: [], timeline: [], limit: 200, missing: [], generated_at: "2026-10-24 12:00:00.000",
  };
  const md = actorMarkdown(report);
  assert.ok(md.includes("| login | held\\_bot (на удержании: max\\_logins) | "), md);
  assert.ok(md.includes("Алиасы «на удержании»"), "раздел «чего нет в данных» объясняет удержание");
});

test("aliasPrefilter: hasAny по ключам индекса idx_actor_keys, регистр по виду, удержанные мимо, кавычки экранированы", () => {
  const mk = (kind: Alias["kind"], value: string, confidence = 1): Alias => ({ person_id: "p", kind, value, valid_from: "2026-10-01 00:00:00.000", valid_to: null, source: "yaml", confidence, note: "" });
  const pf = aliasPrefilter([mk("email", "A@X.org"), mk("login", "o'neil"), mk("ip", "10.0.0.5"), mk("uid", "Authentik:7"), mk("login", "held", 0.3), mk("host", "SRV1")]);
  assert.equal(pf.sql, `hasAny(${ACTOR_KEYS_EXPR}, {pf_keys:Array(String)})`);
  // Выражение совпадает с индексом миграции дословно — иначе ClickHouse его не применит.
  const migration = readFileSync(path.join(__dirname, "../../clickhouse/migrations/0032_events_actor_keys_index.sql"), "utf8");
  assert.ok(migration.includes(`idx_actor_keys ${ACTOR_KEYS_EXPR} TYPE bloom_filter`), "ACTOR_KEYS_EXPR = выражение индекса");
  const all = pf.params.pf_keys as string;
  assert.ok(all.includes("'o\\'neil'"), all);
  assert.ok(all.includes("'a@x.org'") && all.includes("'srv1'"), "email/host — в нижнем регистре, как в точном предикате");
  assert.ok(all.includes("'Authentik:7'"), "uid — как есть");
  assert.ok(!all.includes("held"));
  assert.ok(!pf.sql.includes("a@x.org"), "значения только параметрами");
  assert.equal(aliasPrefilter([]).sql, "0");
});
