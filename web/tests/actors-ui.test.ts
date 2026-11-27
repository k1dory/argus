// Правила интерфейса раздела «Субъекты»: начало действия привязки (по умолчанию —
// сегодня, «вся история» только флажком), предупреждения для общих учёток и
// адресов, человеческие подписи источника/пометки алиаса, порядок персон по риску.
import { test } from "node:test";
import assert from "node:assert/strict";
import {
  aliasNoteLabel, aliasSourceLabel, bindFromInput, bindRisk, byRisk, guessAliasKind, matchesPersonTab, sightingTitle, todayUtc,
} from "../src/lib/shared/actors-ui";

test("привязка: пустая дата без флажка — ошибка; флажок «на всю историю» — без даты; дата — как есть", () => {
  const empty = bindFromInput("", null);
  assert.equal(empty.ok, false, "пустая дата не означает молча «с начала журнала»");
  assert.match(!empty.ok ? empty.error : "", /на всю историю/);
  assert.equal(bindFromInput(null, null).ok, false);
  assert.deepEqual(bindFromInput("", "1"), { ok: true, from: null });
  assert.deepEqual(bindFromInput("2026-11-01", "1"), { ok: true, from: null }, "флажок главнее даты");
  assert.deepEqual(bindFromInput(" 2026-11-01 ", null), { ok: true, from: "2026-11-01" });
  assert.equal(todayUtc(Date.UTC(2026, 10, 27, 23, 59)), "2026-11-27");
});

test("привязка: предупреждения — общие учётки, IP и хост; обычный логин — без предупреждения", () => {
  assert.match(bindRisk("login", "root") ?? "", /общая системная учётка/);
  assert.match(bindRisk("login", "CORP\\Administrator") ?? "", /общая/);
  assert.match(bindRisk("ip", "10.0.0.5") ?? "", /IP-адрес часто общий/);
  assert.match(bindRisk("host", "ws-1") ?? "", /Хостом/);
  assert.equal(bindRisk("login", "i.petrov"), null);
  assert.equal(guessAliasKind("10.0.0.5"), "ip");
  assert.equal(guessAliasKind("a@b.c"), "email");
  assert.equal(guessAliasKind("hostgroup"), "login");
});

test("подписи: источник и пометка алиаса без машинных префиксов", () => {
  assert.equal(aliasSourceLabel("yaml"), "файл identities.yml");
  assert.equal(aliasSourceLabel("api"), "вручную в консоли");
  assert.equal(aliasSourceLabel("event:netbird"), "событие NetBird");
  assert.equal(aliasNoteLabel({ confidence: 0.3, note: "policy:hold:max-logins" }), "политика «max-logins»");
  assert.equal(aliasNoteLabel({ confidence: 1, note: "старый адрес" }), "старый адрес");
  assert.equal(sightingTitle({ source: "linux.auth", action: "auth.ssh", where: "ai2" }), "Вход по SSH на ai2");
  assert.equal(sightingTitle({ source: "linux.auth", action: "auth.ssh", where: "ai2", fails: 3, events: 3 }), "Неудачный вход по SSH на ai2");
  assert.equal(sightingTitle({ source: "linux.auth", action: "priv.sudo", where: "argus1" }), "sudo на argus1");
});

test("список: сначала инциденты, затем свежесть, без активности — в конце; вкладки", () => {
  const p = (person_id: string, incidents: number, last_ts: string | null, kind = "person") => ({ person_id, display: person_id, kind, events: last_ts ? 1 : 0, incidents, last_ts });
  const rows = [p("c", 0, null), p("b", 0, "2026-11-02 00:00:00"), p("a", 0, "2026-11-01 00:00:00"), p("d", 2, null), p("e", 1, "2026-10-01 00:00:00")];
  assert.deepEqual([...rows].sort(byRisk).map((r) => r.person_id), ["d", "e", "b", "a", "c"]);
  assert.equal(matchesPersonTab(p("x", 1, null), "incidents"), true);
  assert.equal(matchesPersonTab(p("x", 0, null), "active"), false);
  assert.equal(matchesPersonTab(p("x", 0, null, "service"), "service"), true);
});
