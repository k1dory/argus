// Подписи журнала и поиска: словарь действий, важность строки, шкала
// легенды по индексу (регрессия: на графике событий была шкала Wazuh 12+/7–11),
// «красивые» оси гистограммы и один список полей языка запросов.
import { test } from "node:test";
import assert from "node:assert/strict";
import { actionTitle, eventImportance, eventKind, isBadOutcome, outcomeWord } from "../src/lib/shared/event-labels";
import { SEVERITY, SEVERITY_MAX, severityBands } from "../src/lib/shared/severity";
import { bucketLabel, compactNum, niceCeil, timeTicks } from "../src/lib/shared/histogram";
import { addQueryTerm, QUERY_FIELDS, queryFieldLabel } from "../src/lib/shared/query-fields";
import { INDEXES } from "../src/lib/search";

test("словарь действий: фраза по исходу, правило Wazuh, неизвестное — как есть", () => {
  assert.deepEqual(actionTitle("auth.login", "failure"), { title: "Неудачный вход", known: true });
  assert.deepEqual(actionTitle("auth.login", "success"), { title: "Вход в систему", known: true });
  assert.equal(actionTitle("priv.sudo").title, "Команда через sudo");
  assert.equal(actionTitle("flow", "allow").title, "Сетевое соединение");
  assert.equal(actionTitle("flow", "deny").title, "Соединение заблокировано");
  assert.equal(actionTitle("user.change").title, "Изменена учётная запись");
  assert.equal(actionTitle("rule.5712").title, "Правило Wazuh 5712");
  assert.deepEqual(actionTitle("custom.thing"), { title: "custom.thing", known: false });
  assert.equal(actionTitle("").title, "Событие без действия");
  assert.equal(eventKind("auth.login"), "auth");
  assert.equal(eventKind("flow"), "net");
  assert.equal(eventKind("whatever", "k8s"), "k8s");
  assert.equal(outcomeWord("failure"), "неудача");
  assert.equal(outcomeWord("unknown"), "");
  assert.ok(isBadOutcome("deny") && !isBadOutcome("allow"));
});

test("важность строки — по порогам шкалы событий", () => {
  assert.equal(eventImportance(SEVERITY.events.critical), "err");
  assert.equal(eventImportance(10), "err");
  assert.equal(eventImportance(SEVERITY.events.high), "warn");
  assert.equal(eventImportance(SEVERITY.events.high - 1), null);
  assert.equal(eventImportance(0), null);
});

test("регрессия 2.1: легенда графика строится из шкалы своего индекса", () => {
  const ev = severityBands(SEVERITY.events, SEVERITY_MAX.events);
  assert.deepEqual(ev.map((b) => b.range), ["8–10", "5–7", "0–4"]);
  assert.ok(!ev.some((b) => /12/.test(b.range)), "у событий нет уровня 12+ — это шкала Wazuh");
  const al = severityBands(SEVERITY.alerts, SEVERITY_MAX.alerts);
  assert.deepEqual(al.map((b) => b.range), ["12–15", "7–11", "0–6"]);
  assert.deepEqual(ev.map((b) => b.label), ["критичные", "высокие", "остальные"]);
});

test("ось гистограммы: круглый верх, короткие числа, деления по календарю", () => {
  assert.equal(niceCeil(70_054), 75_000);
  assert.equal(niceCeil(14), 15);
  assert.equal(niceCeil(0), 1);
  assert.equal(compactNum(75_000).replace(/\s/g, " "), "75 тыс.");
  assert.equal(compactNum(37_500).replace(/\s/g, " "), "37,5 тыс.");
  assert.equal(compactNum(900), "900");
  assert.equal(bucketLabel(240), "4 ч");
  assert.equal(bucketLabel(30), "30 мин");
  // 7 дней — деление на каждые сутки «пн 23»
  const start = Date.UTC(2026, 10, 20, 8);
  const week = timeTicks(start, start + 7 * 86_400_000, 8);
  assert.equal(week.length, 7);
  assert.equal(week[0].label, "сб 21");
  // 24 часа — каждые 3 часа, полночь подписана днём
  const day = timeTicks(Date.UTC(2026, 10, 26, 10), Date.UTC(2026, 10, 27, 10), 8);
  assert.ok(day.length <= 8 && day.length >= 6);
  assert.ok(day.some((t) => t.label === "пт 27"), "полночь подписана днём");
  assert.ok(day.some((t) => t.label === "12:00"));
});

test("поля языка запросов: один список для шпаргалки и разбора поиска", () => {
  for (const index of ["events", "alerts"] as const) {
    assert.deepEqual(QUERY_FIELDS[index].map((f) => f.field).sort(), Object.keys(INDEXES[index].fields).sort(), `поля ${index} совпадают с lib/search`);
  }
  assert.equal(queryFieldLabel("events", "src"), "IP источника");
  assert.equal(queryFieldLabel("events", "attr.rule_groups"), "rule_groups");
  assert.equal(addQueryTerm("sshd", "src:10.20.*"), "sshd src:10.20.*");
  assert.equal(addQueryTerm("sshd src:10.20.*", "src:10.20.*"), "sshd src:10.20.*");
  assert.equal(addQueryTerm("", "sshd"), "sshd");
});
