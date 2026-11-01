// Диапазонные фильтры консоли: разбор URL (мусор отбрасывается, ничего не
// бросает), условия ClickHouse только параметрами и подписи активных фильтров.
import { test } from "node:test";
import assert from "node:assert/strict";
import {
  hasRange, inOrdinal, inRange, inTime, INCIDENT_LEVELS, numConditions, ordinalConditions, parseDtParam, parseNumRange,
  parseOrdinalRange, parseTimeFilter, patchHref, timeBounds, timeCondition, timeLabel, toDtParam, VULN_SEVERITIES,
  type Params,
} from "../src/lib/shared/filters";
import {
  agentRangeChips, alertRangeChips, incidentRangeChips, isEmptyIncidentRanges, parseActorRanges, parseAgentRanges, parseAlertRanges,
  parseIncidentRanges, parseRuleRanges, parseSearchLevel, parseSourceRanges, parseVulnRanges, pickParams, vulnRangeChips,
} from "../src/lib/shared/page-filters";
import { journalHref, journalQuery, parseJournalParams } from "../src/lib/shared/journal";
import { buildWhere } from "../src/lib/search";

const NOW = Date.UTC(2026, 10, 1, 12, 0, 0); // 2026-11-01 12:00 UTC

test("parseDtParam: формат datetime-local в UTC; несуществующие даты и мусор — null", () => {
  assert.equal(parseDtParam("2026-10-12T10:00"), Date.UTC(2026, 9, 12, 10, 0));
  assert.equal(parseDtParam("2026-10-12T10:00:30"), Date.UTC(2026, 9, 12, 10, 0, 30));
  for (const bad of [undefined, "", "2026-02-31T10:00", "2026-10-12 10:00", "2026-10-12T25:00", "2026-10-12", "now", "2026-10-12T10:00Z", "1'; DROP TABLE x"]) {
    assert.equal(parseDtParam(bad), null, String(bad));
  }
  assert.equal(toDtParam(Date.UTC(2026, 0, 2, 3, 4, 5)), "2026-01-02T03:04");
  assert.equal(toDtParam(Date.UTC(2026, 0, 2, 3, 4, 5), true), "2026-01-02T03:04:05");
});

test("parseTimeFilter: пресет, синоним period, точный интервал с обменом границ и потолком ширины", () => {
  assert.deepEqual(parseTimeFilter({}, {}, NOW), {});
  assert.deepEqual(parseTimeFilter({}, { defaultRange: "24h" }, NOW), { range: "24h" });
  assert.deepEqual(parseTimeFilter({ range: "7d" }, {}, NOW), { range: "7d" });
  assert.deepEqual(parseTimeFilter({ period: "30d" }, {}, NOW), { range: "30d" }, "period — синоним range");
  assert.deepEqual(parseTimeFilter({ range: "1y" }, { defaultRange: "24h" }, NOW), { range: "24h" }, "чужой пресет — окно по умолчанию");
  assert.deepEqual(parseTimeFilter({ range: "1h" }, { ranges: ["24h", "7d"] }, NOW), {}, "пресет вне списка страницы");
  // Перепутанные границы меняются местами.
  assert.deepEqual(parseTimeFilter({ from: "2026-10-20T00:00", to: "2026-10-10T00:00" }, {}, NOW), { from: "2026-10-10T00:00", to: "2026-10-20T00:00" });
  // Невалидная граница отбрасывается, валидная остаётся.
  assert.deepEqual(parseTimeFilter({ from: "2026-10-10T00:00", to: "вчера" }, {}, NOW), { from: "2026-10-10T00:00" });
  // Только конец — окно пресета до него.
  assert.deepEqual(parseTimeFilter({ to: "2026-10-10T12:00", range: "24h" }, {}, NOW), { range: "24h", from: "2026-10-09T12:00", to: "2026-10-10T12:00" });
  // Шире потолка — начало подтягивается к концу.
  assert.deepEqual(parseTimeFilter({ from: "2026-01-01T00:00", to: "2026-10-31T00:00" }, { maxDays: 30 }, NOW), { from: "2026-10-01T00:00", to: "2026-10-31T00:00" });
  assert.deepEqual(parseTimeFilter({ from: "2025-01-01T00:00" }, { maxDays: 30 }, NOW), { from: "2026-10-02T12:00" }, "без конца — 30 дней до «сейчас»");
  // Второй интервал страницы: свой префикс, без пресета.
  assert.deepEqual(parseTimeFilter({ seen_from: "2026-10-30T00:00", range: "7d" }, { prefix: "seen" }, NOW), { from: "2026-10-30T00:00" });
  // Массивы из searchParams (?from=a&from=b) — первое значение.
  assert.deepEqual(parseTimeFilter({ from: ["2026-10-30T00:00", "x"] }, {}, NOW), { from: "2026-10-30T00:00" });
});

test("timeCondition: колонка против константы (партиция и первичный ключ), даты только параметрами", () => {
  let params: Params = {};
  assert.deepEqual(timeCondition("timestamp", { from: "2026-10-10T00:00", to: "2026-10-11T06:30" }, params, "t"), [
    "timestamp >= toDateTime({t_from:String}, 'UTC')",
    "timestamp <= toDateTime({t_to:String}, 'UTC')",
  ]);
  assert.deepEqual(params, { t_from: "2026-10-10 00:00:00", t_to: "2026-10-11 06:30:00" });
  params = {};
  assert.deepEqual(timeCondition("ts", { range: "7d" }, params), ["ts >= now() - INTERVAL {tf_hours:UInt32} HOUR"]);
  assert.deepEqual(params, { tf_hours: 168 });
  params = {};
  assert.deepEqual(timeCondition("ts", {}, params), [], "без окна — без условия");
  assert.deepEqual(params, {});
  // Точный интервал главнее пресета.
  params = {};
  assert.equal(timeCondition("ts", { range: "24h", from: "2026-10-10T00:00" }, params).length, 1);
  assert.ok("tf_from" in params && !("tf_hours" in params));
});

test("parseNumRange: клампы, обмен границ, крайние значения — не фильтр, мусор отброшен", () => {
  const spec = { min: 0, max: 15, int: true };
  assert.deepEqual(parseNumRange({ level_min: "7", level_max: "12" }, "level", spec), { min: 7, max: 12 });
  assert.deepEqual(parseNumRange({ level_min: "12", level_max: "7" }, "level", spec), { min: 7, max: 12 });
  assert.deepEqual(parseNumRange({ level_min: "99" }, "level", spec), { min: 15 }, "клампится сверху");
  assert.deepEqual(parseNumRange({ level_min: "0", level_max: "15" }, "level", spec), {}, "весь диапазон — не фильтр");
  assert.deepEqual(parseNumRange({ level_min: "-3" }, "level", spec), {}, "кламп снизу до 0 — не фильтр");
  for (const bad of ["abc", "1e3", "7; DROP", "0x10", "", " "]) assert.deepEqual(parseNumRange({ level_min: bad }, "level", spec), {}, bad);
  assert.deepEqual(parseNumRange({ cvss_min: "7.5" }, "cvss", { min: 0, max: 10 }), { min: 7.5 });
  assert.deepEqual(parseNumRange({ level_min: "7.6" }, "level", spec), { min: 8 }, "целое поле округляется");
  assert.equal(hasRange({}), false);
  assert.equal(hasRange({ max: 3 }), true);
});

test("numConditions / ordinalConditions: выражение против {name:Type}, значения шкалы тоже параметрами", () => {
  const params: Params = {};
  assert.deepEqual(numConditions("rule_level", { min: 7, max: 12 }, params, "lvl", "UInt8"), ["rule_level >= {lvl_min:UInt8}", "rule_level <= {lvl_max:UInt8}"]);
  assert.deepEqual(numConditions("x", {}, params, "n"), []);
  const ord = ordinalConditions("level", { min: "high" }, INCIDENT_LEVELS, params, "inc");
  assert.equal(ord.length, 1);
  assert.match(ord[0], /^multiIf\(lower\(level\) = \{inc_r1:String\}, 1, .*, 0\) >= \{inc_min:UInt8\}$/);
  assert.equal(params.inc_min, 3);
  assert.equal(params.inc_r4, "critical");
  assert.ok(!/'high'|'critical'/.test(ord[0]), "значения шкалы не вклеены в SQL");
  assert.deepEqual(ordinalConditions("level", {}, INCIDENT_LEVELS, {}, "x"), []);
});

test("parseOrdinalRange: регистр не важен, перепутанные меняются, крайние ступени — не фильтр", () => {
  assert.deepEqual(parseOrdinalRange({ level_min: "HIGH" }, "level", INCIDENT_LEVELS), { min: "high" });
  assert.deepEqual(parseOrdinalRange({ level_min: "critical", level_max: "medium" }, "level", INCIDENT_LEVELS), { min: "medium" }, "обмен, а верхняя ступень — не фильтр");
  assert.deepEqual(parseOrdinalRange({ level_min: "low", level_max: "critical" }, "level", INCIDENT_LEVELS), {});
  assert.deepEqual(parseOrdinalRange({ level_max: "high" }, "level", INCIDENT_LEVELS), { max: "high" });
  assert.deepEqual(parseOrdinalRange({ level_min: "urgent" }, "level", INCIDENT_LEVELS), {});
  assert.deepEqual(parseOrdinalRange({ level: "high" }, "level", INCIDENT_LEVELS, "level"), { min: "high", max: "high" }, "legacyExact — точное значение");
  assert.deepEqual(parseOrdinalRange({ level_min: "medium" }, "level", VULN_SEVERITIES), { min: "Medium" });
  assert.equal(inOrdinal("High", { min: "medium" }, INCIDENT_LEVELS), true);
  assert.equal(inOrdinal("low", { min: "medium" }, INCIDENT_LEVELS), false);
  assert.equal(inOrdinal("info", { max: "high" }, INCIDENT_LEVELS), false, "вне шкалы при активном фильтре — не проходит");
  assert.equal(inOrdinal("info", {}, INCIDENT_LEVELS), true);
});

test("фильтры в памяти: inRange / inTime", () => {
  assert.equal(inRange(5, { min: 3 }), true);
  assert.equal(inRange(2, { min: 3 }), false);
  assert.equal(inRange(null, { min: 3 }), false);
  assert.equal(inRange(null, {}), true);
  const t = { from: "2026-10-30T00:00", to: "2026-10-31T00:00" };
  assert.equal(inTime("2026-10-30 12:00:00", t, NOW), true);
  assert.equal(inTime("2026-10-31T00:00:01Z", t, NOW), false);
  assert.equal(inTime("", t, NOW), false);
  assert.equal(inTime("", {}, NOW), true);
  assert.deepEqual(timeBounds({ range: "1h" }, NOW), { startMs: NOW - 3_600_000, endMs: NOW });
  assert.equal(timeBounds({}, NOW), null);
  assert.equal(timeLabel({ from: "2026-10-30T00:00" }), "2026-10-30 00:00 — сейчас UTC");
  assert.equal(timeLabel({ range: "7d" }), "7 дней");
});

test("patchHref и pickParams: смена параметров сбрасывает страницу, чужие ключи не теряются", () => {
  assert.equal(patchHref("/x", { a: "1", page: "3", level_min: "7" }, { level_min: undefined, from: "2026-10-30T00:00" }), "/x?a=1&from=2026-10-30T00%3A00");
  assert.equal(patchHref("/x", new URLSearchParams("page=2"), { page: "3" }), "/x?page=3");
  assert.equal(patchHref("/x", {}, {}), "/x");
  assert.equal(pickParams({ from: "a", q: "x", level_min: "high", junk: "1" }, ["from", "level_min"]), "from=a&level_min=high");
});

test("страницы: разбор параметров, совместимость со старыми level/sev, подписи для пустых списков", () => {
  // Инциденты: level=… остаётся точным фильтром страницы, диапазон — отдельно.
  const inc = parseIncidentRanges({ level: "high", level_min: "medium", events_min: "10", range: "7d" }, NOW);
  assert.deepEqual(inc, { time: { range: "7d" }, level: { min: "medium" }, events: { min: 10 } });
  assert.equal(isEmptyIncidentRanges(parseIncidentRanges({ level: "high", q: "x" }, NOW)), true);
  assert.deepEqual(incidentRangeChips(inc).map((c) => `${c.label} ${c.value}`), ["начало 7 дней", "уровень ≥ средний", "событий ≥ 10"]);

  // Алерты: прежний level=N — «не ниже N»; новые параметры главнее.
  assert.deepEqual(parseAlertRanges({ level: "7" }, NOW).level, { min: 7 });
  assert.deepEqual(parseAlertRanges({ level: "7", level_max: "10" }, NOW).level, { max: 10 });
  assert.deepEqual(parseAlertRanges({}, NOW).time, { range: "24h" });
  assert.deepEqual(alertRangeChips(parseAlertRanges({}, NOW)), [], "окно по умолчанию — не активный фильтр");
  assert.deepEqual(alertRangeChips(parseAlertRanges({ range: "7d", level_min: "12" }, NOW)).map((c) => c.value), ["7 дней", "≥ 12"]);
  const ag = parseAgentRanges({ alerts_min: "100", critical_min: "1" }, NOW);
  assert.deepEqual([ag.alerts, ag.critical], [{ min: 100 }, { min: 1 }]);
  assert.equal(agentRangeChips(ag).length, 2);

  // CVE: окно по умолчанию 30 дней, точное — не шире 30; серьёзность по шкале Wazuh.
  const v = parseVulnRanges({ from: "2026-01-01T00:00", level_min: "high", cvss_min: "7", cvss_max: "50" }, NOW);
  assert.deepEqual(v.time, { range: "30d", from: "2026-10-02T12:00" });
  assert.deepEqual(v.severity, { min: "High" });
  assert.deepEqual(v.cvss, { min: 7 });
  assert.deepEqual(vulnRangeChips(v).map((c) => c.label), ["обнаружено", "серьёзность", "CVSS"]);

  assert.deepEqual(parseSearchLevel({ level_min: "12" }, "alerts"), { min: 12 });
  assert.deepEqual(parseSearchLevel({ level_min: "12" }, "events"), { min: 10 }, "у событий шкала 0..10: порог клампится до 10");
  assert.deepEqual(parseSearchLevel({ level_max: "4" }, "events"), { max: 4 });

  const src = parseSourceRanges({ seen_to: "2026-10-31T00:00", events_min: "1", eps_max: "0.5", level_min: "5" }, NOW);
  assert.deepEqual(src.seen, { from: "2026-10-30T00:00", to: "2026-10-31T00:00" });
  assert.deepEqual([src.events, src.eps, src.severity, src.time], [{ min: 1 }, { max: 0.5 }, { min: 5 }, { range: "24h" }]);

  const act = parseActorRanges({ range: "1h", from: "2026-09-01T00:00", events_min: "1" }, NOW);
  assert.deepEqual(act.time, { from: "2026-10-02T12:00" }, "1h нет среди пресетов паспорта; окно не шире 30 дней");
  assert.deepEqual(parseRuleRanges({ level_min: "high", fp_min: "20", incidents_max: "5" }), { level: { min: "high" }, incidents: { max: 5 }, fp: { min: 20 } });
});

test("журнал: level_min/level_max (и старый sev) → severity>= / severity<= в языке запроса", () => {
  const f = parseJournalParams({ level_min: "3", level_max: "7" });
  assert.equal(f.sev, 3);
  assert.equal(f.sevMax, 7);
  assert.equal(journalQuery({ ...f, q: "sshd" }), "sshd severity>=3 severity<=7");
  assert.equal(parseJournalParams({ sev: "5" }).sev, 5, "прежнее имя порога");
  assert.equal(parseJournalParams({ sev: "5", level_min: "8" }).sev, 8, "новое имя главнее");
  assert.deepEqual([parseJournalParams({ level_min: "8", level_max: "3" }).sev, parseJournalParams({ level_min: "8", level_max: "3" }).sevMax], [3, 8]);
  assert.equal(parseJournalParams({ level_max: "10" }).sevMax, undefined, "до 10 — весь диапазон");
  assert.equal(parseJournalParams({ level_max: "x" }).sevMax, undefined);
  assert.equal(journalHref(f), "/events?level_min=3&level_max=7");
  assert.deepEqual([parseJournalParams({ from: "2026-10-20T00:00", to: "2026-10-10T00:00" }).from, parseJournalParams({ from: "2026-02-31T00:00" }).from], ["2026-10-10T00:00", undefined]);
});

test("поиск: порог уровня — условие на колонку серьёзности индекса, параметрами", () => {
  const ev = buildWhere({ index: "events", q: "", range: "24h", page: 1, levelMin: 3, levelMax: 7 });
  assert.match(ev.where, /severity >= \{lvl_min:UInt8\} AND severity <= \{lvl_max:UInt8\}/);
  assert.equal(ev.params.lvl_min, 3);
  assert.equal(ev.params.lvl_max, 7);
  const al = buildWhere({ index: "alerts", q: "", range: "24h", page: 1, levelMin: 12, from: "2026-10-30T00:00", to: "2026-10-31T00:00" });
  assert.match(al.where, /rule_level >= \{lvl_min:UInt8\}/);
  assert.match(al.where, /timestamp >= toDateTime\(\{from:String\}, 'UTC'\)/);
  assert.doesNotMatch(buildWhere({ index: "events", q: "", range: "24h", page: 1 }).where, /lvl_/);
});
