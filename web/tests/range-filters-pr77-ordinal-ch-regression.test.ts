// PR #77: SQL и фильтр в памяти должны одинаково исключать значения вне шкалы.
// Только SELECT над литеральной фикстурой: без таблиц, миграций и записей в БД.
import { test } from "node:test";
import assert from "node:assert/strict";
import { ch, liveSkip as skip } from "./_ch-live";
import {
  INCIDENT_LEVELS, VULN_SEVERITIES, inOrdinal, ordinalConditions, parseOrdinalRange, type Params,
} from "../src/lib/shared/filters";

for (const scenario of [
  { name: "CVE", scale: VULN_SEVERITIES, unknown: "Untriaged", max: "High" },
  { name: "инциденты", scale: INCIDENT_LEVELS, unknown: "info", max: "high" },
]) {
  test(`${scenario.name}: верхняя граница шкалы не включает пустое и неизвестное значение`, { skip, timeout: 10_000 }, async () => {
    const range = parseOrdinalRange({ level_max: scenario.max }, "level", scenario.scale);
    const values = ["", scenario.unknown, ...scenario.scale];
    const params: Params = {};
    const conditions = ordinalConditions("severity", range, scenario.scale, params, "review");
    const placeholders = values.map((value, i) => {
      params[`value_${i}`] = value;
      return `{value_${i}:String}`;
    });
    const rows = await ch().chQuery<{ severity: string }>(
      `SELECT severity FROM (SELECT arrayJoin([${placeholders.join(", ")}]) AS severity)
       WHERE ${conditions.join(" AND ")}`,
      params,
      { database: "default", max_threads: 1, max_execution_time: 5, max_memory_usage: 64 * 1024 * 1024 },
    );
    assert.deepEqual(rows.map((r) => r.severity).sort(), values.filter((v) => inOrdinal(v, range, scenario.scale)).sort(),
      "multiIf(..., 0) <= max ошибочно пропускает ранг 0, хотя inOrdinal его отвергает");
  });
}
