import { test } from "node:test";
import assert from "node:assert/strict";
import { fmtMs, fmtNum, formatAgo, formatAxisTs, formatTs, isLongRange, toDate } from "../src/lib/shared/time";

test("строка ClickHouse без зоны читается как UTC", () => {
  const d = toDate("2026-09-13 18:05:07");
  assert.ok(d);
  assert.equal(d.toISOString(), "2026-09-13T18:05:07.000Z");
  assert.equal(toDate("2026-09-13 18:05:07.123")?.toISOString(), "2026-09-13T18:05:07.123Z");
  assert.equal(toDate("2026-09-13T18:05")?.toISOString(), "2026-09-13T18:05:00.000Z");
});

test("строки с явной зоной не сдвигаются", () => {
  assert.equal(toDate("2026-09-13T18:05:07+03:00")?.toISOString(), "2026-09-13T15:05:07.000Z");
  assert.equal(toDate("2026-09-13T18:05:07Z")?.toISOString(), "2026-09-13T18:05:07.000Z");
});

test("formatTs: режимы", () => {
  const v = "2026-09-13 18:05:07";
  assert.equal(formatTs(v), "2026-09-13 18:05:07 UTC");
  assert.equal(formatTs(v, "full"), "2026-09-13 18:05:07 UTC");
  assert.equal(formatTs(v, "datetime"), "2026-09-13 18:05");
  assert.equal(formatTs(v, "date"), "2026-09-13");
  assert.equal(formatTs(v, "time"), "18:05:07");
  assert.equal(formatTs(v, "short"), "09-13 18:05");
});

test("formatTs: пустое и мусор → тире, число — секунды или миллисекунды", () => {
  assert.equal(formatTs(null), "—");
  assert.equal(formatTs(""), "—");
  assert.equal(formatTs("не дата"), "—");
  assert.equal(formatTs(1789668307, "time"), "18:05:07");
  assert.equal(formatTs(1789668307000, "time"), "18:05:07");
});

test("formatAxisTs: короткий диапазон — ЧЧ:ММ, длинный — ММ-ДД ЧЧ:ММ", () => {
  assert.equal(formatAxisTs("2026-09-13 18:05:07", false), "18:05");
  assert.equal(formatAxisTs("2026-09-13 18:05:07", true), "09-13 18:05");
  assert.equal(formatAxisTs("мусор", true), "мусор");
});

test("isLongRange", () => {
  assert.equal(isLongRange("1h"), false);
  assert.equal(isLongRange("24h"), false);
  assert.equal(isLongRange("7d"), true);
  assert.equal(isLongRange("30d"), true);
  assert.equal(isLongRange("1h", "2026-09-01T00:00"), true);
});

test("formatAgo", () => {
  const now = new Date("2026-09-13T18:10:00Z");
  assert.equal(formatAgo("2026-09-13 18:09:30", now), "30 с назад");
  assert.equal(formatAgo("2026-09-13 18:05:00", now), "5 мин назад");
  assert.equal(formatAgo("2026-09-13 15:10:00", now), "3 ч назад");
  assert.equal(formatAgo("2026-09-10 18:10:00", now), "3 дн назад");
  assert.equal(formatAgo(null, now), "—");
});

test("fmtNum и fmtMs", () => {
  assert.equal(fmtNum(1234567).replace(/\s/g, " "), "1 234 567");
  assert.equal(fmtNum("42"), "42");
  assert.equal(fmtNum(3.14159, 2), "3,14");
  assert.equal(fmtNum(null), "—");
  assert.equal(fmtNum("abc"), "—");
  assert.equal(fmtMs(12), "12 мс");
  assert.equal(fmtMs(1400), "1,4 с");
});

test("formatTs: режим iso — ISO 8601 в UTC для <time dateTime>, на пустое — undefined", () => {
  assert.equal(formatTs("2026-09-13 18:05:07", "iso"), "2026-09-13T18:05:07.000Z");
  assert.equal(formatTs("2026-09-13T18:05:07+03:00", "iso"), "2026-09-13T15:05:07.000Z");
  assert.equal(formatTs(null, "iso"), undefined);
  assert.equal(formatTs("", "iso"), undefined);
  assert.equal(formatTs("не дата", "iso"), undefined);
});

test("formatDay / dayHeading: «вт, 25 ноября», сегодня/вчера, другой год — с годом; группировка ленты по дням", async () => {
  const { formatDay, dayHeading } = await import("../src/lib/shared/time");
  const { groupFeedByDay } = await import("../src/lib/shared/feed");
  const now = new Date("2026-11-27T12:00:00Z");
  assert.equal(formatDay("2026-11-25 23:59:00", now), "ср, 25 ноября");
  assert.equal(formatDay("2025-12-29 08:00:00", now), "пн, 29 декабря 2025");
  assert.equal(formatDay(null, now), "—");
  assert.equal(dayHeading("2026-11-27 00:00:01", now), "Сегодня");
  assert.equal(dayHeading("2026-11-26 23:59:59", now), "Вчера");
  assert.equal(dayHeading("2026-11-24 10:00:00", now), "вт, 24 ноября");
  const groups = groupFeedByDay([{ t: "2026-11-27 10:00:00" }, { t: "2026-11-27 01:00:00" }, { t: "2026-11-25 09:00:00" }], (x) => x.t, now);
  assert.deepEqual(groups.map((g) => [g.heading, g.items.length]), [["Сегодня", 2], ["ср, 25 ноября", 1]]);
});
