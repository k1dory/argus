// PR #77: перестановка границ должна сохранять ноль в шкале severity 0..10.
// Проверяем конечный запрос журнала, а не только промежуточные поля парсера.
import { test } from "node:test";
import assert from "node:assert/strict";
import { journalQuery, parseJournalParams } from "../src/lib/shared/journal";

for (const lower of ["level_min", "sev"] as const) {
  test(`журнал: ${lower}=8&level_max=0 эквивалентен диапазону 0..8`, () => {
    const reversed = parseJournalParams({ [lower]: "8", level_max: "0" });
    const ordered = parseJournalParams({ level_min: "0", level_max: "8" });
    assert.equal(journalQuery(ordered), "severity<=8");
    assert.equal(journalQuery(reversed), journalQuery(ordered),
      "severity=0 должен остаться в окне после обмена границ; Math.max(1, sevMax) теряет эти события");
  });
}
