// Представление инцидента (lib/shared/incident-view): ATT&CK из тегов любого
// формата, срок реакции без выдуманной просрочки, главное действие, срочность.
import { test } from "node:test";
import assert from "node:assert/strict";
import { formatSpan, formatWhen, incidentTechniques, incidentUrgency, nextAction, plainTags, plural, reactionView } from "../src/lib/shared/incident-view";

const NOW = new Date("2026-10-29T12:00:00Z");

test("C3: техники ATT&CK — и attack.t1003, и голый T1003; теги без техник не дублируют их", () => {
  assert.deepEqual(incidentTechniques(["T1003", "attack.t1110", "attack.T1003.001", "t1003", "linux", "attack.credential_access"]), ["T1003", "T1110", "T1003.001"]);
  assert.deepEqual(plainTags(["T1003", "attack.t1110", "linux", "attack.credential_access"]), ["linux", "attack.credential_access"]);
});

test("C3: срок реакции — просрочка у нового, «нет данных» у взятого без записи take, взятие — реакция", () => {
  const created = "2026-10-29 06:00:00"; // critical → до 06:15
  const fmt = (d: Date | string) => formatWhen(d, NOW);
  const fresh = reactionView({ created_at: created, level: "critical", status: "new", owner: "" }, null, NOW, fmt)!;
  assert.equal(fresh.tone, "err");
  assert.match(fresh.text, /Реакция до сегодня, 06:15 — просрочено на 5 ч/);
  const busy = reactionView({ created_at: created, level: "critical", status: "in_progress", owner: "anna" }, null, NOW, fmt)!;
  assert.equal(busy.tone, "muted");
  assert.match(busy.text, /В работе у anna · время взятия не записано/);
  const taken = reactionView({ created_at: created, level: "critical", status: "in_progress", owner: "anna" }, "2026-10-29 06:10:00", NOW, fmt)!;
  assert.deepEqual(taken, { text: "В работе у anna с сегодня, 06:10 — в срок", tone: "ok" });
  const late = reactionView({ created_at: created, level: "critical", status: "in_progress", owner: "anna" }, "2026-10-29 07:15:00", NOW, fmt)!;
  assert.equal(late.tone, "warn");
  assert.match(late.text, /позже срока на 1 ч/);
});

test("главное действие карточки по состоянию и роли", () => {
  assert.equal(nextAction({ status: "new", owner: "" }, "anna", true), "take");
  assert.equal(nextAction({ status: "in_progress", owner: "anna" }, "anna", true), "finish");
  assert.equal(nextAction({ status: "in_progress", owner: "boris" }, "anna", true), null);
  assert.equal(nextAction({ status: "new", owner: "" }, "anna", false), null, "наблюдателю — нет");
  assert.equal(nextAction({ status: "closed", owner: "anna" }, "anna", true), null);
});

test("срочность строки очереди совпадает с порядком запроса", () => {
  assert.equal(incidentUrgency({ created_at: "2026-10-29 06:00:00", level: "medium", status: "new" }, NOW), "overdue");
  assert.equal(incidentUrgency({ created_at: "2026-10-29 11:59:00", level: "critical", status: "new" }, NOW), "urgent");
  assert.equal(incidentUrgency({ created_at: "2026-10-29 06:00:00", level: "critical", status: "in_progress" }, NOW), "urgent");
  assert.equal(incidentUrgency({ created_at: "2026-10-29 06:00:00", level: "critical", status: "closed" }, NOW), "normal");
  assert.equal(incidentUrgency({ created_at: "2026-10-29 11:00:00", level: "medium", status: "new" }, NOW), "normal");
});

test("подписи: склонение, длительность, момент", () => {
  assert.deepEqual([1, 3, 5, 11, 21, 104].map((n) => plural(n, ["инцидент", "инцидента", "инцидентов"])), ["инцидент", "инцидента", "инцидентов", "инцидентов", "инцидент", "инцидента"]);
  assert.equal(formatSpan(23 * 3600_000 + 5), "23 ч");
  assert.equal(formatWhen("2026-10-28 13:09:00", NOW), "вчера, 13:09");
  assert.equal(formatWhen("2026-09-01 08:00:00", NOW), "1 сен, 08:00");
  assert.equal(formatWhen("2025-09-01 08:00:00", NOW), "1 сен 2025, 08:00");
});
