import { test } from "node:test";
import assert from "node:assert/strict";
import { reactionDeadline, reactionLate, reactionOverdue } from "../src/lib/shared/incident-sla";

test("срок реакции считается от UTC создания и только новый инцидент просрочен", () => {
  const created = "2026-09-24 10:00:00";
  assert.equal(reactionDeadline(created, "critical")?.toISOString(), "2026-09-24T10:15:00.000Z");
  assert.equal(reactionDeadline(created, "high")?.toISOString(), "2026-09-24T11:00:00.000Z");
  assert.equal(reactionDeadline(created, "medium")?.toISOString(), "2026-09-24T14:00:00.000Z");
  assert.equal(reactionDeadline(created, "low")?.toISOString(), "2026-09-25T10:00:00.000Z");
  assert.equal(reactionOverdue(created, "critical", "new", new Date("2026-09-24T10:15:00Z")), false);
  assert.equal(reactionOverdue(created, "critical", "new", new Date("2026-09-24T10:15:01Z")), true);
  assert.equal(reactionOverdue(created, "critical", "waiting_owner", new Date("2026-09-24T10:15:01Z")), false);
  assert.equal(reactionOverdue(created, "critical", "in_progress", new Date("2026-09-24T11:00:00Z")), false);
});

test("первая реакция сохраняет историческую просрочку после смены статуса", () => {
	const created = "2026-09-24 10:00:00";
	assert.equal(reactionLate(created, "critical", "2026-09-24 10:15:00.000"), false);
	assert.equal(reactionLate(created, "critical", "2026-09-24 10:15:00.001"), true);
	assert.equal(reactionLate(created, "critical", null), null);
});
