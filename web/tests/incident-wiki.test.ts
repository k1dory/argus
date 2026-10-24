import { test } from "node:test";
import assert from "node:assert/strict";
import { incidentMarkdown, closingEvent } from "../src/lib/shared/incident-wiki";

const incident = {
  incident_id: "INC-30", rule_title: "Мало места на диске ClickHouse", rule_id: "argus.system.disk_low",
  level: "critical", status: "closed" as const, owner: "analyst1", created_at: "2026-09-25 14:26:00", note: "",
};

test("unavailable history and analysis are not presented as absent data", () => {
  const md = incidentMarkdown(incident, null, [], [], { verdict: true, history: true, comments: true });
  assert.match(md, /История завершения временно недоступна/);
  assert.match(md, /Анализ модели временно недоступен/);
  assert.match(md, /История изменений временно недоступна/);
  assert.match(md, /Записи команды временно недоступны/);
  assert.doesNotMatch(md, /Анализ ещё не готов|Переходов в журнале нет|Записей пока нет|Кем: не зафиксировано/);
});

test("досье показывает проверяемую причину и автора закрытия вместе с анализом и заметками", () => {
  const changes = [{ revision: 1, changed_at: "2026-09-25 15:00:00", actor: "analyst1", kind: "status", status: "closed" as const, owner: "analyst1", reason: "Проверен диск, расширен том ClickHouse" }];
  const verdict = { summary_ru: "Заполнен диск.", shown: 1, error: "", model: "local", profile: "critical", evaluated_at: "2026-09-25 14:30:00", evidence: ["свободно 2 %"], actions: ["расширить том"], first_action: "расширить том" };
  const md = incidentMarkdown(incident, verdict, changes, [{ author: "analyst2", created_at: "2026-09-25 14:40:00", body: "### Проверка\n- лог подтверждён" }]);
  assert.equal(closingEvent(incident.status, changes)?.actor, "analyst1");
  assert.match(md, /Кем: analyst1/);
  assert.match(md, /Причина: Проверен диск, расширен том ClickHouse/);
  assert.match(md, /Модель: local/);
  assert.match(md, /### analyst2/);
  assert.match(md, /- лог подтверждён/);
});

test("для исторического закрытия автор и причина не выдумываются", () => {
  const md = incidentMarkdown(incident, null, [], []);
  assert.match(md, /Кем: не зафиксировано в истории/);
  assert.match(md, /Причина: не зафиксирована/);
});

test("при повторном закрытии отображается последнее действие независимо от порядка журнала", () => {
  const older = { revision: 2, changed_at: "2026-09-25 15:00:00", actor: "analyst1", kind: "status", status: "closed" as const, owner: "analyst1", reason: "Первое закрытие" };
  const latest = { revision: 5, changed_at: "2026-09-26 15:00:00", actor: "analyst2", kind: "status", status: "closed" as const, owner: "analyst2", reason: "Повторная проверка" };
  assert.equal(closingEvent("closed", [latest, older])?.actor, "analyst2");
  assert.equal(closingEvent("closed", [older, latest])?.reason, "Повторная проверка");
});
