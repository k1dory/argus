// Журналы «Настроек» человеческим языком: подписи действий и заголовки
// строк реагирования (отказ — выделен, HTTP-глагол исполнителя не показывается).
import { test } from "node:test";
import assert from "node:assert/strict";
import { auditActionLabel, parseSettingsTab, responseView } from "../src/lib/shared/settings-view";

const row = (o: Partial<Parameters<typeof responseView>[0]>) => ({ ip: "203.0.113.7", mode: "ips", executor: "ngfw.edge", dry_run: 0, ok: 1, detail: "POST", ...o });

test("журнал реагирования: блок, отказ, разблокировка, симуляция, ожидание движка", () => {
  assert.deepEqual([responseView(row({})).title, responseView(row({})).note, responseView(row({})).flagged], ["Заблокирован 203.0.113.7 на ngfw.edge", "", false]);
  const fail = responseView(row({ ok: 0, detail: "timeout" }));
  assert.equal(fail.title, "Не удалось заблокировать 203.0.113.7 на ngfw.edge");
  assert.equal(fail.flagged, true);
  assert.equal(fail.note, "timeout");
  assert.equal(responseView(row({ executor: "ngfw.edge.unblock", detail: "разблокирован 203.0.113.7" })).title, "Разблокирован 203.0.113.7 на ngfw.edge");
  assert.match(responseView(row({ dry_run: 1 })).title, /^Симуляция: заблокировал бы/);
  const wait = responseView(row({ executor: "argus", ok: 0, detail: "ожидание: доверенных событий 0 из 1" }));
  assert.equal(wait.title, "Блокировка 203.0.113.7 отложена");
  assert.equal(wait.flagged, false, "ожидание — не отказ");
  assert.equal(responseView(row({ executor: "argus", ok: 0, detail: "все исполнители отказали — повтор №1" })).flagged, true);
});

test("журнал действий: подписи по-русски, неудачи помечены, неизвестное — как есть", () => {
  assert.deepEqual(auditActionLabel("actor.view"), { label: "открыл карточку субъекта", failed: false });
  assert.deepEqual(auditActionLabel("triage.verdict.failed"), { label: "не удалось: вердикт агента", failed: true });
  assert.equal(auditActionLabel("session.login.failed").failed, true);
  assert.equal(auditActionLabel("x.custom").label, "x.custom");
});

test("вкладки настроек: неизвестная — «Учётная запись»", () => {
  assert.equal(parseSettingsTab("respond"), "respond");
  assert.equal(parseSettingsTab("../x"), "account");
  assert.equal(parseSettingsTab(undefined), "account");
});
