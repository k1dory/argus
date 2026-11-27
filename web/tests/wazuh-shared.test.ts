// Хелперы раздела Wazuh: ссылки (агент → его алерты, пагинация политик) и
// сводка агентов (API менеджера + активность по алертам).
import { test } from "node:test";
import assert from "node:assert/strict";
import { policiesPageHref, wazuhAgentHref } from "../src/app/(console)/wazuh/_shared/links";
import { mergeAgents, sortAgents, sortByStatus } from "../src/app/(console)/wazuh/_shared/agents";

test("пагинация политик ведёт на /wazuh/policies, а не на /policies (404)", () => {
  assert.equal(policiesPageHref(1), "/wazuh/policies");
  assert.equal(policiesPageHref(3), "/wazuh/policies?page=3");
  assert.ok(policiesPageHref(2).startsWith("/wazuh/"), "маршрут раздела");
});

test("ссылка на агента — его алерты, а не общий список агентов; фильтры сохраняются, страница сбрасывается", () => {
  assert.equal(wazuhAgentHref("web-01"), "/wazuh/alerts?agent=web-01");
  assert.equal(wazuhAgentHref("host a&b"), "/wazuh/alerts?agent=host+a%26b");
  const href = wazuhAgentHref("db-01", new URLSearchParams("range=7d&agent=web-01&page=4&level_min=10"));
  const u = new URL(href, "http://x");
  assert.equal(u.pathname, "/wazuh/alerts");
  assert.equal(u.searchParams.get("agent"), "db-01");
  assert.equal(u.searchParams.get("range"), "7d");
  assert.equal(u.searchParams.get("level_min"), "10");
  assert.equal(u.searchParams.get("page"), null);
});

const ACTIVITY = [
  { agent_name: "web-01", alerts: 40, critical: 3, rules: 7, last_alert: "2026-10-29 10:00:00" },
  { agent_name: "app-01", alerts: 5, critical: 0, rules: 2, last_alert: "2026-10-29 09:00:00" },
];
const API = [
  { id: "001", name: "web-01", status: "active", lastKeepAlive: "2026-10-29T09:59:00Z", ip: "10.0.0.5" },
  { id: "002", name: "db-01", status: "disconnected", lastKeepAlive: "2026-10-20T09:59:00Z" },
  { id: "003", name: "new-01", status: "never_connected" },
  { id: "000", name: "manager", status: "active", lastKeepAlive: "9999-12-31T23:59:59Z" },
];

test("агенты: замолчавшие и отключённые видны, хотя алертов у них нет; отключённые — сверху", () => {
  const rows = sortAgents(mergeAgents(ACTIVITY, API), "status", "desc");
  assert.deepEqual(rows.map((r) => r.name), ["db-01", "new-01", "web-01", "manager", "app-01"]);
  const db = rows.find((r) => r.name === "db-01")!;
  assert.equal(db.alerts, 0);
  assert.equal(db.status, "disconnected");
  assert.equal(rows.find((r) => r.name === "manager")!.keepalive, undefined, "keepalive 9999-… не показываем");
  assert.equal(rows.find((r) => r.name === "app-01")!.status, undefined, "агент только из алертов — статус неизвестен");
});

test("агенты: порог «алертов ≥ N» не показывает молчащих; без API — только алертная часть", () => {
  assert.deepEqual(mergeAgents(ACTIVITY, API, { alerts: { min: 10 } }).map((r) => r.name), ["web-01", "app-01"]);
  assert.deepEqual(mergeAgents(ACTIVITY, null).map((r) => r.name), ["web-01", "app-01"]);
  assert.deepEqual(sortAgents(mergeAgents(ACTIVITY, null), "alerts", "asc").map((r) => r.name), ["app-01", "web-01"]);
});

test("управление: таблица агентов — отключённые и не подключавшиеся наверху", () => {
  const sorted = sortByStatus([
    { id: "000", status: "active" },
    { id: "004", status: "pending" },
    { id: "003", status: "never_connected" },
    { id: "002", status: "disconnected" },
    { id: "001", status: "active" },
  ]);
  assert.deepEqual(sorted.map((a) => a.id), ["002", "003", "004", "000", "001"]);
});
