/* eslint-disable @typescript-eslint/no-require-imports -- настоящие page/action загружаются после _next-mock */
import { after, before, beforeEach, test } from "node:test";
import assert from "node:assert/strict";
import fs from "node:fs";
import path from "node:path";
import type { ReactElement } from "react";
import { formData, installNextMocks, isRedirect, loadAuth } from "./_next-mock";
import { html, pageText } from "./_render";
import { isBlindIncident } from "../src/lib/blind";

const mocks = installNextMocks();
const auth = loadAuth();
const { scanGroupAction } = require("../src/lib/incident-actions") as typeof import("../src/lib/incident-actions");
const { ScanGroupActions } = require("../src/components/console/scan-group-actions") as typeof import("../src/components/console/scan-group-actions");
const page = require("../src/app/(console)/incidents/page") as {
  default: (p: { searchParams: Promise<Record<string, string>> }) => Promise<unknown>;
};

const subnet = "203.0.113.0/24";
const ts = "2026-11-01 10:00:00";
const row = (id: string, over: Record<string, unknown> = {}) => ({
  incident_id: id, created_at: ts, updated_at: ts, first_ts: ts, last_ts: ts,
  rule_id: "a41c-net-070", rule_title: "Inbound port scan", actor_name: "203.0.113.7",
  level: "medium", status: "new", owner: "", tags: [], sources: ["netflow"], node: "edge",
  note: "", event_count: 50, pii: 0, chain: [], enrichment: [], similar: [], ...over,
});
let rows: ReturnType<typeof row>[] = [];
let writes: { id: string; kind: string; actor?: string; status?: string }[] = [];

function visibleRows(filter: unknown) {
  const f = filter as { queue?: string; user?: string; level?: string } | undefined;
  return rows.filter((r) => (!f?.level || r.level === f.level)
    && (f?.queue !== "mine" || r.owner === f.user)
    && (f?.queue !== "unassigned" || !r.owner));
}

before(async () => {
  await auth.getAuthState();
  const pwd = fs.readFileSync(auth.ADMIN_PASSWORD_FILE, "utf8").trim();
  assert.equal(await auth.changePassword("admin", pwd, "AdminPassw0rd."), null);
  for (const [name, role] of [["reviewer", "analyst"], ["other", "analyst"], ["observer", "viewer"]] as const) {
    assert.ok("password" in await auth.createUser(name, role));
  }
});

after(() => fs.rmSync(path.dirname(mocks.authFile), { recursive: true, force: true }));

beforeEach(async () => {
  rows = [row("INC-65001")];
  writes = [];
  mocks.audit.length = 0;
  mocks.jar.clear();
  mocks.queries.incidentsList = async () => ({ rows: [], total: 0, page: 1, pageSize: 50 });
  mocks.queries.incidentStats = async () => ({ total: rows.length, open: rows.length, escalated: 0, pii: 0 });
  mocks.queries.scanGroups = async (filter) => {
    const shown = visibleRows(filter);
    return [{
      subnet, incidents: shown.length, addresses: 1, rules: ["a41c-net-070"],
      first_ts: ts, last_ts: ts, level: "medium", unassigned: shown.filter((r) => !r.owner).length,
    }];
  };
  mocks.queries.scanGroupIncidents = async (_subnet, filter) => visibleRows(filter);
  mocks.queries.incidentBlockStates = async () => ({});
  mocks.queries.verdictsFor = async () => ({});
  mocks.queries.incidentClosuresFor = async () => ({});
  mocks.queries.incidentTransition = async (input) => { writes.push(input as typeof writes[number]); };
  await auth.createSession("reviewer", "analyst");
});

type Element = ReactElement<Record<string, unknown>>;
function findElement(node: unknown, matches: (element: Element) => boolean): Element | undefined {
  if (Array.isArray(node)) return node.map((n) => findElement(n, matches)).find(Boolean);
  if (!node || typeof node !== "object" || !("props" in node) || !("type" in node)) return undefined;
  const el = node as Element;
  if (matches(el)) return el;
  return findElement(el.props.children, matches);
}

const unescape = (s: string) => s.replace(/&quot;/g, '"').replace(/&#x27;/g, "'").replace(/&lt;/g, "<").replace(/&gt;/g, ">").replace(/&amp;/g, "&");

// Берём ВСЕ hidden-поля из реальной формы, а не выдумываем её протокол:
// после добавления серверного снимка состава он тоже попадёт в запрос.
async function confirmedClose(search: Record<string, string> = {}): Promise<FormData> {
  const tree = await page.default({ searchParams: Promise.resolve({ subnet, ...search }) });
  const actions = findElement(tree, (el) => el.type === ScanGroupActions);
  assert.ok(actions, "на показанную группу должна быть форма действия");
  const rendered = html(actions);
  const closeForm = rendered.match(/<form\b[^>]*>[\s\S]*?<\/form>/g)?.find((f) => f.includes("Завершить все"));
  assert.ok(closeForm, "используем настоящую форму завершения");
  const fd = new FormData();
  for (const input of closeForm.match(/<input\b[^>]*>/g) ?? []) {
    const attrs = Object.fromEntries(Array.from(input.matchAll(/([\w:-]+)="([^"]*)"/g), (m) => [m[1], unescape(m[2])]));
    if (attrs.type === "hidden" && attrs.name) fd.append(attrs.name, attrs.value ?? "");
  }
  for (const [name, value] of Object.entries({
    confirm: "yes", status: "closed", reason: "Проверенные фоновые сканы, эскалация не нужна",
    disposition: "benign_authorized", escalate: "no", severity_correct: "yes",
  })) fd.set(name, value);
  return fd;
}

test("PR65: прежнее подтверждение не закрывает новый инцидент при том же размере группы", async () => {
  const fd = await confirmedClose(); // оператор видел только INC-65001
  rows = [row("INC-65002", { actor_name: "203.0.113.99", level: "high" })];
  // INC-65001 уже завершён другим оператором/автоматикой; вместо него появился INC-65002.
  const result = await scanGroupAction({ error: null }, fd);
  assert.deepEqual(writes, [], "замена состава 1 → 1 требует нового подтверждения до любого take/status");
  assert.match(result.error ?? "", /измен|обнов|подтверд/i);
});

test("PR65: рост группы 500 → 501 не обходит повторное подтверждение из-за LIMIT 500", async () => {
  rows = Array.from({ length: 500 }, (_, i) => row(`INC-${70000 - i}`, {
    actor_name: `203.0.113.${i % 254 + 1}`, rule_id: i < 254 ? "a41c-net-070" : "a41c-net-071",
  }));
  // Результат реального запроса ограничен 500 строками. Это его контракт,
  // а наличие самого ограничения проверяет scan-groups-pr65-ch-regression.
  mocks.queries.scanGroupIncidents = async (_subnet, filter) => visibleRows(filter).slice(0, 500);
  const fd = await confirmedClose();
  rows.unshift(row("INC-80001", { actor_name: "203.0.113.250", rule_id: "a41c-net-072" }));
  const result = await scanGroupAction({ error: null }, fd);
  assert.deepEqual(writes, [], "новый INC-80001 не входил в показанные 500; выросшую группу нужно подтвердить заново");
  assert.match(result.error ?? "", /измен|обнов|подтверд|лимит|500/i);
});

test("PR65: неизменившаяся очередь «Мои» завершает именно показанную группу", async () => {
  rows = [row("INC-65001", { owner: "reviewer", status: "in_progress" }), row("INC-65002", { owner: "other", status: "in_progress" })];
  const fd = await confirmedClose({ queue: "mine" });
  const result = await scanGroupAction({ error: null }, fd);
  assert.equal(result.error, null, "скрытый чужой инцидент не означает, что показанная группа изменилась");
  assert.deepEqual(writes.map((w) => [w.id, w.kind]), [["INC-65001", "status"]]);
});

test("PR65: неизменившийся фильтр уровня не блокирует завершение видимых инцидентов", async () => {
  rows = [row("INC-65001", { level: "high", owner: "reviewer", status: "in_progress" }), row("INC-65002")];
  const fd = await confirmedClose({ level: "high" });
  const result = await scanGroupAction({ error: null }, fd);
  assert.equal(result.error, null);
  assert.deepEqual(writes.map((w) => [w.id, w.kind]), [["INC-65001", "status"]], "medium не входил в подтверждение");
});

test("PR65: GET-поиск сохраняет выбранный режим «показать списком»", async () => {
  const calls: { groupScans?: boolean }[] = [];
  mocks.queries.incidentsList = async (filter) => {
    calls.push(filter as typeof calls[number]);
    return { rows: [], total: 0, page: 1, pageSize: 50 };
  };
  const tree = await page.default({ searchParams: Promise.resolve({ scans: "list" }) });
  const searchForm = findElement(tree, (el) => el.type === "form" && el.props.method === "get" && el.props.action === "/incidents");
  assert.ok(searchForm);
  const submitted: Record<string, string> = { q: "INC-65001" };
  // GET-форма отправляет только свои successful controls: прочие параметры
  // исходного URL браузер не сохраняет автоматически.
  const collectHidden = (node: unknown): void => {
    if (Array.isArray(node)) { node.forEach(collectHidden); return; }
    if (!node || typeof node !== "object" || !("props" in node) || !("type" in node)) return;
    const el = node as Element;
    if (el.type === "input" && el.props.type === "hidden" && typeof el.props.name === "string") {
      submitted[el.props.name] = String(el.props.value ?? "");
    }
    collectHidden(el.props.children);
  };
  collectHidden(searchForm);
  await page.default({ searchParams: Promise.resolve(submitted) });
  assert.deepEqual(calls.map((c) => c.groupScans), [false, false], "поиск не должен сам включать группировку обратно");
});

test("PR65 control: без сессии/viewer/подтверждения групповая запись запрещена", async () => {
  const fd = formData({ op: "take", subnet, expected: "1", confirm: "yes", actor: "admin", role: "admin" });
  mocks.jar.clear();
  await assert.rejects(scanGroupAction({ error: null }, fd), isRedirect);
  await auth.createSession("observer", "viewer");
  assert.match((await scanGroupAction({ error: null }, fd)).error ?? "", /Недостаточно прав/);
  await auth.createSession("reviewer", "analyst");
  fd.set("op", "assign");
  fd.set("owner", "other");
  assert.match((await scanGroupAction({ error: null }, fd)).error ?? "", /Недостаточно прав/);
  fd.set("op", "take");
  fd.delete("confirm");
  assert.match((await scanGroupAction({ error: null }, fd)).error ?? "", /Подтвердите/);
  assert.deepEqual(writes, []);
});

test("PR65 control: расширенная группа не передаёт скрытый вердикт в страницу/клиентские props", async () => {
  assert.ok(isBlindIncident("INC-4"));
  rows = [row("INC-4")];
  const marker = "PRIVATE_BLIND_MODEL_VERDICT_PR65";
  const requests: string[][] = [];
  mocks.queries.verdictsFor = async (ids) => {
    requests.push(ids);
    return { "INC-4": { incident_id: "INC-4", summary_ru: marker, shown: 1, confidence: 0.99 } };
  };
  const tree = await page.default({ searchParams: Promise.resolve({ subnet }) });
  assert.doesNotMatch(await pageText(tree), new RegExp(marker));
  assert.doesNotMatch(JSON.stringify(tree), new RegExp(marker));
  assert.ok(requests.every((ids) => !ids.includes("INC-4")));
});
