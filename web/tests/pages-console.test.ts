// Страницы консоли без Wazuh-модуля: обзор, инциденты, карточка, источники,
// правила, настройки, поиск, журнал, дашборды, вход. Каждая страница
// отрисовывается с реальными строками, пустой и при недоступном ClickHouse;
// роли проверяются там, где страница их различает. Данные — моки argus-queries
// (_next-mock) и подмена fetch для запросов lib/queries, search, journal, dashboards.
import type React from "react";
import { test, before, beforeEach } from "node:test";
import assert from "node:assert/strict";
import fs from "node:fs";
import { installNextMocks, isRedirect, loadAuth } from "./_next-mock";
import { html, pageText, stripTags } from "./_render";

// RO-пользователь панелей читается при загрузке lib/dashboards — окружение до require страниц.
process.env.CLICKHOUSE_RO_USER = "argus_ro";
process.env.CLICKHOUSE_RO_PASSWORD = "test";

const auth = loadAuth();
const mocks = installNextMocks();

/* eslint-disable @typescript-eslint/no-require-imports -- страницы грузятся после моков */
type Props = { params: Promise<Record<string, string>>; searchParams: Promise<Record<string, string | string[] | undefined>> };
type Page = { default: (props: Props) => Promise<unknown>; generateMetadata?: (props: Props) => Promise<{ title?: string }> };
const overview = require("../src/app/(console)/page") as Page;
const incidents = require("../src/app/(console)/incidents/page") as Page;
const incident = require("../src/app/(console)/incidents/[id]/page") as Page;
const sources = require("../src/app/(console)/sources/page") as Page;
const rules = require("../src/app/(console)/rules/page") as Page;
const settings = require("../src/app/(console)/settings/page") as Page;
const search = require("../src/app/(console)/search/page") as Page;
const journal = require("../src/app/(console)/events/page") as Page;
const dashboards = require("../src/app/(console)/dashboards/page") as Page;
const dashboard = require("../src/app/(console)/dashboards/[id]/page") as Page;
const dashboardEdit = require("../src/app/(console)/dashboards/[id]/edit/page") as Page;
const login = require("../src/app/login/page") as Page;
const consoleError = require("../src/app/(console)/error") as { default: (p: { error: Error & { digest?: string }; reset: () => void }) => unknown };
const globalError = require("../src/app/global-error") as { default: (p: { error: Error & { digest?: string }; reset: () => void }) => unknown };
const consoleLayout = require("../src/app/(console)/layout") as { default: (p: { children: unknown }) => Promise<unknown> };
const wazuhLayout = require("../src/app/(console)/wazuh/layout") as { default: (p: { children: unknown }) => unknown };
const consoleNotFound = require("../src/app/(console)/not-found") as { default: React.FC };
const consoleLoading = require("../src/app/(console)/loading") as { default: React.FC };
const { ClickHouseError } = require("../src/lib/clickhouse") as typeof import("../src/lib/clickhouse");
/* eslint-enable @typescript-eslint/no-require-imports */

const props = (params: Record<string, string> = {}, sp: Record<string, string> = {}): Props => ({ params: Promise.resolve(params), searchParams: Promise.resolve(sp) });
const isNotFound = (e: unknown): boolean => e instanceof Error && /NEXT_HTTP_ERROR_FALLBACK;404|NEXT_NOT_FOUND/.test(String((e as { digest?: string }).digest ?? e.message));
const down = () => new ClickHouseError("ClickHouse недоступен: нет соединения");

/* ===== fetch: ClickHouse по подстроке SQL, движок по пути ===== */
// rows получает параметры запроса (param_*): фильтры диапазонов проверяются по тому, что дошло до ClickHouse.
type Route = { when: (sql: string) => boolean; rows: (params: URLSearchParams) => Record<string, unknown>[] };
let routes: Route[] = [];
let chDown = false;
const fetched: string[] = [];
globalThis.fetch = (async (input: URL | string | Request, init?: RequestInit) => {
  const url = String(input instanceof Request ? input.url : input);
  const sql = String(init?.body ?? "");
  fetched.push(sql || url);
  if (chDown) throw Object.assign(new Error("connect ECONNREFUSED 127.0.0.1:9"), { cause: { code: "ECONNREFUSED" } });
  if (url.includes("/healthz")) return new Response("{}", { status: 503 });
  if (url.includes("query=SELECT")) return new Response("1\n");
  for (const r of routes) if (r.when(sql)) return new Response(r.rows(new URL(url).searchParams).map((x) => JSON.stringify(x)).join("\n") + "\n");
  return new Response("");
}) as typeof fetch;

const NOW = "2026-10-29 10:00:00";
const incidentRow = (over: Record<string, unknown> = {}) => ({
  incident_id: "INC-7", created_at: NOW, updated_at: NOW, rule_id: "ssh.bruteforce", rule_title: "Перебор SSH", level: "high", tags: ["attack.t1110", "ssh"],
  status: "new", owner: "", note: "", actor_name: "203.0.113.5", node: "bastion", sources: ["linux.auth"], event_count: 12, first_ts: NOW, last_ts: NOW, pii: 0,
  chain: ["10:00:00  linux.auth        bastion        login.failed             user=root from 203.0.113.5", "→ порог достигнут: 12 событий за 6m"],
  enrichment: ["cmdb.owner: ops"], similar: ["INC-3 · 2026-10-01 · closed · Перебор SSH · проверено"],
  ...over,
});

before(async () => {
  await auth.getAuthState();
  const pwd = fs.readFileSync(auth.ADMIN_PASSWORD_FILE, "utf8").trim();
  assert.equal(await auth.changePassword("admin", pwd, "AdminPassw0rd."), null);
  for (const [name, role] of [["viewer1", "viewer"], ["analyst1", "analyst"]] as const) assert.ok("password" in (await auth.createUser(name, role)));
  console.error = () => undefined;
});

beforeEach(() => {
  routes = [];
  chDown = false;
  fetched.length = 0;
  mocks.jar.clear();
  delete process.env.ARGUS_INTEGRATION_WAZUH;
});

/* ===== Обзор ===== */

test("обзор: плитки инцидентов и классы источников; Wazuh-блок только с модулем", async () => {
  await auth.createSession("viewer1", "viewer");
  mocks.queries.incidentStats = async () => ({ total: 10, open: 3, escalated: 1, pii: 0 });
  mocks.queries.eventsByClass = async () => [{ source_class: "syslog", count: 1200, sources: 4 }, { source_class: "k8s", count: 7, sources: 1 }];
  let text = await pageText(await overview.default(props({}, { range: "7d" })));
  assert.match(text, /Открытых инцидентов/);
  assert.match(text, /syslog/);
  assert.match(text, /4 ист\./);
  assert.doesNotMatch(text, /Алертов Wazuh/, "без модуля витрин Wazuh нет");

  process.env.ARGUS_INTEGRATION_WAZUH = "1";
  routes = [
    { when: (s) => s.includes("countIf(rule_level >= 12) AS critical") && s.includes("uniqExactIf"), rows: () => [{ total: "50", critical: "2", agents: "3" }] },
    { when: (s) => s.includes("system.columns"), rows: () => [{ n: "1" }] },
    { when: (s) => s.includes("avgIf(compliant"), rows: () => [{ pct: 97.5 }] },
    { when: (s) => s.includes("toStartOfInterval(timestamp"), rows: () => [{ bucket: NOW, low: "1", high: "2", critical: "3" }] },
    { when: (s) => s.includes("any(rule_description) AS description"), rows: () => [{ rule_id: 5763, description: "sshd: brute force", level: 10, cnt: "9" }] },
    { when: (s) => s.includes("ARRAY JOIN mitre_tactics"), rows: () => [{ tactic: "Credential Access", cnt: "9" }] },
  ];
  text = await pageText(await overview.default(props()));
  assert.match(text, /Алертов Wazuh/);
  assert.match(text, /97,5|97\.5/);
  assert.match(text, /Топ правил/);
});

test("обзор: пустой период — подсказка про источники; без ClickHouse — окно «Хранилище недоступно»", async () => {
  await auth.createSession("viewer1", "viewer");
  mocks.queries.incidentStats = async () => ({ total: 0, open: 0, escalated: 0, pii: 0 });
  mocks.queries.eventsByClass = async () => [];
  let text = await pageText(await overview.default(props()));
  assert.match(text, /новые события не поступали/);

  mocks.queries.incidentStats = async () => { throw down(); };
  text = await pageText(await overview.default(props()));
  assert.match(text, /Хранилище недоступно/);
  assert.match(text, /нет соединения/);
});

/* ===== Инциденты ===== */

test("инциденты: сканы снаружи свёрнуты по подсети, раскрытие со статусом блока и групповыми действиями", async () => {
  await auth.createSession("analyst1", "analyst");
  const listed: unknown[] = [];
  mocks.queries.incidentsList = async (...args: unknown[]) => { listed.push(args[0]); return { rows: [], total: 0, page: 1, pageSize: 50 }; };
  mocks.queries.incidentStats = async () => ({ total: 3, open: 3, escalated: 0, pii: 0 });
  mocks.queries.scanGroups = async () => [{ subnet: "203.0.113.0/24", incidents: 3, addresses: 2, rules: ["a41c-net-070", "a41c-net-071"], first_ts: NOW, last_ts: NOW, level: "medium", unassigned: 1 }];
  mocks.queries.scanGroupIncidents = async () => [
    incidentRow({ incident_id: "INC-41", rule_id: "a41c-net-070", actor_name: "203.0.113.7", level: "medium" }),
    incidentRow({ incident_id: "INC-42", rule_id: "a41c-net-071", actor_name: "203.0.113.9", level: "medium", owner: "anna" }),
  ];
  mocks.queries.incidentBlockStates = async () => ({ "INC-41": "blocked" });
  const folded = await pageText(await incidents.default(props({}, { queue: "open" })));
  assert.match(folded, /Сканы снаружи · по подсетям/);
  assert.match(folded, /203\.0\.113\.0\/24/);
  assert.match(folded, /раскрыть/);
  assert.doesNotMatch(folded, /INC-41/, "свёрнутая группа не показывает инциденты");
  assert.equal((listed[0] as { groupScans?: boolean }).groupScans, true, "очередь без сканов, пока они свёрнуты");

  const open = await pageText(await incidents.default(props({}, { queue: "open", subnet: "203.0.113.0/24" })));
  assert.match(open, /Подсеть 203\.0\.113\.0\/24 · 2 открытых инцидентов/);
  assert.match(open, /INC-41/);
  assert.match(open, /заблокирован/);
  assert.match(open, /свернуть/);
  assert.match(open, /Взять все в работу/);
  assert.match(open, /Завершить все/);
  assert.doesNotMatch(open, /Назначить все/, "назначать группу — только администратору");

  await auth.createSession("viewer1", "viewer");
  const viewer = await pageText(await incidents.default(props({}, { queue: "open", subnet: "203.0.113.0/24" })));
  assert.match(viewer, /INC-41/);
  assert.doesNotMatch(viewer, /Завершить все/, "наблюдателю групповые действия не показываются");

  listed.length = 0;
  const flat = await pageText(await incidents.default(props({}, { scans: "list" })));
  assert.doesNotMatch(flat, /Сканы снаружи · по подсетям/);
  assert.match(flat, /свернуть по подсетям/);
  assert.equal((listed[0] as { groupScans?: boolean }).groupScans, false);
  // Неподсеть в адресе страницы не раскрывает ничего.
  const bad = await pageText(await incidents.default(props({}, { subnet: "x' OR 1=1" })));
  assert.doesNotMatch(bad, /Подсеть x/);
  mocks.queries.scanGroups = async () => [];
  mocks.queries.scanGroupIncidents = async () => [];
  mocks.queries.incidentBlockStates = async () => ({});
});

test("инциденты: очередь с вердиктами, закрытием и просрочкой; фильтры в ссылках", async () => {
  await auth.createSession("analyst1", "analyst");
  const old = "2026-10-29 06:00:00"; // high → срок 1 ч → просрочен относительно now()
  mocks.queries.incidentsList = async () => ({ rows: [incidentRow({ created_at: old }), incidentRow({ incident_id: "INC-8", status: "closed", level: "low", pii: 1 })], total: 2, page: 1, pageSize: 50 });
  mocks.queries.incidentStats = async () => ({ total: 2, open: 1, escalated: 0, pii: 1 });
  mocks.queries.verdictsFor = async () => ({ "INC-7": { incident_id: "INC-7", summary_ru: "Перебор с одного адреса", shown: 1, confidence: 0.9, error: "" }, "INC-8": { incident_id: "INC-8", summary_ru: "", shown: 0, confidence: 0.2, error: "" } });
  mocks.queries.incidentClosuresFor = async () => ({ "INC-8": { incident_id: "INC-8", actor: "analyst1", kind: "status", changed_at: NOW, reason: "дубликат" } });
  const text = await pageText(await incidents.default(props({}, { queue: "open", level: "high", q: "ssh" })));
  assert.match(text, /Очередь · 2 инцидентов/);
  assert.match(text, /Перебор с одного адреса/, "показанный вердикт");
  assert.match(text, /ниже порога — разбор скрыт/, "скрытый вердикт");
  assert.match(text, /закрыл: analyst1/);
  assert.match(text, /дубликат/);
  assert.match(text, /просрочено ·/, "реакция по high просрочена");
  assert.match(text, /ПДн/);
  assert.match(text, /сбросить/, "поиск q — кнопка сброса");
});

test("инциденты: пусто с фильтрами и без; вердикты недоступны — лента остаётся", async () => {
  await auth.createSession("viewer1", "viewer");
  mocks.queries.incidentsList = async () => ({ rows: [], total: 0, page: 1, pageSize: 50 });
  mocks.queries.incidentStats = async () => ({ total: 0, open: 0, escalated: 0, pii: 0 });
  assert.match(await pageText(await incidents.default(props({}, { status: "closed" }))), /снимите фильтры/);
  assert.match(await pageText(await incidents.default(props())), /движок ждёт событий/);

  mocks.queries.incidentsList = async () => ({ rows: [incidentRow()], total: 1, page: 1, pageSize: 50 });
  mocks.queries.verdictsFor = async () => { throw down(); };
  const text = await pageText(await incidents.default(props()));
  assert.match(text, /Вердикты модели временно недоступны/);
  assert.match(text, /разбор временно недоступен/);
  assert.match(text, /INC-7/);

  mocks.queries.incidentsList = async () => { throw down(); };
  assert.match(await pageText(await incidents.default(props())), /Хранилище недоступно/);
});

/* ===== Карточка инцидента ===== */

test("карточка: аналитик видит цепочку, похожие, кандидата на блокировку и отработку; наблюдатель — только чтение", async () => {
  mocks.queries.incidentGet = async (id) => (id === "INC-7" ? incidentRow() : null);
  mocks.queries.incidentStateHistory = async () => [{ event_id: "e1", revision: 1, changed_at: NOW, actor: "analyst1", kind: "take", status: "in_progress", owner: "analyst1", reason: "" }];
  mocks.queries.responseLog = async () => [{ ts: NOW, incident_id: "INC-7", rule_id: "ssh.bruteforce", ip: "203.0.113.5", mode: "simulate", executor: "wazuh", dry_run: 1, ok: 1, detail: "ok", reason: "", actor: "argus-engine" }];
  mocks.queries.agentVerdictsFor = async () => [{ session_id: "s1", created_at: NOW, agent: "claude", verdict: "true_positive", confidence: 0.8, human_needed: 1, markdown: "## Разбор\n\nперебор" }];
  mocks.queries.triageVerdictClaim = async () => ({ incident_id: "INC-7", session_id: "s1", claimed_at: NOW });
  mocks.queries.respondStatus = async () => ({ mode: "ips", mode_from: "console", enabled: true, ttl: "1h", allowlist: [], active: [{ ip: "198.51.100.9", incident: "INC-7", until: "2026-10-29 12:00:00", manual: false, executors: ["wazuh"] }], config_errors: [], pending: 0, requested: "ips" });

  await auth.createSession("analyst1", "analyst");
  let text = await pageText(await incident.default(props({ id: "INC-7" })));
  assert.match(text, /Перебор SSH/);
  assert.match(text, /Цепочка событий · 12 шт\./);
  assert.match(text, /login\.failed/);
  assert.match(text, /T1110/, "ATT&CK из тегов");
  assert.match(text, /Похожие закрытые инциденты/);
  assert.match(text, /INC-3/);
  assert.match(text, /Обогащение/);
  assert.match(text, /Реагирование · автоматика и оператор/);
  assert.match(text, /Обратный канал · блокировка адреса/);
  assert.match(text, /режим ips/);
  assert.match(text, /198\.51\.100\.9/, "активная блокировка движка");
  assert.match(text, /Разбор агентом/);
  assert.match(text, /нужен человек/);
  assert.match(text, /взял в работу/, "история изменений");
  assert.match(text, /Досье инцидента/);
  assert.doesNotMatch(text, /менять отработку может аналитик/);

  mocks.jar.clear();
  await auth.createSession("viewer1", "viewer");
  text = await pageText(await incident.default(props({ id: "INC-7" })));
  assert.match(text, /менять отработку может аналитик/);
  assert.doesNotMatch(text, /Обратный канал/, "наблюдателю блокировки не показываются");
});

test("карточка: закрытый инцидент — блок завершения; недоступные части перечислены; 404 и ошибка хранилища", async () => {
  await auth.createSession("admin", "admin");
  mocks.queries.incidentGet = async () => incidentRow({ status: "closed", owner: "analyst1" });
  mocks.queries.incidentStateHistory = async () => [{ event_id: "e2", revision: 2, changed_at: NOW, actor: "argus", kind: "auto_close", status: "closed", owner: "", reason: "тишина 24 ч" }];
  mocks.queries.verdictGet = async () => { throw down(); };
  mocks.queries.incidentComments = async () => { throw down(); };
  let text = await pageText(await incident.default(props({ id: "INC-7" })));
  assert.match(text, /Завершение инцидента/);
  assert.match(text, /ARGUS \(автоматически\)/);
  assert.match(text, /тишина 24 ч/);
  assert.match(text, /Не удалось загрузить: анализ модели, записи команды/);

  mocks.queries.incidentGet = async () => null;
  await assert.rejects(incident.default(props({ id: "INC-404" })), isNotFound);
  await assert.rejects(incident.default(props({ id: "not-an-id" })), isNotFound);

  mocks.queries.incidentGet = async () => { throw down(); };
  text = await pageText(await incident.default(props({ id: "INC-7" })));
  assert.match(text, /Хранилище недоступно/);
  assert.equal((await incident.generateMetadata!(props({ id: "INC-7" }))).title, "INC-7 · Инциденты");
  assert.equal((await incident.generateMetadata!(props({ id: "x" }))).title, "Инцидент · Инциденты");
});

/* ===== Источники ===== */

test("источники: живой и молчащий источник, фильтр ленты, пусто и без хранилища", async () => {
  await auth.createSession("viewer1", "viewer");
  mocks.queries.sourcesHealth = async () => [
    { source: "linux.auth", source_class: "syslog", events_1h: 120, eps_60s: 2, last_ts: NOW, pii_share: 12.5, alive: 1, events_window: 9000, rhythm_sec: 60, silence_threshold_sec: 300, silent_for_sec: 10 },
    { source: "ci.nightly", source_class: "cicd", events_1h: 0, eps_60s: 0, last_ts: "2026-10-27 03:00:00", pii_share: 0, alive: 0, events_window: 3, rhythm_sec: 86400, silence_threshold_sec: 259200, silent_for_sec: 300000 },
  ];
  mocks.queries.eventsRecent = async (source) => [{ ts: NOW, received_at: NOW, source: source ?? "linux.auth", action: "login", outcome: "failure", severity: 5, actor_name: "root", object: "", node: "bastion", src_ip: "203.0.113.5", dst_ip: "", dst_port: 0, pii: 1 }];
  let text = await pageText(await sources.default(props({}, { source: "linux.auth" })));
  assert.match(text, /Живы \(по ритму\) 1 \/ 2/);
  assert.match(text, /12,5 %|12\.5 %/);
  assert.match(text, /ci\.nightly/);
  assert.match(text, /молчит|тишина/i);
  assert.match(text, /События · linux\.auth/);
  assert.match(text, /сбросить фильтр/);
  assert.match(text, /\[ПДн\]/);

  mocks.queries.sourcesHealth = async () => [];
  mocks.queries.eventsRecent = async () => [];
  text = await pageText(await sources.default(props()));
  assert.match(text, /событий нет/);
  assert.match(text, /make replay/);
  assert.match(text, /За 24 часа новых поступлений нет/);

  mocks.queries.sourcesHealth = async () => { throw down(); };
  assert.match(await pageText(await sources.default(props())), /Хранилище недоступно/);
});

/* ===== Правила ===== */

test("правила: таблица с порогом, профилем и долей ложных; движок недоступен; статистика недоступна", async () => {
  await auth.createSession("viewer1", "viewer");
  mocks.queries.engineRules = async () => ({
    rules: [
      { ID: "ssh.bruteforce", Title: "Перебор SSH", Level: "high", File: "linux/ssh.yml", Tags: ["attack.t1110"], Threshold: true, Profile: "" },
      { ID: "k8s.exec", Title: "exec в pod", Level: "medium", File: "k8s/exec.yml", Tags: [], Threshold: false, Profile: "cloud" },
    ],
    health: { last_run: NOW, incidents_created: 42 },
    error: null,
  });
  mocks.queries.rulesFalsePositives = async () => ({ "ssh.bruteforce": { rule_id: "ssh.bruteforce", total: 4, false_positive: 1, closed: 3 } });
  let text = await pageText(await rules.default(props()));
  assert.match(text, /Правил загружено 2/);
  assert.match(text, /С порогом 1/);
  assert.match(text, /Инцидентов создано 42/);
  assert.match(text, /T1110/);
  assert.match(text, /окно/);
  assert.match(text, /по событию/);
  assert.match(text, /cloud/);
  assert.match(text, /4 \/ 1 · 25 %/);

  mocks.queries.engineRules = async () => ({ rules: [], health: null, error: "движок недоступен" });
  text = await pageText(await rules.default(props()));
  assert.match(text, /Движок корреляции не ответил/);

  mocks.queries.engineRules = async () => ({ rules: [], health: null, error: null });
  mocks.queries.rulesFalsePositives = async () => { throw down(); };
  text = await pageText(await rules.default(props()));
  assert.match(text, /Статистика ложных недоступна/);
  assert.match(text, /не загрузил ни одного правила/);
});

/* ===== Настройки ===== */

test("настройки: администратор — пользователи, исключения, реагирование, лицензия, аудит; наблюдатель — без форм", async () => {
  mocks.queries.listExceptions = async () => [{ rule_id: "ssh.bruteforce", field: "actor.name", value: "scanner", reason: "сканер ИБ", incident_id: "INC-2", created_by: "admin", created_at: NOW }];
  mocks.queries.auditTail = async () => [{ ts: NOW, user: "admin", action: "incident.status", target: "INC-2", detail: "closed" }];
  mocks.queries.licenseStats = async () => ({ peak_eps_30d: 150, avg_eps_7d: 12.34, events_30d: 1_000_000, retention_days: 180, sources: 9 });
  mocks.queries.respondStatus = async () => ({ mode: "ips", mode_from: "console", enabled: true, ttl: "1h", allowlist: ["10.0.0.0/8"], active: [{ ip: "198.51.100.9", incident: "INC-7", until: "0001-01-01 00:00:00", manual: true }], excluded: [{ ip: "192.0.2.44", since: "2026-11-01 10:00:00", until: "2026-11-02 10:00:00", actor: "admin", reason: "сканер партнёра" }], config_errors: ["нет пароля Wazuh"], pending: 2, requested: "ips" });
  mocks.queries.responseLog = async () => [{ ts: NOW, incident_id: "INC-7", rule_id: "r", ip: "198.51.100.9", mode: "manual", executor: "ngfw", dry_run: 0, ok: 0, detail: "timeout", reason: "оператор", actor: "admin" }];

  await auth.createSession("admin", "admin");
  let text = await pageText(await settings.default(props()));
  assert.match(text, /Пользователи и роли управляет администратор/);
  assert.match(text, /viewer1/);
  assert.match(text, /это вы/);
  assert.match(text, /scanner/);
  assert.match(text, /сканер ИБ/);
  assert.match(text, /IPS — автоблокировка/);
  assert.match(text, /TTL 1h · активных блокировок 1 · в очереди повторов 2/);
  assert.match(text, /конфиг: нет пароля Wazuh/);
  assert.match(text, /198\.51\.100\.9 \( ?INC-7 ?\) постоянно/);
  assert.match(text, /10\.0\.0\.0\/8/);
  assert.match(text, /192\.0\.2\.44 до .*admin ?: сканер партнёра/);
  assert.match(text, /Отозвать/);
  assert.match(text, /Исключить/);
  assert.match(text, /пиковый EPS, 30 д 150/);
  assert.match(text, /incident\.status/);
  assert.doesNotMatch(text, /Заглушённые правила/, "без модуля Wazuh мьютов нет");

  process.env.ARGUS_INTEGRATION_WAZUH = "1";
  routes = [{ when: (s) => s.includes("console_rule_mutes") && s.includes("LEFT JOIN"), rows: () => [{ rule_id: 5710, description: "sshd: attempt" }] }];
  mocks.jar.clear();
  await auth.createSession("viewer1", "viewer");
  text = await pageText(await settings.default(props()));
  assert.match(text, /Заглушённые правила/);
  assert.match(text, /# ?5710/);
  assert.match(text, /наблюдатель — только чтение/);
  assert.match(text, /переключает администратор/);
  assert.match(text, /viewer1 · это вы/);
  assert.doesNotMatch(text, /Сбросить пароль/, "кнопки администратора наблюдателю не показываются");
  assert.match(text, /192\.0\.2\.44 до/, "список исключений виден всем");
  assert.match(text, /исключает и отзывает администратор/);
  assert.doesNotMatch(text, /Отозвать/, "отзыв исключения — только администратору");
});

test("настройки: без ClickHouse правая колонка заменяется окном ошибки, учётная запись и «О системе» остаются", async () => {
  await auth.createSession("analyst1", "analyst");
  mocks.queries.listExceptions = async () => { throw down(); };
  const text = await pageText(await settings.default(props()));
  assert.match(text, /Мьюты, исключения, реагирование, лицензия и аудит недоступны/);
  assert.match(text, /Смена пароля · analyst1/);
  assert.match(text, /О системе/);
  assert.match(text, /версия консоли/);
});

/* ===== Поиск ===== */

test("поиск: результаты, фасеты, пагинация; индекс alerts без модуля — ошибка запроса", async () => {
  await auth.createSession("viewer1", "viewer");
  routes = [
    { when: (s) => s.includes("FROM events WHERE") && s.includes("OFFSET"), rows: () => [{ time: NOW, severity: 8, source: "linux.auth", action: "login", outcome: "failure", actor_name: "root", node: "bastion", src_ip: "203.0.113.5", object: "", raw: "{\"a\":1}" }] },
    { when: (s) => s.includes("toStartOfInterval(ts"), rows: () => [{ bucket: NOW, low: "40", high: "15", critical: "5" }] },
    { when: (s) => s.includes("arrayJoin(arrayConcat"), rows: () => [{ field: "source", value: "linux.auth", count: 60 }] },
  ];
  let text = await pageText(await search.default(props({}, { q: "root", range: "7d", index: "events", from: "2026-10-28T00:00", page: "2" })));
  assert.match(text, /Распределение · 60 записей/);
  // Строки приходят раньше гистограммы; точный итог появляется в отдельном пейджере.
  assert.match(text, /Результаты · стр\. 2/);
  assert.match(text, /страница 2 из 2 · строки 51 – 60 из 60/, "точный итог и диапазон сохранены после загрузки гистограммы");
  assert.match(text, /203\.0\.113\.5/);
  assert.match(text, /сбросить интервал/);
  assert.match(text, /linux\.auth 60/, "фасет со счётчиком");

  text = await pageText(await search.default(props({}, { index: "alerts" })));
  assert.match(text, /модуль Wazuh выключен/);

  chDown = true;
  text = await pageText(await search.default(props({}, { q: "x" })));
  assert.match(text, /хранилище недоступно/i);
  assert.doesNotMatch(text, /Ничего не найдено/, "сбой хранилища не должен выглядеть как пустая выдача");
});

/* ===== Журнал событий ===== */

test("журнал: заголовок с числом событий, чипы фильтров, гистограмма, лента; пусто и без хранилища", async () => {
  await auth.createSession("viewer1", "viewer");
  routes = [
    { when: (s) => s.includes("{seal:UInt32}"), rows: () => [{ n: NOW }] },
    { when: (s) => s.includes("source AS v"), rows: () => [{ v: "linux.auth" }, { v: "k8s.audit" }] },
    { when: (s) => s.includes("node AS v"), rows: () => [{ v: "bastion" }] },
    { when: (s) => s.includes("cityHash64"), rows: () => [{ time: NOW, received: NOW, id: "1", severity: 9, source: "linux.auth", source_class: "syslog", vendor: "", product: "", action: "login", outcome: "failure", actor_name: "root", actor_kind: "user", object: "", node: "bastion", session_id: "", src_ip: "203.0.113.5", src_port: 0, dst_ip: "", dst_port: 0, proto: "", bytes: 0, packets: 0, value: 0, unit: "", pii: 0, attrs: {}, raw: "<86>sshd: Failed password" }] },
    { when: (s) => s.includes("toStartOfInterval(ts"), rows: () => [{ bucket: NOW, low: "2", high: "0", critical: "1" }] },
    { when: (s) => s.includes("hasAny(sources"), rows: () => [{ incident_id: "INC-7", rule_id: "r", rule_title: "Перебор SSH", level: "high", status: "new", node: "bastion", actor_name: "root", sources: ["linux.auth"], first_s: NOW, last_s: NOW }] },
  ];
  let text = await pageText(await journal.default(props({}, { source: "linux.auth", sev: "7", range: "24h" })));
  assert.match(text, /3 события за 24 часа по фильтрам/);
  assert.match(text, /Убрать фильтр: источник linux\.auth|linux\.auth/);
  assert.match(text, /сбросить всё/);
  assert.match(text, /Лента · страница 1 из 1/);
  assert.match(text, /корзина 30 мин/, "гистограмма");

  routes = [{ when: (s) => s.includes("{seal:UInt32}"), rows: () => [{ n: NOW }] }];
  text = await pageText(await journal.default(props()));
  assert.match(text, /Нет событий за 24 часа/);

  chDown = true;
  text = await pageText(await journal.default(props()));
  assert.match(text, /Все источники в одной ленте/);
  assert.match(text, /хранилище недоступно или запрос отклонён/, "journalSearch переводит ошибку в текст рядом с фильтрами");
});

/* ===== Дашборды ===== */

const SPEC = { id: "ops-main", title: "Операции", description: "сводка", refresh: "30s", panels: [
  { id: "p1", title: "События", type: "timeseries", sql: "SELECT toStartOfHour(ts) AS t, count() AS n FROM events GROUP BY t", w: 12, h: 6 },
  { id: "p2", title: "Итого", type: "stat", sql: "SELECT count() AS total FROM events", w: 6, h: 3, unit: "шт" },
  { id: "p3", title: "Таблица", type: "table", sql: "SELECT source, count() AS n FROM events GROUP BY source", w: 6, h: 6 },
] };
const dashboardRoutes = (): Route[] => [
  { when: (s) => s.includes("FROM console_dashboards") && s.includes("WHERE id ="), rows: () => [{ id: SPEC.id, title: SPEC.title, updated_max: NOW, updated_by: "admin", provisioned: 0, spec: JSON.stringify(SPEC), deleted: 0 }] },
  { when: (s) => s.includes("FROM console_dashboards") && s.includes("HAVING deleted = 0"), rows: () => [{ id: SPEC.id, title: SPEC.title, updated_max: NOW, updated_by: "admin", provisioned: 0, spec: JSON.stringify(SPEC), deleted: 0 }, { id: "wazuh-ov", title: "Wazuh", updated_max: NOW, updated_by: "provisioning", provisioned: 1, spec: "{}", deleted: 0 }] },
  { when: (s) => s.includes("toStartOfHour"), rows: () => [{ t: NOW, n: 5 }, { t: "2026-10-29 11:00:00", n: 7 }] },
  { when: (s) => s.includes("count() AS total"), rows: () => [{ total: 12 }] },
  { when: (s) => s.includes("GROUP BY source"), rows: () => [{ source: "linux.auth", n: 12 }] },
];

test("дашборды: список с источником; просмотр с панелями трёх типов; редактор только аналитику", async () => {
  routes = dashboardRoutes();
  await auth.createSession("viewer1", "viewer");
  let text = await pageText(await dashboards.default(props()));
  assert.match(text, /Дашборды · 2/);
  assert.match(text, /Операции/);
  assert.match(text, /provisioning/);
  assert.doesNotMatch(text, /Создать|Новый дашборд/i, "наблюдатель без формы создания");

  text = await pageText(await dashboard.default(props({ id: "ops-main" }, { range: "7d" })));
  assert.match(text, /Операции/);
  assert.match(text, /сводка/);
  assert.match(text, /автообновление 30 с/);
  assert.match(text, /ряд ·/);
  assert.match(text, /число ·/);
  assert.match(text, /таблица ·/);
  assert.match(text, /total 12 шт/);
  assert.match(text, /linux\.auth/);
  assert.doesNotMatch(text, /Редактировать/, "наблюдатель не редактирует");
  await assert.rejects(dashboardEdit.default(props({ id: "ops-main" })), isRedirect);

  mocks.jar.clear();
  await auth.createSession("analyst1", "analyst");
  text = await pageText(await dashboard.default(props({ id: "ops-main" })));
  assert.match(text, /Редактировать/);
  assert.match(text, /Удалить/, "кнопка удаления; текст диалога появляется только после клика");
  text = await pageText(await dashboardEdit.default(props({ id: "ops-main" })));
  assert.match(text, /Редактор · Операции/);
  assert.match(text, /К дашборду/);
  assert.equal((await dashboard.generateMetadata!(props({ id: "ops-main" }))).title, "Операции · Дашборды");
  assert.equal((await dashboardEdit.generateMetadata!(props({ id: "BAD id" }))).title, "Редактор");
});

test("дашборды: нет такого id — 404, плохой id — 404, без хранилища — окно ошибки, пусто — подсказка", async () => {
  await auth.createSession("analyst1", "analyst");
  routes = [];
  await assert.rejects(dashboard.default(props({ id: "nope" })), isNotFound);
  await assert.rejects(dashboard.default(props({ id: "BAD id" })), isNotFound);
  await assert.rejects(dashboardEdit.default(props({ id: "nope" })), isNotFound);
  let text = await pageText(await dashboards.default(props()));
  assert.match(text, /Дашбордов пока нет — создайте первый/);

  chDown = true;
  text = await pageText(await dashboards.default(props()));
  assert.match(text, /Хранилище недоступно/);
  text = await pageText(await dashboard.default(props({ id: "ops-main" })));
  assert.match(text, /Хранилище недоступно/);
  text = await pageText(await dashboardEdit.default(props({ id: "ops-main" })));
  assert.match(text, /Хранилище недоступно/);
});

/* ===== Вход и ошибка сегмента ===== */

test("вход: без сессии — форма; с SSO — кнопка и текст отказа; с сессией — редирект на next", async () => {
  delete process.env.OIDC_ISSUER;
  let text = await pageText(await login.default(props({}, { next: "//evil.example" })));
  assert.match(text, /Вход в консоль/);
  assert.match(text, /Пользователь/);
  assert.doesNotMatch(text, /SSO/);

  process.env.OIDC_ISSUER = "https://idp.example/application/o/argus/";
  process.env.OIDC_CLIENT_ID = "argus";
  process.env.OIDC_REDIRECT_URL = "https://argus.example:8443/api/auth/oidc/callback";
  text = await pageText(await login.default(props({}, { sso: "denied" })));
  assert.match(text, /Войти через SSO/);
  assert.match(text, /группа не сопоставлена роли/);
  text = await pageText(await login.default(props({}, { sso: "state" })));
  assert.match(text, /https:\/\/argus\.example:8443/);
  delete process.env.OIDC_ISSUER;

  await auth.createSession("viewer1", "viewer");
  await assert.rejects(login.default(props({}, { next: "/incidents" })), (e: unknown) => isRedirect(e) && String((e as { digest?: string }).digest).includes("/incidents"));
});

test("error.tsx: отказ по роли и общая ошибка с digest", () => {
  const React = require("react") as typeof import("react"); // eslint-disable-line @typescript-eslint/no-require-imports
  const render = (digest: string) => stripTags(html(React.createElement(consoleError.default as React.FC<{ error: Error & { digest?: string }; reset: () => void }>, { error: Object.assign(new Error("x"), { digest }), reset: () => undefined })));
  const d = render("FORBIDDEN");
  assert.match(d, /Доступ запрещён/);
  assert.match(d, /Недостаточно прав/);
  assert.doesNotMatch(d, /Повторить/);
  const g = render("abc123");
  assert.match(g, /digest abc123/);
  assert.match(g, /Повторить/);
  assert.doesNotMatch(g, /\bx\b/, "текст ошибки пользователю не показывается");
});

/* ===== Каркас консоли: layout, 404, загрузка, глобальная ошибка ===== */

test("layout консоли: без сессии — на /login с next; с сессией — шапка с именем, ролью и LED служб; Wazuh-пункты по модулю", async () => {
  mocks.headers.set("x-argus-path", "/incidents?queue=open");
  await assert.rejects(consoleLayout.default({ children: "тело" }), (e: unknown) => isRedirect(e) && String((e as { digest?: string }).digest).includes(encodeURIComponent("/incidents?queue=open")));

  await auth.createSession("analyst1", "analyst");
  let text = await pageText(await consoleLayout.default({ children: "тело страницы" }));
  assert.match(text, /analyst1 · аналитик/);
  assert.match(text, /тело страницы/);
  assert.match(text, /Выход/);
  assert.match(text, /clickhouse ClickHouse отвечает/, "LED служб (SELECT 1 через fetch)");
  assert.match(text, /движок/);
  assert.match(text, /Инциденты/, "навигация есть");
  assert.doesNotMatch(text, /Алерты Wazuh/);
  process.env.ARGUS_INTEGRATION_WAZUH = "1";
  text = await pageText(await consoleLayout.default({ children: null }));
  assert.match(text, /Алерты Wazuh/);
  mocks.headers.delete("x-argus-path");
});

test("layout Wazuh: без модуля — 404, с модулем — дети как есть; 404 консоли, скелет загрузки, глобальная ошибка", () => {
  delete process.env.ARGUS_INTEGRATION_WAZUH;
  assert.throws(() => wazuhLayout.default({ children: "x" }), isNotFound);
  process.env.ARGUS_INTEGRATION_WAZUH = "1";
  assert.equal(wazuhLayout.default({ children: "x" }), "x");

  const React = require("react") as typeof import("react"); // eslint-disable-line @typescript-eslint/no-require-imports
  const nf = stripTags(html(React.createElement(consoleNotFound.default)));
  assert.match(nf, /Не найдено 404/);
  assert.match(nf, /На обзор К инцидентам К дашбордам/);
  assert.match(html(React.createElement(consoleLoading.default)), /role="status"/);
  const ge = html(React.createElement(globalError.default as React.FC<{ error: Error & { digest?: string }; reset: () => void }>, { error: Object.assign(new Error("secret"), { digest: "d1" }), reset: () => undefined }));
  assert.match(ge, /<html lang="ru">/);
  assert.match(stripTags(ge), /ARGUS SIEM · ошибка/);
  assert.match(stripTags(ge), /digest d1/);
  assert.doesNotMatch(stripTags(ge), /secret/);
});

/* ===== Диапазонные фильтры: параметр сужает выдачу ===== */

/* eslint-disable @typescript-eslint/no-require-imports -- общие хелперы фильтров, как у страниц */
const F = require("../src/lib/shared/filters") as typeof import("../src/lib/shared/filters");
/* eslint-enable @typescript-eslint/no-require-imports */

test("инциденты: окно по началу, уровень не ниже и событий от — доходят до запроса и сужают очередь; level=… остаётся точным", async () => {
  await auth.createSession("viewer1", "viewer");
  const ROWS = [
    incidentRow({ incident_id: "INC-1", level: "critical", event_count: 40, first_ts: "2026-10-29 09:00:00" }),
    incidentRow({ incident_id: "INC-2", level: "medium", event_count: 3, first_ts: "2026-10-29 09:00:00" }),
    incidentRow({ incident_id: "INC-3", level: "high", event_count: 12, first_ts: "2026-10-01 09:00:00" }),
  ];
  const seen: Record<string, unknown>[] = [];
  // Мок применяет фильтр так же, как условие запроса: уровень — по шкале, окно — по first_ts.
  mocks.queries.incidentsList = async (...args: unknown[]) => {
    const f = args[0] as { level?: string; ranges?: import("../src/lib/shared/page-filters").IncidentRanges };
    seen.push(f as Record<string, unknown>);
    const r = f.ranges!;
    const rows = ROWS.filter((x) => (!f.level || x.level === f.level) && F.inOrdinal(x.level, r.level, F.INCIDENT_LEVELS)
      && F.inRange(x.event_count, r.events) && F.inTime(x.first_ts, r.time, Date.UTC(2026, 9, 29, 12)));
    return { rows, total: rows.length, page: 1, pageSize: 50 };
  };
  let text = await pageText(await incidents.default(props({}, { level_min: "high" })));
  assert.match(text, /Очередь · 2 инцидентов/);
  assert.match(text, /INC-1/);
  assert.doesNotMatch(text, /INC-2/);
  text = await pageText(await incidents.default(props({}, { events_min: "10", from: "2026-10-28T00:00" })));
  assert.match(text, /Очередь · 1 инцидентов/);
  assert.match(text, /INC-1/);
  assert.deepEqual((seen.at(-1)!.ranges as { time: unknown }).time, { from: "2026-10-28T00:00" });
  // Прежняя ссылка level=medium — точный уровень, не диапазон.
  text = await pageText(await incidents.default(props({}, { level: "medium" })));
  assert.match(text, /INC-2/);
  assert.doesNotMatch(text, /INC-1/);
  // Пустая очередь называет активные диапазоны.
  text = await pageText(await incidents.default(props({}, { level_min: "critical", events_max: "5", range: "7d" })));
  assert.match(text, /По этим условиям инцидентов нет \(начало 7 дней, уровень ≥ критический, событий ≤ 5\) — снимите фильтры/);
  // Ссылки очереди сохраняют диапазоны; кнопка точного уровня их снимает.
  const markup = html(await incidents.default(props({}, { level_min: "high", from: "2026-10-28T00:00" })) as React.ReactElement, "/incidents");
  assert.match(markup, /href="\/incidents\?queue=open&amp;from=2026-10-28T00%3A00&amp;level_min=high"/);
  assert.match(markup, /href="\/incidents\?level=critical&amp;from=2026-10-28T00%3A00"/);
});

test("источники: фильтры таблицы (последний приём, событий за час, EPS) и ленты (окно поступления, серьёзность)", async () => {
  await auth.createSession("viewer1", "viewer");
  mocks.queries.sourcesHealth = async () => [
    { source: "linux.auth", source_class: "syslog", events_1h: 120, eps_60s: 2, last_ts: "2026-10-29 10:00:00", pii_share: 0, alive: 1, events_window: 9000, rhythm_sec: 60, silence_threshold_sec: 300, silent_for_sec: 10 },
    { source: "ci.nightly", source_class: "cicd", events_1h: 0, eps_60s: 0, last_ts: "2026-10-27 03:00:00", pii_share: 0, alive: 0, events_window: 3, rhythm_sec: 86400, silence_threshold_sec: 259200, silent_for_sec: 300000 },
  ];
  const FEED = [
    { ts: NOW, received_at: NOW, source: "linux.auth", action: "login", outcome: "failure", severity: 8, actor_name: "root", object: "", node: "bastion", src_ip: "", dst_ip: "", dst_port: 0, pii: 0 },
    { ts: NOW, received_at: NOW, source: "linux.auth", action: "cron.run", outcome: "success", severity: 1, actor_name: "cron", object: "", node: "bastion", src_ip: "", dst_ip: "", dst_port: 0, pii: 0 },
  ];
  let feedArgs: unknown[] = [];
  mocks.queries.eventsRecent = async (...args: unknown[]) => {
    feedArgs = args;
    const f = (args[2] ?? {}) as { severity?: { min?: number; max?: number } };
    return FEED.filter((e) => F.inRange(e.severity, f.severity ?? {}));
  };
  let text = await pageText(await sources.default(props({}, { seen_to: "2026-10-28T00:00" })));
  assert.match(text, /ci\.nightly/);
  assert.doesNotMatch(text, /linux\.auth syslog/, "приём позже окна — строки нет");
  text = await pageText(await sources.default(props({}, { events_min: "1" })));
  assert.doesNotMatch(text, /ci\.nightly/);
  text = await pageText(await sources.default(props({}, { eps_min: "100" })));
  assert.match(text, /Нет источников по фильтрам: EPS ≥ 100/);

  text = await pageText(await sources.default(props({}, { level_min: "5", range: "7d" })));
  assert.match(text, /login/);
  assert.doesNotMatch(text, /cron\.run/);
  assert.deepEqual(feedArgs[2], { time: { range: "7d" }, severity: { min: 5 } });
  text = await pageText(await sources.default(props({}, { level_min: "10" })));
  assert.match(text, /Поступлений по фильтрам нет: серьёзность ≥ 10/);
});

test("правила: уровень не ниже, инцидентов за 30 дней и доля ложных — фильтр в памяти по ответу движка", async () => {
  await auth.createSession("viewer1", "viewer");
  mocks.queries.engineRules = async () => ({
    rules: [
      { ID: "ssh.bruteforce", Title: "Перебор SSH", Level: "high", File: "linux/ssh.yml", Tags: [], Threshold: true, Profile: "" },
      { ID: "k8s.exec", Title: "exec в pod", Level: "medium", File: "k8s/exec.yml", Tags: [], Threshold: false, Profile: "" },
      { ID: "vpn.geo", Title: "VPN из новой страны", Level: "critical", File: "vpn/geo.yml", Tags: [], Threshold: false, Profile: "" },
    ],
    health: null,
    error: null,
  });
  mocks.queries.rulesFalsePositives = async () => ({
    "ssh.bruteforce": { rule_id: "ssh.bruteforce", total: 4, false_positive: 1, closed: 3 },
    "vpn.geo": { rule_id: "vpn.geo", total: 10, false_positive: 8, closed: 2 },
  });
  let text = await pageText(await rules.default(props({}, { level_min: "high" })));
  assert.match(text, /Загруженные правила · 2 из 3/);
  assert.doesNotMatch(text, /exec в pod/);
  text = await pageText(await rules.default(props({}, { fp_min: "50" })));
  assert.match(text, /VPN из новой страны/);
  assert.doesNotMatch(text, /Перебор SSH/);
  text = await pageText(await rules.default(props({}, { incidents_min: "1", level_max: "high" })));
  assert.match(text, /Перебор SSH/);
  assert.doesNotMatch(text, /VPN из новой страны|exec в pod/);
  text = await pageText(await rules.default(props({}, { incidents_min: "100" })));
  assert.match(text, /Нет правил по фильтрам: инцидентов ≥ 100/);
});

test("поиск: level_min/level_max — условие на серьёзность индекса параметрами; форма запроса их сохраняет", async () => {
  await auth.createSession("viewer1", "viewer");
  const EVENTS = [
    { time: NOW, severity: 8, source: "linux.auth", action: "login", outcome: "failure", actor_name: "root", node: "bastion", src_ip: "203.0.113.5", object: "", raw: "" },
    { time: NOW, severity: 2, source: "linux.auth", action: "cron.run", outcome: "success", actor_name: "cron", node: "bastion", src_ip: "", object: "", raw: "" },
  ];
  const lvl = (p: URLSearchParams, v: number) => (p.get("param_lvl_min") === null || v >= Number(p.get("param_lvl_min"))) && (p.get("param_lvl_max") === null || v <= Number(p.get("param_lvl_max")));
  routes = [
    { when: (s) => s.includes("FROM events WHERE") && s.includes("OFFSET"), rows: (p) => EVENTS.filter((e) => lvl(p, e.severity)) },
    { when: (s) => s.includes("toStartOfInterval(ts"), rows: (p) => [{ bucket: NOW, low: String(EVENTS.filter((e) => lvl(p, e.severity) && e.severity < 3).length), high: "0", critical: String(EVENTS.filter((e) => lvl(p, e.severity) && e.severity >= 8).length) }] },
  ];
  let markup = html(await search.default(props({}, { index: "events", level_min: "5" })) as React.ReactElement, "/search");
  const text = stripTags(markup);
  assert.match(text, /203\.0\.113\.5/);
  assert.doesNotMatch(text, /cron\.run/);
  assert.match(text, /сбросить уровень ≥ 5/);
  assert.match(markup, /name="level_min" value="5"/, "отправка формы запроса сохраняет порог");
  markup = html(await search.default(props({}, { index: "events", level_min: "9" })) as React.ReactElement, "/search");
  assert.match(stripTags(markup), /Ничего не найдено \(активны: уровень ≥ 9\)/);
});

test("журнал: «серьёзность до» (level_max) уходит в запрос как severity <= параметром и сужает ленту", async () => {
  await auth.createSession("viewer1", "viewer");
  const row = (id: string, severity: number, action: string) => ({ time: NOW, received: NOW, id, severity, source: "linux.auth", source_class: "syslog", vendor: "", product: "", action, outcome: "", actor_name: "root", actor_kind: "user", object: "", node: "bastion", session_id: "", src_ip: "", src_port: 0, dst_ip: "", dst_port: 0, proto: "", bytes: 0, packets: 0, value: 0, unit: "", pii: 0, attrs: {}, raw: "" });
  const FEED = [row("1", 9, "rootkit.found"), row("2", 2, "cron.run")];
  let sql = "";
  routes = [
    { when: (s) => s.includes("{seal:UInt32}"), rows: () => [{ n: NOW }] },
    { when: (s) => s.includes("cityHash64"), rows: (p) => {
      // Порог из условия severity <= {pN:…}: ищем имя параметра в SQL и применяем как ClickHouse.
      const m = /severity <= \{(p\d+):/.exec(sql);
      const max = m ? Number(p.get(`param_${m[1]}`)) : Infinity;
      return FEED.filter((e) => e.severity <= max);
    } },
  ];
  const origFetch = globalThis.fetch;
  globalThis.fetch = (async (input: URL | string | Request, init?: RequestInit) => {
    if (String(init?.body ?? "").includes("cityHash64")) sql = String(init?.body);
    return origFetch(input, init);
  }) as typeof fetch;
  try {
    const text = await pageText(await journal.default(props({}, { level_max: "4" })));
    assert.match(sql, /severity <= \{p\d+:/);
    assert.match(text, /cron\.run/);
    assert.doesNotMatch(text, /rootkit\.found/);
    assert.match(text, /серьёзность ≤ 4/);
  } finally {
    globalThis.fetch = origFetch;
  }
});

test("дашборд: точный интервал — границы $__timeFilter параметрами argus_from/argus_to, панели считают только окно", async () => {
  await auth.createSession("viewer1", "viewer");
  const spec = { id: "win", title: "Окно", description: "", refresh: "", panels: [{ id: "p", title: "Итого", type: "stat", sql: "SELECT count() AS total FROM events WHERE $__timeFilter(ts)", w: 6, h: 3 }] };
  const TS = ["2026-10-01 10:00:00", "2026-10-20 10:00:00", "2026-10-21 10:00:00"];
  let body = "";
  routes = [
    { when: (s) => s.includes("FROM console_dashboards") && s.includes("WHERE id ="), rows: () => [{ id: spec.id, title: spec.title, updated_max: NOW, updated_by: "admin", provisioned: 0, spec: JSON.stringify(spec), deleted: 0 }] },
    { when: (s) => s.includes("count() AS total"), rows: (p) => {
      const from = p.get("param_argus_from"), to = p.get("param_argus_to");
      return [{ total: TS.filter((t) => (!from || t >= from) && (!to || t <= to)).length }];
    } },
  ];
  const origFetch = globalThis.fetch;
  globalThis.fetch = (async (input: URL | string | Request, init?: RequestInit) => {
    if (String(init?.body ?? "").includes("count() AS total")) body = String(init?.body);
    return origFetch(input, init);
  }) as typeof fetch;
  try {
    let text = await pageText(await dashboard.default(props({ id: "win" }, { range: "30d" })));
    assert.match(text, /total 3/);
    assert.match(body, /ts >= now\(\) - INTERVAL 720 HOUR AND ts <= now\(\)/);
    text = await pageText(await dashboard.default(props({ id: "win" }, { from: "2026-10-15T00:00", to: "2026-10-31T00:00" })));
    assert.match(text, /total 2/);
    assert.match(body, /ts >= toDateTime\(\{argus_from:String\}, 'UTC'\) AND ts <= toDateTime\(\{argus_to:String\}, 'UTC'\)/);
    assert.doesNotMatch(body, /2026-10-15/, "даты не вклеены в SQL");
  } finally {
    globalThis.fetch = origFetch;
  }
});
