// Страницы модуля Wazuh: витрины по алертам менеджера (агенты, алерты, MITRE,
// политики, уязвимости — ClickHouse через fetch) и управление менеджером
// (агенты, группы, правила — wazuh-api через делегат _wazuh-delegate).
import { test, before, beforeEach } from "node:test";
import assert from "node:assert/strict";
import fs from "node:fs";
import { installNextMocks, loadAuth } from "./_next-mock";
import { pageText } from "./_render";

const auth = loadAuth();
const mocks = installNextMocks();

/* eslint-disable @typescript-eslint/no-require-imports -- страницы грузятся после моков */
type Props = { params: Promise<Record<string, string>>; searchParams: Promise<Record<string, string | string[] | undefined>> };
type Page = { default: (props: Props) => Promise<unknown> };
const agents = require("../src/app/(console)/wazuh/agents/page") as Page;
const alerts = require("../src/app/(console)/wazuh/alerts/page") as Page;
const mitre = require("../src/app/(console)/wazuh/mitre/page") as Page;
const policies = require("../src/app/(console)/wazuh/policies/page") as Page;
const vulns = require("../src/app/(console)/wazuh/vulnerabilities/page") as Page;
const manage = require("../src/app/(console)/wazuh/manage/page") as Page;
const groups = require("../src/app/(console)/wazuh/manage/groups/page") as Page;
const group = require("../src/app/(console)/wazuh/manage/groups/[group]/page") as Page;
const ruleFiles = require("../src/app/(console)/wazuh/manage/rules/page") as Page;
const ruleFile = require("../src/app/(console)/wazuh/manage/rules/[file]/page") as Page;
const { WazuhApiError } = require("../src/lib/wazuh-api") as typeof import("../src/lib/wazuh-api");
/* eslint-enable @typescript-eslint/no-require-imports */

const props = (params: Record<string, string> = {}, sp: Record<string, string> = {}): Props => ({ params: Promise.resolve(params), searchParams: Promise.resolve(sp) });
const isNotFound = (e: unknown): boolean => e instanceof Error && /NEXT_HTTP_ERROR_FALLBACK;404|NEXT_NOT_FOUND/.test(String((e as { digest?: string }).digest ?? e.message));

// rows получает параметры запроса (param_*): фильтры диапазонов проверяются по тому, что дошло до ClickHouse.
type Route = { when: (sql: string) => boolean; rows: (params: URLSearchParams) => Record<string, unknown>[] };
let routes: Route[] = [];
let chDown = false;
globalThis.fetch = (async (input: URL | string | Request, init?: RequestInit) => {
  const sql = String(init?.body ?? "");
  if (chDown) throw Object.assign(new Error("connect ECONNREFUSED 127.0.0.1:9"), { cause: { code: "ECONNREFUSED" } });
  const params = new URL(input instanceof Request ? input.url : String(input)).searchParams;
  for (const r of routes) if (r.when(sql)) return new Response(r.rows(params).map((x) => JSON.stringify(x)).join("\n") + "\n");
  return new Response("");
}) as typeof fetch;

const NOW = "2026-10-29 10:00:00";

before(async () => {
  await auth.getAuthState();
  const pwd = fs.readFileSync(auth.ADMIN_PASSWORD_FILE, "utf8").trim();
  assert.equal(await auth.changePassword("admin", pwd, "AdminPassw0rd."), null);
  for (const [name, role] of [["viewer1", "viewer"], ["analyst1", "analyst"]] as const) assert.ok("password" in (await auth.createUser(name, role)));
  console.error = () => undefined;
  process.env.ARGUS_INTEGRATION_WAZUH = "1";
});

beforeEach(() => {
  routes = [];
  chDown = false;
  mocks.jar.clear();
  for (const k of Object.keys(mocks.wazuh)) delete (mocks.wazuh as Record<string, unknown>)[k];
});

/* ===== Витрины по алертам ===== */

test("агенты Wazuh: таблица с критичными; пусто; без хранилища", async () => {
  await auth.createSession("viewer1", "viewer");
  routes = [{ when: (s) => s.includes("uniqExact(rule_id) AS rules"), rows: () => [{ agent_name: "web-01", alerts: "40", critical: "3", rules: "7", last_alert: NOW }, { agent_name: "db-01", alerts: "2", critical: "0", rules: "1", last_alert: NOW }] }];
  let text = await pageText(await agents.default(props({}, { range: "7d" })));
  assert.match(text, /Активность агентов · 2 шт\./);
  assert.match(text, /web-01/);
  assert.match(text, /40 3 7/, "алерты · критичные · правила");

  routes = [];
  text = await pageText(await agents.default(props()));
  assert.match(text, /агенты либо молчат/);

  chDown = true;
  assert.match(await pageText(await agents.default(props())), /Хранилище недоступно/);
});

test("алерты Wazuh: журнал с сортировкой, заглушёнными и кнопкой шума для аналитика; пусто", async () => {
  routes = [
    { when: (s) => s.includes("SELECT timestamp, agent_name, rule_id"), rows: () => [
      { timestamp: NOW, agent_name: "web-01", rule_id: 5763, rule_level: 10, rule_description: "sshd: brute force", srcip: "203.0.113.5", location: "/var/log/auth.log" },
      { timestamp: NOW, agent_name: "", rule_id: 5710, rule_level: 5, rule_description: "sshd: attempt", srcip: "", location: "journald" },
    ] },
    { when: (s) => s.includes("count() AS total FROM wazuh_alerts"), rows: () => [{ total: "250" }] },
    { when: (s) => s.includes("SELECT DISTINCT agent_name"), rows: () => [{ agent_name: "web-01" }] },
    // Список алертов тоже содержит подзапрос по console_rule_mutes (NOT_MUTED) — отличаем по началу запроса.
    { when: (s) => s.trimStart().startsWith("SELECT rule_id FROM console_rule_mutes"), rows: () => [{ rule_id: 5710 }] },
  ];
  await auth.createSession("analyst1", "analyst");
  let text = await pageText(await alerts.default(props({}, { sort: "level", dir: "asc", level: "5", agent: "web-01", q: "ssh", page: "2", muted: "1" })));
  assert.match(text, /Журнал · 250 записей/);
  assert.match(text, /заглушено правил: 1/);
  assert.match(text, /Скрыть заглушённые/);
  assert.match(text, /sshd: brute force/);
  assert.match(text, /journald/, "без srcip показывается location");
  assert.match(text, /Включить правило/, "заглушённое правило — кнопка «включить»");
  assert.match(text, /Заглушить правило/);
  assert.match(text, /страница 2 из 3/);

  mocks.jar.clear();
  await auth.createSession("viewer1", "viewer");
  text = await pageText(await alerts.default(props()));
  assert.doesNotMatch(text, /Заглушить правило/, "наблюдателю кнопки шума не показываются");
  assert.match(text, /Показать заглушённые \(1\)/);

  routes = routes.filter((r) => !r.when("SELECT timestamp, agent_name, rule_id"));
  text = await pageText(await alerts.default(props()));
  assert.match(text, /Ничего не найдено — измените фильтры/);

  chDown = true;
  assert.match(await pageText(await alerts.default(props())), /Хранилище недоступно/);
});

test("MITRE: тактики и техники с долей; пусто; без хранилища", async () => {
  await auth.createSession("viewer1", "viewer");
  routes = [
    { when: (s) => s.includes("ARRAY JOIN mitre_tactics"), rows: () => [{ tactic: "Credential Access", cnt: "9" }] },
    { when: (s) => s.includes("arrayZip(mitre_ids"), rows: () => [{ id: "T1110.001", technique: "Password Guessing", cnt: "9" }, { id: "T1078", technique: "", cnt: "3" }] },
  ];
  let text = await pageText(await mitre.default(props({}, { range: "30d" })));
  assert.match(text, /Техники · топ 2/);
  assert.match(text, /T1110\.001/);
  assert.match(text, /Password Guessing/);
  assert.match(text, /100 % от максимума/);
  assert.match(text, /33 % от максимума/);

  routes = [];
  text = await pageText(await mitre.default(props()));
  assert.match(text, /Нет данных за период/);
  chDown = true;
  assert.match(await pageText(await mitre.default(props())), /Хранилище недоступно/);
});

test("политики: сводка, статусы pass/fail/unknown и соответствие без «неизвестно»; пусто; без хранилища", async () => {
  await auth.createSession("viewer1", "viewer");
  routes = [
    { when: (s) => s.includes("system.columns"), rows: () => [{ n: "1" }] },
    { when: (s) => s.includes("max(evaluated_at) AS evaluated_max"), rows: () => [{ total: "4", failed: "1", unknown: "1", evaluated_max: NOW }] },
    { when: (s) => s.includes("SELECT evaluated_at, entity_type"), rows: () => [
      { evaluated_at: NOW, entity_type: "agent", entity_id: "001", entity_name: "web-01", policy: "wazuh/agent", compliant: 0, violations: ["версия устарела", "агент отключён"], status: "fail" },
      { evaluated_at: NOW, entity_type: "sca", entity_id: "002", entity_name: "db-01", policy: "wazuh/sca", compliant: 0, violations: ["SCA fetch failed"], status: "unknown" },
      { evaluated_at: NOW, entity_type: "agent", entity_id: "003", entity_name: "app-01", policy: "wazuh/agent", compliant: 1, violations: [], status: "" },
    ] },
  ];
  let text = await pageText(await policies.default(props({}, { page: "1" })));
  assert.match(text, /Проверок 4/);
  assert.match(text, /Нарушений 1/);
  assert.match(text, /Неизвестно 1/);
  assert.match(text, /Соответствие 67 %/, "(3 − 1) / 3 без unknown");
  assert.match(text, /версия устарела; агент отключён/);
  assert.match(text, /SCA fetch failed/);
  assert.match(text, /оценка от 2026-10-29/);

  routes = [{ when: (s) => s.includes("system.columns"), rows: () => [{ n: "1" }] }];
  text = await pageText(await policies.default(props()));
  assert.match(text, /Вердиктов пока нет/);
  assert.match(text, /Соответствие —/);

  chDown = true;
  assert.match(await pageText(await policies.default(props())), /Хранилище недоступно/);
});

test("уязвимости: активные и устранённые, бейджи серьёзности; пусто; без хранилища", async () => {
  await auth.createSession("viewer1", "viewer");
  routes = [{ when: (s) => s.includes("vuln_cve AS cve"), rows: () => [
    { cve: "CVE-2026-0001", severity: "Critical", score: "9.8", pkg: "openssl", pkg_version: "3.0.1", agent_name: "web-01", status: "Active", last_seen: NOW },
    { cve: "CVE-2026-0002", severity: "High", score: "7.5", pkg: "curl", pkg_version: "", agent_name: "", status: "Solved", last_seen: NOW },
    { cve: "CVE-2026-0003", severity: "Low", score: "0", pkg: "vim", pkg_version: "", agent_name: "db-01", status: "", last_seen: NOW },
  ] }];
  let text = await pageText(await vulns.default(props()));
  assert.match(text, /Активных CVE 2/);
  assert.match(text, /Критических 1/);
  assert.match(text, /Устранено 1/);
  assert.match(text, /CVE-2026-0001/);
  assert.match(text, /openssl 3\.0\.1/);
  assert.match(text, /9,8|9\.8/);

  routes = [];
  text = await pageText(await vulns.default(props()));
  assert.match(text, /включите модуль в ossec\.conf/);
  chDown = true;
  assert.match(await pageText(await vulns.default(props())), /Хранилище недоступно/);
});

/* ===== Диапазоны витрин: фильтр сужает выдачу по тому, что дошло до ClickHouse ===== */

/** Пороги из param_<name>_min/_max: так ClickHouse применил бы условие запроса. */
const within = (p: URLSearchParams, name: string, v: number): boolean => {
  const lo = p.get(`param_${name}_min`), hi = p.get(`param_${name}_max`);
  return (lo === null || v >= Number(lo)) && (hi === null || v <= Number(hi));
};

test("алерты: level_min/level_max и точный интервал доходят до запроса и сужают журнал; прежний level=N — «не ниже»", async () => {
  await auth.createSession("viewer1", "viewer");
  const ALERTS = [
    { timestamp: NOW, agent_name: "web-01", rule_id: 5763, rule_level: 10, rule_description: "sshd: brute force", srcip: "203.0.113.5", location: "" },
    { timestamp: NOW, agent_name: "web-01", rule_id: 5710, rule_level: 5, rule_description: "sshd: attempt", srcip: "", location: "journald" },
    { timestamp: NOW, agent_name: "db-01", rule_id: 100100, rule_level: 13, rule_description: "rootkit found", srcip: "", location: "rootcheck" },
  ];
  const seen: URLSearchParams[] = [];
  const pick = (p: URLSearchParams) => ALERTS.filter((a) => within(p, "lvl", a.rule_level));
  routes = [
    { when: (s) => s.includes("SELECT timestamp, agent_name, rule_id"), rows: (p) => { seen.push(p); return pick(p); } },
    { when: (s) => s.includes("count() AS total FROM wazuh_alerts"), rows: (p) => [{ total: String(pick(p).length) }] },
  ];
  let text = await pageText(await alerts.default(props({}, { level_min: "7", level_max: "12" })));
  assert.match(text, /Журнал · 1 записей/);
  assert.match(text, /sshd: brute force/);
  assert.doesNotMatch(text, /rootkit found|sshd: attempt/);
  assert.equal(seen.at(-1)?.get("param_t_hours"), "24", "окно по умолчанию — 24 часа");

  text = await pageText(await alerts.default(props({}, { level: "12" })));
  assert.match(text, /rootkit found/);
  assert.doesNotMatch(text, /sshd/, "прежний level=12 — порог снизу");

  text = await pageText(await alerts.default(props({}, { from: "2026-10-29T00:00", to: "2026-10-28T00:00", level_min: "14" })));
  assert.equal(seen.at(-1)?.get("param_t_from"), "2026-10-28 00:00:00", "перепутанные границы — по порядку");
  assert.equal(seen.at(-1)?.get("param_t_to"), "2026-10-29 00:00:00");
  assert.equal(seen.at(-1)?.get("param_t_hours"), null, "точный интервал главнее пресета");
  assert.match(text, /Ничего не найдено \(интервал 2026-10-28 00:00 — 2026-10-29 00:00 UTC, уровень ≥ 14\)/);

  // Мусор в параметрах не роняет страницу и не доходит до запроса.
  text = await pageText(await alerts.default(props({}, { level_min: "abc", from: "2026-02-31T00:00", range: "1y" })));
  assert.match(text, /Журнал · 3 записей/);
  assert.equal(seen.at(-1)?.get("param_lvl_min"), null);
  assert.equal(seen.at(-1)?.get("param_t_from"), null);
});

test("агенты: пороги алертов/критичных (HAVING) и уровень правила сужают таблицу", async () => {
  await auth.createSession("viewer1", "viewer");
  const AGENTS_ROWS = [
    { agent_name: "web-01", alerts: "40", critical: "3", rules: "7", last_alert: NOW },
    { agent_name: "db-01", alerts: "2", critical: "0", rules: "1", last_alert: NOW },
  ];
  let seen: URLSearchParams | null = null;
  routes = [{ when: (s) => s.includes("uniqExact(rule_id) AS rules"), rows: (p) => { seen = p; return AGENTS_ROWS.filter((a) => within(p, "al", Number(a.alerts)) && within(p, "cr", Number(a.critical))); } }];
  let text = await pageText(await agents.default(props({}, { alerts_min: "10", level_min: "7", range: "7d" })));
  assert.match(text, /Активность агентов · 1 шт\./);
  assert.match(text, /web-01/);
  assert.doesNotMatch(text, /db-01/);
  assert.equal(seen!.get("param_lvl_min"), "7");
  assert.equal(seen!.get("param_t_hours"), "168");
  text = await pageText(await agents.default(props({}, { critical_min: "5" })));
  assert.match(text, /Нет агентов по фильтрам: критичных ≥ 5/);
});

test("MITRE: уровень правила и интервал сужают техники", async () => {
  await auth.createSession("viewer1", "viewer");
  // Алерты с техниками и уровнями — фейк считает техники так, как посчитал бы ClickHouse по условиям.
  const RAW = [{ id: "T1110", technique: "Brute Force", level: 10 }, { id: "T1110", technique: "Brute Force", level: 12 }, { id: "T1046", technique: "Network Service Discovery", level: 3 }];
  routes = [
    { when: (s) => s.includes("ARRAY JOIN mitre_tactics"), rows: () => [{ tactic: "Credential Access", cnt: "2" }] },
    { when: (s) => s.includes("arrayZip(mitre_ids"), rows: (p) => {
      const counts = new Map<string, { id: string; technique: string; cnt: number }>();
      for (const r of RAW.filter((x) => within(p, "lvl", x.level))) {
        const c = counts.get(r.id) ?? { id: r.id, technique: r.technique, cnt: 0 };
        c.cnt++;
        counts.set(r.id, c);
      }
      return [...counts.values()].map((c) => ({ ...c, cnt: String(c.cnt) }));
    } },
  ];
  let text = await pageText(await mitre.default(props()));
  assert.match(text, /Техники · топ 2/);
  text = await pageText(await mitre.default(props({}, { level_min: "7" })));
  assert.match(text, /Техники · топ 1/);
  assert.doesNotMatch(text, /T1046/);
  routes = [];
  text = await pageText(await mitre.default(props({}, { level_min: "15" })));
  assert.match(text, /Нет данных по фильтрам: уровень ≥ 15/);
});

test("уязвимости: серьёзность не ниже и CVSS от–до (HAVING), окно не шире 30 дней", async () => {
  await auth.createSession("viewer1", "viewer");
  const VULNS = [
    { cve: "CVE-2026-0001", severity: "Critical", score: "9.8", pkg: "openssl", pkg_version: "3.0.1", agent_name: "web-01", status: "Active", last_seen: NOW },
    { cve: "CVE-2026-0002", severity: "High", score: "7.5", pkg: "curl", pkg_version: "", agent_name: "", status: "Active", last_seen: NOW },
    { cve: "CVE-2026-0003", severity: "Low", score: "2.1", pkg: "vim", pkg_version: "", agent_name: "db-01", status: "", last_seen: NOW },
  ];
  const rank = (p: URLSearchParams, sev: string) => [1, 2, 3, 4].find((i) => p.get(`param_sev_r${i}`) === sev.toLowerCase()) ?? 0;
  let seen: URLSearchParams | null = null;
  routes = [{ when: (s) => s.includes("vuln_cve AS cve"), rows: (p) => {
    seen = p;
    return VULNS.filter((v) => within(p, "cvss", Number(v.score)) && (p.get("param_sev_min") === null || within(p, "sev", rank(p, v.severity))));
  } }];
  let text = await pageText(await vulns.default(props({}, { level_min: "high" })));
  assert.match(text, /CVE по агентам и пакетам · 2 записей/);
  assert.doesNotMatch(text, /CVE-2026-0003/);
  assert.equal(seen!.get("param_t_hours"), "720", "окно по умолчанию — 30 дней");
  text = await pageText(await vulns.default(props({}, { cvss_min: "8", cvss_max: "10" })));
  assert.match(text, /CVE-2026-0001/);
  assert.doesNotMatch(text, /CVE-2026-0002/);
  text = await pageText(await vulns.default(props({}, { from: "2026-01-01T00:00", to: "2026-10-29T00:00" })));
  assert.equal(seen!.get("param_t_from"), "2026-09-29 00:00:00", "точное окно подтянуто до 30 дней");
  text = await pageText(await vulns.default(props({}, { cvss_min: "9.9" })));
  assert.match(text, /Нет CVE по фильтрам: CVSS ≥ 9\.9/);
});

/* ===== Управление менеджером ===== */

const AGENTS = [
  { id: "000", name: "manager", status: "active", version: "4.9.0", group: [], lastKeepAlive: "9999-12-31T23:59:59Z", ip: "127.0.0.1", os: { name: "Ubuntu" } },
  { id: "001", name: "web-01", status: "active", version: "4.9.0", group: ["default", "web"], lastKeepAlive: "2026-10-29T09:59:00Z", ip: "10.0.0.5", os: { name: "Debian" } },
  { id: "002", name: "db-01", status: "disconnected", version: undefined, group: ["default"], lastKeepAlive: "2026-10-20T09:59:00Z", ip: undefined, os: undefined },
];
const GROUPS = [{ name: "default", count: 2, configSum: "ab12" }, { name: "web", count: 1 }];

test("управление: аналитик — мастер установки и действия; наблюдатель — чтение; API недоступен — подсказка", async () => {
  mocks.wazuh.listAgents = async () => AGENTS as never;
  mocks.wazuh.listGroups = async () => GROUPS;
  mocks.wazuh.managerInfo = async () => ({ version: "4.9.0" });
  process.env.WAZUH_API_URL = "https://wazuh.example:55000";

  await auth.createSession("analyst1", "analyst");
  let text = await pageText(await manage.default(props()));
  assert.match(text, /Добавить агента/);
  assert.match(text, /wazuh\.example/, "адрес менеджера из WAZUH_API_URL в команде установки");
  assert.match(text, /Менеджер 4\.9\.0/);
  assert.match(text, /Агентов 3/);
  assert.match(text, /Активных 2/);
  assert.match(text, /Групп 2/);
  assert.match(text, /web ×/, "группу можно убрать");
  assert.match(text, /Перезапустить агента/);
  assert.doesNotMatch(text, /Перезапустить менеджер/, "рестарт менеджера — только администратор");
  assert.match(text, /Debian/);
  assert.match(text, /disconnected/);

  mocks.jar.clear();
  await auth.createSession("admin", "admin");
  text = await pageText(await manage.default(props()));
  assert.match(text, /Перезапустить менеджер/);

  mocks.jar.clear();
  await auth.createSession("viewer1", "viewer");
  text = await pageText(await manage.default(props()));
  assert.doesNotMatch(text, /Добавить агента/);
  assert.match(text, /только чтение/);
  assert.match(text, /Перезапуск агентов и группы — роль аналитика/);
  assert.doesNotMatch(text, /wazuh\.example/, "адрес менеджера наблюдателю не раскрывается");

  mocks.wazuh.listAgents = async () => { throw new WazuhApiError("timeout", 0); };
  text = await pageText(await manage.default(props()));
  assert.match(text, /Менеджер Wazuh не подключён/);
  assert.match(text, /WAZUH_API_URL/);
});

test("группы: список с удалением для администратора; карточка группы с agent.conf и 404; API недоступен", async () => {
  mocks.wazuh.listGroups = async () => GROUPS;
  mocks.wazuh.groupAgents = async () => AGENTS.slice(1, 2) as never;
  mocks.wazuh.getGroupConf = async (name) => { if (name === "web") throw new WazuhApiError("not found", 404); return "<agent_config><localfile/></agent_config>"; };

  await auth.createSession("admin", "admin");
  let text = await pageText(await groups.default(props()));
  assert.match(text, /Группы · 2 шт\./);
  assert.match(text, /ab12/);
  assert.match(text, /Удалить группу/, "не default — можно удалить");
  assert.match(text, /Группа|Создать/);

  text = await pageText(await group.default(props({ group: "default" })));
  assert.match(text, /Агенты в группе · 1 шт\./);
  assert.match(text, /web-01/);
  assert.match(text, /localfile/, "реальный agent.conf");
  assert.match(text, /Ctrl\+S/);

  text = await pageText(await group.default(props({ group: "web" })));
  assert.match(text, /Конфигурация группы; разъедется/, "404 на agent.conf — шаблон");

  mocks.jar.clear();
  await auth.createSession("viewer1", "viewer");
  text = await pageText(await groups.default(props()));
  assert.match(text, /только чтение/);
  assert.doesNotMatch(text, /Удалить группу/);
  text = await pageText(await group.default(props({ group: "default" })));
  assert.match(text, /только чтение/);

  await assert.rejects(group.default(props({ group: "../etc" })), isNotFound);
  mocks.wazuh.groupAgents = async () => { throw new WazuhApiError("not found", 404); };
  await assert.rejects(group.default(props({ group: "ghost" })), isNotFound);
  mocks.wazuh.groupAgents = async () => { throw new WazuhApiError("boom", 500); };
  text = await pageText(await group.default(props({ group: "default" })));
  assert.match(text, /Wazuh API недоступен/);
  mocks.wazuh.listGroups = async () => { throw new Error("ECONNREFUSED"); };
  assert.match(await pageText(await groups.default(props())), /Wazuh API недоступен/);
});

test("правила Wazuh: список файлов; редактор файла; новый файл только администратору; API недоступен", async () => {
  mocks.wazuh.listRuleFiles = async () => [{ filename: "local_rules.xml", relative_dirname: "etc/rules", status: "enabled" }];
  mocks.wazuh.getRuleFile = async (name) => { if (name === "new_rules.xml") throw new WazuhApiError("not found", 404); return "<group name=\"local,\"><rule id=\"100500\" level=\"3\"/></group>"; };

  await auth.createSession("admin", "admin");
  let text = await pageText(await ruleFiles.default(props()));
  assert.match(text, /Файлы правил · 1 шт\./);
  assert.match(text, /local_rules\.xml/);
  assert.match(text, /применяются рестартом менеджера/);

  text = await pageText(await ruleFile.default(props({ file: "local_rules.xml" })));
  assert.match(text, /Редактор · etc\/rules\/local_rules\.xml/);
  assert.match(text, /100500/);
  assert.match(text, /Перезапустить менеджер/);
  text = await pageText(await ruleFile.default(props({ file: "local_rules.xml" }, { new: "1" })));
  assert.match(text, /Файл с таким именем уже существует/);
  text = await pageText(await ruleFile.default(props({ file: "new_rules.xml" }, { new: "1" })));
  assert.match(text, /Пример: переопределение уровня/, "шаблон нового файла");

  mocks.jar.clear();
  await auth.createSession("analyst1", "analyst");
  text = await pageText(await ruleFiles.default(props()));
  assert.match(text, /только чтение — редактирует администратор/);
  await assert.rejects(ruleFile.default(props({ file: "new_rules.xml" })), isNotFound, "несуществующий файл не администратору — 404");
  await assert.rejects(ruleFile.default(props({ file: "../ossec.conf" })), isNotFound);

  mocks.wazuh.listRuleFiles = async () => [];
  assert.match(await pageText(await ruleFiles.default(props())), /Кастомных файлов пока нет/);
  mocks.wazuh.listRuleFiles = async () => { throw new Error("ECONNREFUSED"); };
  assert.match(await pageText(await ruleFiles.default(props())), /Wazuh API недоступен/);
  mocks.wazuh.getRuleFile = async () => { throw new WazuhApiError("boom", 500); };
  assert.match(await pageText(await ruleFile.default(props({ file: "local_rules.xml" }))), /Wazuh API недоступен/);
});
