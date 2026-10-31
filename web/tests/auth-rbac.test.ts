/* eslint-disable @typescript-eslint/no-require-imports -- моки кладутся в кэш CJS до загрузки модулей, статический import не подходит */
import { test, before } from "node:test";
import assert from "node:assert/strict";
import fs from "node:fs";
import { formData, installNextMocks, isRedirect, loadAuth, type AuthModule } from "./_next-mock";

const mocks = installNextMocks();
const auth = loadAuth();
// Actions грузим после моков: они тянут auth.ts и argus-queries (подменён).
const manage = require("../src/lib/manage-actions") as typeof import("../src/lib/manage-actions");
const users = require("../src/lib/user-actions") as typeof import("../src/lib/user-actions");
const actions = require("../src/lib/actions") as typeof import("../src/lib/actions");
const respond = require("../src/lib/respond-actions") as typeof import("../src/lib/respond-actions");
const incidents = require("../src/lib/incident-actions") as typeof import("../src/lib/incident-actions");
const dashboards = require("../src/lib/dashboard-actions") as typeof import("../src/lib/dashboard-actions");

type Role = AuthModule["ROLE_RANK"] extends Record<infer R, number> ? R : never;
const passwords: Record<string, string> = {};

async function login(user: string): Promise<void> {
  const role = (await auth.listUsers()).find((u) => u.name === user)!.role;
  await auth.createSession(user, role);
}

const DENIED = /Недостаточно прав/;
const isForbidden = (err: unknown): boolean => err instanceof Error && (err as { digest?: string }).digest === "FORBIDDEN";

before(async () => {
  // Стартовый пароль admin меняем: иначе все действия отказывают «смените пароль».
  await auth.getAuthState(); // первая инициализация создаёт auth.json и файл пароля
  const pwd = fs.readFileSync(auth.ADMIN_PASSWORD_FILE, "utf8").trim();
  assert.equal(await auth.changePassword("admin", pwd, "AdminPassw0rd."), null);
  passwords.admin = "AdminPassw0rd.";
  for (const [name, role] of [["viewer1", "viewer"], ["analyst1", "analyst"], ["analyst2", "analyst"], ["adm2", "admin"]] as [string, Role][]) {
    const r = await auth.createUser(name, role);
    assert.ok("password" in r);
    passwords[name] = r.password;
  }
  console.error = () => undefined; // сеть до Wazuh/ClickHouse в тестах намеренно не отвечает
});

test("матрица manage-actions × роли: viewer — отказ, analyst — агенты/группы, admin — всё", async () => {
  const cases: { name: string; run: () => Promise<{ error: string | null }>; min: Role }[] = [
    { name: "restartManager", min: "admin", run: () => manage.restartManagerAction() },
    { name: "deleteGroup", min: "admin", run: () => manage.deleteGroupAction(formData({ name: "web" })) },
    { name: "saveGroupConf", min: "admin", run: () => manage.saveGroupConfAction({ error: null }, formData({ group: "web", xml: "<agent_config/>" })) },
    { name: "saveRuleFile", min: "admin", run: () => manage.saveRuleFileAction({ error: null }, formData({ filename: "x.xml", xml: "<group name=\"a,\"/>" })) },
    { name: "restartAgent", min: "analyst", run: () => manage.restartAgentAction(formData({ agent_id: "001" })) },
    { name: "agentGroup", min: "analyst", run: () => manage.agentGroupAction(formData({ agent_id: "001", group_id: "web", op: "add" })) },
    { name: "createGroup", min: "analyst", run: () => manage.createGroupAction({ error: null }, formData({ name: "web" })) },
    { name: "respondMode", min: "admin", run: () => respond.setRespondModeAction({ error: null }, formData({ mode: "ids" })) },
    { name: "createUser", min: "admin", run: () => users.createUserAction({ error: null }, formData({ name: "zz", role: "viewer" })) },
  ];
  for (const user of ["viewer1", "analyst1", "admin"]) {
    await login(user);
    const rank = auth.ROLE_RANK[(await auth.getSession())!.role];
    for (const c of cases) {
      const res = await c.run();
      const allowed = rank >= auth.ROLE_RANK[c.min];
      if (allowed) {
        assert.ok(!DENIED.test(res.error ?? ""), `${user} → ${c.name}: не должен получить отказ по роли, получил «${res.error}»`);
      } else {
        assert.match(res.error ?? "", DENIED, `${user} → ${c.name}: ожидался отказ по роли`);
      }
    }
  }
  // Без сессии — redirect на /login, а не выполнение.
  mocks.jar.clear();
  await assert.rejects(manage.restartManagerAction(), isRedirect);
});

test("матрица incident-actions × роли: viewer — отказ, analyst и admin — проходят до движка/хранилища", async () => {
  const cases: { name: string; run: () => Promise<{ error: string | null }> }[] = [
    { name: "setIncidentStatus", run: () => incidents.setIncidentStatusAction({ error: null }, formData({ incident_id: "INC-1", status: "in_progress" })) },
    { name: "blockIp", run: () => incidents.blockIpAction({ error: null }, formData({ incident_id: "INC-1", ip: "203.0.113.7", reason: "тест" })) },
    { name: "unblockIp", run: () => incidents.unblockIpAction({ error: null }, formData({ ip: "203.0.113.7", reason: "тест" })) },
    { name: "unblockIpForm", run: () => incidents.unblockIpFormAction(formData({ ip: "203.0.113.7", reason: "тест" })) },
    { name: "reanalyze", run: () => incidents.reanalyzeAction({ error: null }, formData({ incident_id: "INC-1" })) },
    { name: "removeException", run: () => incidents.removeExceptionAction(formData({ rule_id: "r1", field: "node", value: "x" })) },
    { name: "reopenTriage", run: () => incidents.reopenTriageAction({ error: null }, formData({ incident_id: "INC-1" })) },
  ];
  for (const user of ["viewer1", "analyst1", "admin"]) {
    await login(user);
    const allowed = auth.ROLE_RANK[(await auth.getSession())!.role] >= auth.ROLE_RANK.analyst;
    for (const c of cases) {
      const res = await c.run();
      if (allowed) assert.ok(!DENIED.test(res.error ?? ""), `${user} → ${c.name}: не должен получить отказ по роли, получил «${res.error}»`);
      else assert.match(res.error ?? "", DENIED, `${user} → ${c.name}: ожидался отказ по роли`);
    }
  }
  mocks.jar.clear();
  await assert.rejects(incidents.reanalyzeAction({ error: null }, formData({ incident_id: "INC-1" })), isRedirect);
});

test("бросающие действия (muteRule, dashboards): viewer — digest FORBIDDEN, analyst — доходит до хранилища", async () => {
  const cases: { name: string; run: () => Promise<unknown> }[] = [
    { name: "muteRule", run: () => actions.muteRuleAction(formData({ rule_id: "5716", muted: "1" })) },
    { name: "createDashboard", run: () => dashboards.createDashboardAction({ error: null }, formData({ title: "Тестовый" })) },
    { name: "saveDashboard", run: () => dashboards.saveDashboardAction({ error: null }, formData({ id: "abc", spec: "{}" })) },
    { name: "deleteDashboard", run: () => dashboards.deleteDashboardAction(formData({ id: "abc" })) },
    { name: "previewPanel", run: () => dashboards.previewPanelAction({ data: null, error: null }, formData({ sql: "SELECT 1", range: "24h" })) },
  ];
  await login("viewer1");
  for (const c of cases) await assert.rejects(c.run(), isForbidden, `viewer → ${c.name}: ожидался ForbiddenError`);
  for (const user of ["analyst1", "admin"]) {
    await login(user);
    for (const c of cases) {
      try {
        await c.run();
      } catch (err) {
        assert.ok(!isForbidden(err), `${user} → ${c.name}: отказ по роли`);
        assert.ok(!isRedirect(err), `${user} → ${c.name}: редирект на логин`);
      }
    }
  }
  mocks.jar.clear();
  await assert.rejects(actions.muteRuleAction(formData({ rule_id: "1", muted: "1" })), isRedirect);
});

test("вход через SSO запоминает сотрудника: он в списке с ролью IdP, без пароля, роль обновляется входом, назначить ему можно", async () => {
  await auth.recordSsoLogin("sso:ivanov", "analyst");
  await auth.recordSsoLogin("sso:ivanov", "analyst");
  let u = (await auth.listUsers()).find((x) => x.name === "sso:ivanov");
  assert.ok(u && u.sso && !u.builtin && u.role === "analyst" && !u.totp);
  assert.equal((await auth.listUsers()).filter((x) => x.name === "sso:ivanov").length, 1);
  await auth.recordSsoLogin("sso:ivanov", "admin");
  u = (await auth.listUsers()).find((x) => x.name === "sso:ivanov");
  assert.equal(u?.role, "admin");
  await auth.recordSsoLogin("", "admin");
  assert.ok(!(await auth.listUsers()).some((x) => x.name === ""));
  const writes: unknown[][] = [];
  mocks.queries.incidentGet = async () => ({ incident_id: "INC-30", rule_id: "r1", actor_name: "", node: "", owner: "", status: "new" });
  mocks.queries.incidentTransition = async (...args) => void writes.push(args);
  await login("admin");
  assert.equal((await incidents.assignIncidentAction({ error: null }, formData({ incident_id: "INC-30", owner: "sso:ivanov" }))).error, null);
  assert.deepEqual(writes, [[{ id: "INC-30", kind: "assign", owner: "sso:ivanov", actor: "admin", role: "admin" }]]);
});

test("setIncidentStatus: статус из прототипа (toString/constructor) отвергается, реальный — принимается", async () => {
  await login("analyst1");
  for (const status of ["toString", "constructor", "__proto__", "hasOwnProperty", "nope", "waiting_owner"]) {
    const res = await incidents.setIncidentStatusAction({ error: null }, formData({ incident_id: "INC-1", status }));
    assert.match(res.error ?? "", /Неизвестный статус/, status);
  }
  const calls: unknown[][] = [];
  mocks.queries.incidentGet = async () => ({ incident_id: "INC-1", rule_id: "r1", actor_name: "", node: "", owner: "analyst1", status: "in_progress", tags: ["attack.t1110"] });
  mocks.queries.incidentTransition = async (...args) => void calls.push(args);
  // Завершение без метки ответа отклоняется до движка.
  const unlabeled = await incidents.setIncidentStatusAction({ error: null }, formData({ incident_id: "INC-1", status: "closed", reason: "Проверены события, угрозы нет" }));
  assert.match(unlabeled.error ?? "", /характер срабатывания/);
  assert.equal(calls.length, 0);
  const ok = await incidents.setIncidentStatusAction({ error: null }, formData({ incident_id: "INC-1", status: "closed", reason: "Проверены события, угрозы нет",
    disposition: "benign_authorized", escalate: "no", severity_correct: "yes" }));
  assert.equal(ok.error, null);
  assert.deepEqual(calls, [[{ id: "INC-1", kind: "status", status: "closed", reason: "Проверены события, угрозы нет", actor: "analyst1", role: "analyst",
    label: { disposition: "benign_authorized", escalate: false, severity_correct: true } }]]);
  assert.ok(mocks.audit.some((e) => e.action === "incident.status" && e.target === "INC-1" && e.user === "analyst1"));
});

test("комментарий доступен аналитику без назначения; статус только после взятия, передача только администратору", async () => {
  const current = { incident_id: "INC-22", rule_id: "r1", actor_name: "", node: "", owner: "", status: "new", tags: ["argus.system", "ops.storage"] };
  const writes: unknown[][] = [];
  const comments: unknown[][] = [];
  mocks.queries.incidentGet = async () => ({ ...current });
  mocks.queries.incidentTransition = async (...args) => {
    writes.push(args);
    const input = args[0] as { kind: string; status?: string; owner?: string; actor: string };
    current.status = input.kind === "take" ? "in_progress" : input.kind === "assign" ? current.status === "new" ? "new" : "waiting_owner" : String(input.status);
    current.owner = input.kind === "assign" ? String(input.owner) : input.actor;
  };
  mocks.queries.addIncidentComment = async (...args) => void comments.push(args);
  await login("analyst1");
  assert.equal((await incidents.addIncidentCommentAction({ error: null }, formData({ incident_id: "INC-22", body: "смотрю журнал" }))).error, null);
  assert.deepEqual(comments, [["INC-22", "analyst1", "смотрю журнал"]]);
  assert.match((await incidents.setIncidentStatusAction({ error: null }, formData({ incident_id: "INC-22", status: "closed" }))).error ?? "", /Сначала возьмите/);
  await login("admin");
  assert.equal((await incidents.assignIncidentAction({ error: null }, formData({ incident_id: "INC-22", owner: "analyst1" }))).error, null);
  assert.deepEqual(writes[0], [{ id: "INC-22", kind: "assign", owner: "analyst1", actor: "admin", role: "admin" }]);
  await login("analyst1");
  assert.match((await incidents.setIncidentStatusAction({ error: null }, formData({ incident_id: "INC-22", status: "closed" }))).error ?? "", /Сначала возьмите/);
  assert.equal((await incidents.takeIncidentAction({ error: null }, formData({ incident_id: "INC-22" }))).error, null);
  assert.match((await incidents.setIncidentStatusAction({ error: null }, formData({ incident_id: "INC-22", status: "closed" }))).error ?? "", /укажите причину/);
  assert.deepEqual(writes[1], [{ id: "INC-22", kind: "take", actor: "analyst1", role: "analyst" }]);
  assert.match((await incidents.assignIncidentAction({ error: null }, formData({ incident_id: "INC-22", owner: "analyst2" }))).error ?? "", /Недостаточно прав/);
  await login("admin");
  assert.match((await incidents.assignIncidentAction({ error: null }, formData({ incident_id: "INC-22", owner: "viewer1" }))).error ?? "", /Выберите аналитика/);
  // Администратор — тоже ответственный: в маленькой команде инциденты разбирает и он.
  assert.equal((await incidents.assignIncidentAction({ error: null }, formData({ incident_id: "INC-22", owner: "adm2" }))).error, null);
  assert.deepEqual(writes[2], [{ id: "INC-22", kind: "assign", owner: "adm2", actor: "admin", role: "admin" }]);
  assert.equal((await incidents.assignIncidentAction({ error: null }, formData({ incident_id: "INC-22", owner: "analyst2" }))).error, null);
  assert.deepEqual(writes[3], [{ id: "INC-22", kind: "assign", owner: "analyst2", actor: "admin", role: "admin" }]);
  await login("analyst2");
  assert.match((await incidents.setIncidentStatusAction({ error: null }, formData({ incident_id: "INC-22", status: "closed" }))).error ?? "", /Сначала возьмите/);
  await login("analyst1");
  assert.match((await incidents.setIncidentStatusAction({ error: null }, formData({ incident_id: "INC-22", status: "closed" }))).error ?? "", /Сначала возьмите/);
  await login("analyst2");
  assert.equal((await incidents.takeIncidentAction({ error: null }, formData({ incident_id: "INC-22" }))).error, null);
  // Эксплуатационное правило: вместо вердикта ИБ — причина и действие DevOps.
  assert.match((await incidents.setIncidentStatusAction({ error: null }, formData({ incident_id: "INC-22", status: "closed", reason: "Проверена цепочка событий, угрозы нет",
    disposition: "malicious", escalate: "no", severity_correct: "yes" }))).error ?? "", /причину и действие/);
  assert.equal((await incidents.setIncidentStatusAction({ error: null }, formData({ incident_id: "INC-22", status: "closed", reason: "Проверена цепочка событий, угрозы нет",
    ops_cause: "planned_work", ops_action: "no_action" }))).error, null);
  assert.deepEqual((writes.at(-1)?.[0] as { label?: unknown }).label, { ops_cause: "planned_work", ops_action: "no_action" });
});

test("blockIp: аудит строго до вызова движка; недоступный журнал отменяет блокировку; адрес — только из цепочки", async () => {
  await login("analyst1");
  mocks.queries.incidentGet = async () => ({ incident_id: "INC-7", chain: ["ssh from 203.0.113.7", "lateral 10.0.0.5"], actor_name: "203.0.113.7", rule_id: "r1", node: "n1" });
  const order: string[] = [];
  mocks.queries.requestBlockIp = async () => { order.push("engine"); return { results: [{ executor: "wazuh", ok: true, detail: "ok" }] }; };
  const baseAudit = mocks.queries.audit;
  mocks.queries.audit = async (user, action, target, detail = "", opts) => { order.push(`audit${opts?.strict ? ":strict" : ""}`); return baseAudit(user, action, target, detail, opts); };
  mocks.audit.length = 0;
  const ok = await incidents.blockIpAction({ error: null }, formData({ incident_id: "INC-7", ip: "203.0.113.7", reason: "брутфорс" }));
  assert.equal(ok.error, null);
  assert.deepEqual(order, ["audit:strict", "engine", "audit"], "первая запись — strict и до движка, вторая — результат");
  assert.equal(mocks.audit.filter((e) => e.action === "respond.block_ip").length, 2);
  assert.match(mocks.audit[0].detail, /запрос · INC-7 · брутфорс/);

  // Частный адрес из цепочки и чужой публичный — отказ без вызова движка
  order.length = 0;
  assert.match((await incidents.blockIpAction({ error: null }, formData({ incident_id: "INC-7", ip: "10.0.0.5", reason: "x" }))).error ?? "", /не относится/);
  assert.match((await incidents.blockIpAction({ error: null }, formData({ incident_id: "INC-7", ip: "198.51.100.1", reason: "x" }))).error ?? "", /не относится/);
  assert.match((await incidents.blockIpAction({ error: null }, formData({ incident_id: "INC-7", ip: "4.7.2.1.1", reason: "x" }))).error ?? "", /Некорректный/);
  assert.match((await incidents.blockIpAction({ error: null }, formData({ incident_id: "INC-7", ip: "203.0.113.7", reason: "" }))).error ?? "", /причину/);
  assert.deepEqual(order, []);

  // Журнал недоступен → strict-аудит бросает → движок не вызывается
  mocks.queries.audit = async (_u, _a, _t, _d, opts) => { if (opts?.strict) throw new Error("журнал действий недоступен — действие отменено"); };
  const fail = await incidents.blockIpAction({ error: null }, formData({ incident_id: "INC-7", ip: "203.0.113.7", reason: "брутфорс" }));
  assert.match(fail.error ?? "", /журнал действий недоступен/);
  assert.deepEqual(order, []);
  mocks.queries.audit = baseAudit;
  mocks.queries.incidentGet = async () => null;
  mocks.queries.requestBlockIp = async () => ({ error: "движок недоступен" });
});

test("manage-actions пишут аудит с sha256 содержимого XML; ошибка Wazuh — в FormState", async () => {
  await login("admin");
  mocks.audit.length = 0;
  const res = await manage.saveGroupConfAction({ error: null }, formData({ group: "web", xml: "<agent_config>\n</agent_config>" }));
  // Wazuh API в тестах недоступен — ошибка возвращается пользователю, не глотается
  assert.match(res.error ?? "", /Wazuh API недоступен/);
  const bad = await manage.saveGroupConfAction({ error: null }, formData({ group: "web", xml: "<agent_config>\n<a>\n</agent_config>" }));
  assert.match(bad.error ?? "", /XML некорректен — строка 3/);
  const badName = await manage.saveRuleFileAction({ error: null }, formData({ filename: "../ossec.conf", xml: "<group/>" }));
  assert.match(badName.error ?? "", /Имя файла/);
  const r2 = await manage.restartManagerAction();
  assert.match(r2.error ?? "", /Wazuh API недоступен/);
  assert.ok(mocks.audit.some((e) => e.action === "wazuh.manager.restart" && e.user === "admin"), "рестарт попадает в журнал даже при ошибке");
  // Ошибка Wazuh — в журнал для всех деструктивных действий, не только рестарта
  mocks.audit.length = 0;
  await manage.restartAgentAction(formData({ agent_id: "001" }));
  await manage.agentGroupAction(formData({ agent_id: "001", group_id: "web", op: "remove" }));
  await manage.createGroupAction({ error: null }, formData({ name: "web" }));
  await manage.deleteGroupAction(formData({ name: "web" }));
  await manage.saveGroupConfAction({ error: null }, formData({ group: "web", xml: "<agent_config/>" }));
  await manage.saveRuleFileAction({ error: null }, formData({ filename: "x.xml", xml: "<group name=\"a,\"/>" }));
  const actionsLogged = mocks.audit.map((e) => e.action).sort();
  assert.deepEqual(actionsLogged, ["wazuh.agent.group.remove", "wazuh.agent.restart", "wazuh.group.conf", "wazuh.group.create", "wazuh.group.delete", "wazuh.rules.save"]);
  assert.ok(mocks.audit.every((e) => /ошибка: Wazuh API недоступен/.test(e.detail)), JSON.stringify(mocks.audit));
  assert.ok(mocks.audit.filter((e) => /sha256:[0-9a-f]{8}/.test(e.detail)).length === 2, "XML-действия пишут sha256 и при ошибке");
});

test("manage-actions: корневые элементы — несколько agent_config/group допустимы, чужой корень — отказ", async () => {
  await login("admin");
  const multi = await manage.saveGroupConfAction({ error: null }, formData({ group: "web", xml: "<agent_config os=\"Linux\"/>\n<agent_config profile=\"web\"/>" }));
  assert.match(multi.error ?? "", /Wazuh API недоступен/, "два корня прошли проверку и дошли до API");
  const foo = await manage.saveGroupConfAction({ error: null }, formData({ group: "web", xml: "<foo/>" }));
  assert.match(foo.error ?? "", /ожидается agent_config, встречен корневой <foo>/);
  const mixed = await manage.saveGroupConfAction({ error: null }, formData({ group: "web", xml: "<agent_config/><ossec_config/>" }));
  assert.match(mixed.error ?? "", /ожидается agent_config, встречен корневой <ossec_config>/);
  const rules = await manage.saveRuleFileAction({ error: null }, formData({ filename: "x.xml", xml: "<group name=\"a,\"/>\n<group name=\"b,\"/>" }));
  assert.match(rules.error ?? "", /Wazuh API недоступен/);
  const dec = await manage.saveRuleFileAction({ error: null }, formData({ filename: "x.xml", xml: "<decoder name=\"x\"/>" }));
  assert.match(dec.error ?? "", /ожидается group, встречен корневой <decoder>/);
  const attr = await manage.saveRuleFileAction({ error: null }, formData({ filename: "x.xml", xml: "<group name=\"a,\"><rule id=\"1\" level=\"1\"><field name=\"x\">a>b</field></rule></group>" }));
  assert.match(attr.error ?? "", /Wazuh API недоступен/);
  // Имя группы и default — разные сообщения
  assert.match((await manage.deleteGroupAction(formData({ name: "../x" }))).error ?? "", /Некорректное имя группы/);
  assert.match((await manage.deleteGroupAction(formData({ name: "default" }))).error ?? "", /default удалить нельзя/);
});

test("manage-actions message(): TLS — понятная строка, неизвестная ошибка — общая фраза, текст только в лог", async () => {
  await login("admin");
  const { WazuhApiError } = require("../src/lib/wazuh-api") as typeof import("../src/lib/wazuh-api");
  const logged: unknown[][] = [];
  const origErr = console.error;
  console.error = (...a: unknown[]) => void logged.push(a);
  try {
    const tls = Object.assign(new Error("self-signed certificate"), { code: "DEPTH_ZERO_SELF_SIGNED_CERT" });
    mocks.wazuh.restartManager = async () => { throw tls; };
    assert.match((await manage.restartManagerAction()).error ?? "", /ошибка TLS/);
    mocks.wazuh.restartManager = async () => { throw new Error("unable to verify the first certificate"); };
    assert.match((await manage.restartManagerAction()).error ?? "", /ошибка TLS/);
    mocks.wazuh.restartManager = async () => { throw Object.assign(new Error("write EPROTO ssl3_get_record:wrong version number"), { code: "EPROTO" }); };
    assert.match((await manage.restartManagerAction()).error ?? "", /ошибка TLS/);
    logged.length = 0;
    mocks.wazuh.restartManager = async () => { throw new Error("secret internal detail http://10.0.0.1:55000"); };
    const r = await manage.restartManagerAction();
    assert.equal(r.error, "Wazuh API: ошибка запроса — подробности в логе консоли");
    assert.ok(logged.some((a) => a.join(" ").includes("secret internal detail")), "полный текст — в лог");
    assert.ok(mocks.audit.some((e) => e.action === "wazuh.manager.restart" && e.detail === "ошибка: Wazuh API: ошибка запроса — подробности в логе консоли"));
    mocks.wazuh.restartManager = async () => { throw new WazuhApiError("Wazuh API 401: неверные учётные данные", 401); };
    assert.match((await manage.restartManagerAction()).error ?? "", /401/);
    mocks.wazuh.restartManager = async () => { throw new Error("Wazuh API: таймаут запроса"); };
    assert.equal((await manage.restartManagerAction()).error, "Wazuh API: таймаут запроса");
  } finally {
    delete mocks.wazuh.restartManager;
    console.error = origErr;
  }
});

test("TOTP-действия работают только над своим пользователем", async () => {
  await login("analyst1");
  const begin = await actions.beginTotpAction({ error: null }, new FormData());
  assert.ok(begin.secret, "секрет выдан");
  const state = await auth.getAuthState();
  const a = state.users!.find((u) => u.name === "analyst1")!;
  assert.equal(a.totpPendingSecret, begin.secret, "pending — у пользователя a");
  assert.equal(state.totpPendingSecret ?? null, null, "у встроенного admin ничего не изменилось");
  assert.ok(!state.users!.some((u) => u.name !== "analyst1" && u.totpPendingSecret), "у остальных ничего не изменилось");

  const { verifyTotp } = require("../src/lib/totp") as typeof import("../src/lib/totp");
  // Вычисляем текущий код независимой реализацией через сам verifyTotp: перебираем все 6-значные — слишком долго,
  // поэтому берём код через hotp из totp.ts (та же математика, что в totp.test.ts).
  const code = currentCode(begin.secret!);
  assert.ok(verifyTotp(begin.secret!, code));
  const confirm = await actions.confirmTotpAction({ error: null }, formData({ code }));
  assert.equal(confirm.error, null);
  assert.equal(await auth.isTotpEnabled("analyst1"), true);
  assert.equal(await auth.isTotpEnabled("admin"), false);
  assert.equal(await auth.isTotpEnabled("viewer1"), false);

  // Вход a без кода → «требуется», с кодом → ок; для v код не нужен
  assert.equal(await auth.verifyLoginTotp("analyst1", ""), "required");
  assert.equal(await auth.verifyLoginTotp("analyst1", code), "ok");
  assert.equal(await auth.verifyLoginTotp("viewer1", ""), "ok");

  // Отключение: нужен и пароль, и код
  assert.match((await actions.disableTotpAction({ error: null }, formData({ password: "wrong", code }))).error ?? "", /пароль/);
  assert.match((await actions.disableTotpAction({ error: null }, formData({ password: passwords.analyst1, code: "000000" }))).error ?? "", /код/i);
  assert.equal((await actions.disableTotpAction({ error: null }, formData({ password: passwords.analyst1, code: currentCode(begin.secret!) }))).error, null);
  assert.equal(await auth.isTotpEnabled("analyst1"), false);
});

test("смена пароля — любым локальным пользователем по своему текущему; SSO — отказ", async () => {
  await login("viewer1");
  const bad = await actions.changePasswordAction({ error: null }, formData({ current: "nope", next: "NewPassw0rd.", confirm: "NewPassw0rd." }));
  assert.match(bad.error ?? "", /Текущий пароль/);
  const ok = await actions.changePasswordAction({ error: null }, formData({ current: passwords.viewer1, next: "NewPassw0rd.", confirm: "NewPassw0rd." }));
  assert.equal(ok.error, null);
  assert.equal(await auth.verifyCredentials("viewer1", "NewPassw0rd."), "viewer");
  assert.equal((await auth.getSession())?.user, "viewer1", "сессия переоформлена после смены");

  await auth.createSession("sso:someone", "admin", true);
  const sso = await actions.changePasswordAction({ error: null }, formData({ current: "x", next: "NewPassw0rd.", confirm: "NewPassw0rd." }));
  assert.match(sso.error ?? "", /IdP/);
  assert.match((await actions.beginTotpAction({ error: null }, new FormData())).error ?? "", /IdP/);
});

test("deleteUser: нельзя себя, встроенного admin и последнего именованного администратора", async () => {
  await login("adm2");
  assert.match((await users.deleteUserAction(formData({ name: "adm2" }))).error ?? "", /самого себя/);
  assert.match((await users.deleteUserAction(formData({ name: "admin" }))).error ?? "", /Встроенного/);
  await login("admin");
  assert.match((await users.deleteUserAction(formData({ name: "adm2" }))).error ?? "", /последний администратор/);
  const r = await auth.createUser("adm3", "admin");
  assert.ok("password" in r);
  assert.equal((await users.deleteUserAction(formData({ name: "adm2" }))).error, null);
  assert.ok(mocks.audit.some((e) => e.action === "user.delete" && e.target === "adm2"));
  await login("viewer1");
  assert.match((await users.deleteUserAction(formData({ name: "analyst1" }))).error ?? "", DENIED);
  assert.match((await users.resetUserPasswordAction({ error: null }, formData({ name: "analyst1" }))).error ?? "", DENIED);
});

test("неудачный вход — в аудит без пароля; TOTP-лимит по имени", async () => {
  mocks.jar.clear();
  mocks.audit.length = 0;
  const res = await actions.loginAction({ error: null }, formData({ user: "analyst1", password: "WrongPassw0rd." }));
  assert.match(res.error ?? "", /Неверный логин/);
  const e = mocks.audit.find((x) => x.action === "session.login.failed");
  assert.ok(e && e.user === "analyst1");
  assert.ok(!JSON.stringify(mocks.audit).includes("WrongPassw0rd"), "пароль в журнал не попадает");
});

/** Текущий TOTP-код по RFC 6238 (та же математика, что в totp.test.ts). */
function currentCode(secret: string): string {
  const crypto = require("node:crypto") as typeof import("node:crypto");
  const A = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";
  let bits = 0, v = 0; const out: number[] = [];
  for (const c of secret) { v = (v << 5) | A.indexOf(c); bits += 5; if (bits >= 8) { out.push((v >>> (bits - 8)) & 255); bits -= 8; } }
  const c = Math.floor(Date.now() / 30000);
  const m = Buffer.alloc(8); m.writeBigUInt64BE(BigInt(c));
  const mac = crypto.createHmac("sha1", Buffer.from(out)).update(m).digest();
  const o = mac[19] & 15;
  return String((((mac[o] & 127) << 24) | (mac[o + 1] << 16) | (mac[o + 2] << 8) | mac[o + 3]) % 1e6).padStart(6, "0");
}
