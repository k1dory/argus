// Страницы паспорта субъекта с данными: список персон (сводка по алиасам,
// непривязанные субъекты, роли, пустое состояние, хранилище недоступно),
// паспорт (алиасы открытые/закрытые/на удержании/неоднозначные, разделы,
// инциденты по действию алиаса, таймлайн, частичная деградация, формы admin,
// 404), резолв по алиасу (нет значения, найден → паспорт, не привязан,
// неоднозначно, хранилище недоступно). ClickHouse — подмена fetch по подстроке SQL.
import { test, before, beforeEach } from "node:test";
import assert from "node:assert/strict";
import fs from "node:fs";
import { installNextMocks, isRedirect, loadAuth } from "./_next-mock";
import { pageText } from "./_render";

const auth = loadAuth();
const mocks = installNextMocks();

/* eslint-disable @typescript-eslint/no-require-imports -- страницы грузятся после моков */
type Props = { params: Promise<Record<string, string>>; searchParams: Promise<Record<string, string | string[] | undefined>> };
type Page = { default: (props: Props) => Promise<unknown>; generateMetadata?: (props: Props) => Promise<{ title?: string }> };
const actorsPage = require("../src/app/(console)/actors/page") as Page;
const actorPage = require("../src/app/(console)/actors/[id]/page") as Page;
const byAliasPage = require("../src/app/(console)/actors/by-alias/page") as Page;
/* eslint-enable @typescript-eslint/no-require-imports */

const props = (params: Record<string, string> = {}, sp: Record<string, string> = {}): Props => ({ params: Promise.resolve(params), searchParams: Promise.resolve(sp) });
const isNotFound = (e: unknown): boolean => e instanceof Error && /NEXT_HTTP_ERROR_FALLBACK;404|NEXT_NOT_FOUND/.test(String((e as { digest?: string }).digest ?? e.message));

/* ===== fetch: ClickHouse по подстроке SQL ===== */
type Route = { when: (sql: string) => boolean; rows: (params: URLSearchParams) => Record<string, unknown>[]; fail?: boolean };
let routes: Route[] = [];
let chDown = false;
const fetched: string[] = [];
globalThis.fetch = (async (input: URL | string | Request, init?: RequestInit) => {
  const sql = String(init?.body ?? "");
  fetched.push(sql);
  if (chDown) throw Object.assign(new Error("connect ECONNREFUSED 127.0.0.1:9"), { cause: { code: "ECONNREFUSED" } });
  for (const r of routes) {
    if (!r.when(sql)) continue;
    if (r.fail) return new Response("Code: 60. DB::Exception: Table argus.events does not exist", { status: 500 });
    const params = new URL(input instanceof Request ? input.url : String(input)).searchParams;
    return new Response(r.rows(params).map((x) => JSON.stringify(x)).join("\n") + "\n");
  }
  return new Response("");
}) as typeof fetch;

const OPEN = "2020-01-01 00:00:00.000";
const persons = [
  { person_id: "i.petrov", display: "Иван Петров", kind: "person", team: "platform", note: "дежурный" },
  { person_id: "svc.backup", display: "", kind: "service", team: "", note: "" },
  { person_id: "a.smirnova", display: "Анна Смирнова", kind: "person", team: "", note: "" },
];
const alias = (person_id: string, alias_kind: string, alias_value: string, over: Record<string, unknown> = {}) => ({
  person_id, alias_kind, alias_value, valid_from: OPEN, valid_to_raw: null, source: "yaml", confidence: 1, note: "", ...over,
});
const aliases = [
  alias("i.petrov", "login", "ivan.petrov"),
  alias("i.petrov", "ip", "10.0.0.5", { valid_to_raw: "2021-01-01 00:00:00.000", source: "event:vpn", note: "старый адрес" }),
  alias("i.petrov", "email", "ivan@corp.local", { confidence: "0.3", note: "policy:hold:many-logins", source: "event:idp" }),
  alias("i.petrov", "host", "ws-ivan"),
  alias("a.smirnova", "login", "a.smirnova"),
  alias("a.smirnova", "uid", "ivan.petrov"), // тот же actor_name у другой персоны — неоднозначность
  alias("a.smirnova", "bogus", "x"), // неизвестный вид — отбрасывается
];
const TS = "2026-10-29 09:30:00.000";
const logRow = (action: string, outcome: string, over: Record<string, unknown> = {}) => ({
  ts: TS, source: "linux.auth", source_class: "syslog", action, outcome, severity: 3, actor_name: "ivan.petrov", actor_kind: "user", object: "", node: "bastion",
  session_id: "", src_ip: "203.0.113.5", dst_ip: "", value: 0, unit: "", attrs: {}, pii: 0, ...over,
});

/** Маршруты для всех запросов паспорта. */
function fullRoutes(): Route[] {
  return [
    { when: (s) => s.includes("FROM identities") && !s.includes("identity_aliases") && s.includes("WHERE person_id = {id:String}"), rows: () => persons.filter((p) => p.person_id === "i.petrov") },
    { when: (s) => s.includes("FROM identities") && !s.includes("identity_aliases") && s.includes("ORDER BY display"), rows: () => persons },
    { when: (s) => s.includes("LEFT JOIN"), rows: () => [] },
    { when: (s) => s.includes("FROM identity_aliases") && s.includes("WHERE person_id = {id:String}"), rows: () => aliases.filter((a) => a.person_id === "i.petrov") },
    { when: (s) => s.includes("FROM identity_aliases"), rows: () => aliases },
    // Активность списка: персона 1 плана — первая персона с алиасами.
    { when: (s) => s.includes("GROUP BY hits") && s.includes("FROM events"), rows: () => [{ p: 1, n: 5, last_ts: "2026-10-29 09:00:00.000" }] },
    { when: (s) => s.includes("countIf(") && s.includes("FROM incidents_current"), rows: () => [{ i0: 0, i1: 2 }] },
    { when: (s) => s.includes("groupUniqArray"), rows: () => [
      { actor_name: "a.smirnova", count: 40, first_ts: TS, last_ts: TS, sources: ["idp"] },
      { actor_name: "guest7", count: "12", first_ts: TS, last_ts: TS, sources: ["linux.auth", "vpn"] },
      { actor_name: "ivan.petrov", count: 9, first_ts: TS, last_ts: TS, sources: ["linux.auth"] },
    ] },
    { when: (s) => s.includes("GROUP BY source_class"), rows: () => [{ source_class: "syslog", count: "7" }, { source_class: "netflow", count: 3 }] },
    { when: (s) => s.includes("GROUP BY node"), rows: () => [{ node: "bastion", count: 4, first_ts: TS, last_ts: TS }] },
    { when: (s) => s.includes("GROUP BY src_ip"), rows: () => [{ src_ip: "203.0.113.5", count: 2, first_ts: TS, last_ts: TS }] },
    { when: (s) => s.includes("GROUP BY source, source_class"), rows: () => [{ source: "linux.auth", source_class: "syslog", count: 7, first_ts: TS, last_ts: TS }] },
    { when: (s) => s.includes("incident_id AS id"), rows: () => [
      { id: "INC-7", level: "high", status: "new", rule_id: "ssh.bruteforce", rule_title: "Перебор SSH", created_s: "2026-10-29 09:30:00", actor_name: "ivan.petrov", first_s: "2026-10-29 09:00:00" },
      { id: "INC-8", level: "low", status: "weird", rule_id: "x", rule_title: "До алиаса", created_s: "2026-10-29 09:30:00", actor_name: "ivan.petrov", first_s: "2019-01-01 00:00:00" },
    ] },
    // Разделы получают собственные строки по параметру section. Общая лента
    // ниже сохраняет все семь событий и больше не служит ответом каждого раздела.
    { when: (s) => s.includes("{section:String}"), rows: (params) => ({
      login: [logRow("auth.login", "failure")],
      host: [logRow("sudo", "success", { object: "/bin/ls" })],
      network: [logRow("net.flow", "allow", { source: "netflow.core", source_class: "netflow", dst_ip: "8.8.8.8", node: "" })],
      app: [logRow("app.authorize", "success", { src_ip: "" })],
      change: [logRow("user.create", "success", { object: "guest7" }), logRow("identity.alias", "deny")],
    } as Record<string, Record<string, unknown>[]>)[params.get("param_section") ?? ""] ?? [] },
    { when: (s) => s.includes("ORDER BY ts DESC LIMIT"), rows: () => [
      logRow("auth.login", "failure"),
      logRow("sudo", "success", { object: "/bin/ls" }),
      logRow("net.flow", "allow", { source: "netflow.core", source_class: "netflow", dst_ip: "8.8.8.8", node: "" }),
      logRow("app.authorize", "success", { src_ip: "" }),
      logRow("user.create", "success", { object: "guest7" }),
      logRow("identity.alias", "deny"),
      logRow("misc", "", { actor_name: "" }),
    ] },
  ];
}

before(async () => {
  await auth.getAuthState();
  const pwd = fs.readFileSync(auth.ADMIN_PASSWORD_FILE, "utf8").trim();
  assert.equal(await auth.changePassword("admin", pwd, "AdminPassw0rd."), null);
  for (const [name, role] of [["viewer1", "viewer"], ["analyst1", "analyst"]] as const) assert.ok("password" in (await auth.createUser(name, role)));
  console.error = () => undefined;
});

beforeEach(() => {
  routes = fullRoutes();
  chDown = false;
  fetched.length = 0;
  mocks.jar.clear();
});

/* ===== Список ===== */

test("список: сводка по персонам — события и инциденты только у персон с алиасами, вид и команда, последняя активность", async () => {
  await auth.createSession("analyst1", "analyst");
  const text = await pageText(await actorsPage.default(props({}, { range: "24h" })));
  assert.match(text, /Персон 3/);
  assert.match(text, /Активны за 24 часа 1/, "события есть только у i.petrov");
  assert.match(text, /Служебных учёток 1/);
  assert.match(text, /С инцидентами 1/, "два инцидента у a.smirnova");
  assert.match(text, /Иван Петров/);
  assert.match(text, /svc\.backup/, "персона без display показана по идентификатору");
  assert.match(text, /служебная/);
  assert.match(text, /platform/);
  assert.match(text, /2026-10-29 09:00:00/, "последняя активность i.petrov");
  const evs = fetched.filter((s) => s.includes("FROM events") && s.includes("GROUP BY hits"));
  assert.equal(evs.length, 1, "события всех персон — одним проходом");
  assert.match(evs[0], /transform\(lowerUTF8\(actor_name\), \{ap_k1:Array\(String\)\}/, "login сравнивается без регистра");
  assert.ok(!evs[0].includes("ivan@corp.local"), "значения — параметрами, не в тексте SQL");
  assert.ok(fetched.some((s) => s.includes("FROM events") && s.includes("parseDateTime64BestEffort({from:String}")), "окно периода параметрами");
});

test("список: непривязанные субъекты — привязанные отфильтрованы, аналитик видит «проверить», администратор — «привязать»", async () => {
  await auth.createSession("analyst1", "analyst");
  let text = await pageText(await actorsPage.default(props()));
  assert.match(text, /guest7/);
  assert.match(text, /linux\.auth, vpn/);
  assert.ok(!/a\.smirnova 40/.test(text), "a.smirnova привязана действующим алиасом");
  assert.match(text, /проверить/);
  assert.ok(!/привязать/.test(text));
  mocks.jar.clear();
  await auth.createSession("admin", "admin");
  text = await pageText(await actorsPage.default(props()));
  assert.match(text, /привязать/);
});

test("список: нет персон — подсказка про источники; все субъекты привязаны — отдельная фраза", async () => {
  await auth.createSession("analyst1", "analyst");
  routes = [
    { when: (s) => s.includes("FROM identities") && !s.includes("identity_aliases"), rows: () => [] },
    { when: (s) => s.includes("FROM identity_aliases"), rows: () => [] },
    { when: (s) => s.includes("groupUniqArray"), rows: () => [] },
  ];
  const text = await pageText(await actorsPage.default(props()));
  assert.match(text, /Персон пока нет/);
  assert.match(text, /identities\.yml/);
  assert.match(text, /Все активные субъекты за сутки привязаны/);
  assert.match(text, /Персон 0/);
});

test("список: хранилище недоступно — панель «недоступно» вместо таблицы и алерт у непривязанных, страница не падает", async () => {
  await auth.createSession("analyst1", "analyst");
  chDown = true;
  const text = await pageText(await actorsPage.default(props()));
  assert.match(text, /недоступн/i);
  assert.match(text, /Список недоступен/);
  assert.ok(!/Персон 3/.test(text));
});

/* ===== Паспорт ===== */

test("паспорт: алиасы (действует / закрыт / на удержании / неоднозначно), сводка, разделы, инциденты по действию алиаса, таймлайн; аналитик без форм", async () => {
  await auth.createSession("analyst1", "analyst");
  const text = await pageText(await actorPage.default(props({ id: "i.petrov" }, { range: "7d" })));
  assert.match(text, /Иван Петров i\.petrov/);
  assert.match(text, /человек · команда platform · дежурный/);
  assert.match(text, /Алиасы 4 · на удержании 1/);
  assert.match(text, /ivan\.petrov/);
  assert.match(text, /неоднозначно/, "login ivan.petrov действует и как uid у a.smirnova");
  assert.match(text, /на удержании/);
  assert.match(text, /политика many-logins/);
  assert.match(text, /старый адрес/, "заметка закрытого алиаса");
  assert.match(text, /2021-01-01 00:00:00/, "закрытый алиас — дата «по»");
  assert.match(text, /действует/);
  assert.match(text, /0\.30/);
  assert.match(text, /Событий за 7 дней 10/);
  assert.match(text, /Узлов 1/);
  assert.match(text, /Адресов 1/);
  assert.match(text, /Инцидентов 1/, "INC-8 начался до действия алиаса и не считается");
  assert.match(text, /syslog 7 · netflow 3/);
  assert.match(text, /linux\.auth \(7/);
  assert.match(text, /Входы · 1/);
  assert.match(text, /отказов 1/);
  assert.match(text, /Хосты и сеансы · 1/);
  assert.match(text, /Сеть · 1/);
  assert.match(text, /Приложения · 1/);
  assert.match(text, /Изменения · 2/, "user.create success и identity.alias");
  assert.match(text, /INC-7/);
  assert.ok(!/INC-8/.test(text));
  assert.match(text, /Перебор SSH/);
  assert.match(text, /Таймлайн · последние 7/);
  assert.match(text, /8\.8\.8\.8|bastion/);
  assert.match(text, /делятся с другой персоной/, "подсказка про неоднозначность");
  assert.match(text, /на удержании.*в сшивку не входят/);
  assert.ok(!/Добавить алиас/.test(text), "форма привязки — только admin");
  assert.ok(!/Закрыть алиас/.test(text));
  assert.match(text, /открыть в журнале по ivan\.petrov/, "основной алиас — login");
  const rec = mocks.audit.find((a) => a.action === "actor.view" && a.target === "i.petrov" && a.detail === "7d");
  assert.ok(rec, "просмотр записан до чтения");
  const tl = fetched.find((s) => s.includes("ORDER BY ts DESC LIMIT"))!;
  assert.ok(!tl.includes("ivan@corp.local"), "удержанный алиас в предикате отсутствует");
  assert.ok(!tl.includes("10.0.0.5"), "закрытый в 2021 алиас вне окна");
});

test("паспорт: длинный раздел показывает 50 строк и явно сообщает полный размер выборки", async () => {
  await auth.createSession("analyst1", "analyst");
  const section = routes.find((route) => route.when("SELECT * WHERE section = {section:String}"));
  assert.ok(section);
  const original = section.rows;
  section.rows = (params) => params.get("param_section") === "login"
    ? Array.from({ length: 60 }, (_, i) => logRow("auth.login", "success", { object: `section-entry-${String(i).padStart(3, "0")}` }))
    : original(params);
  const text = await pageText(await actorPage.default(props({ id: "i.petrov" })));
  assert.match(text, /Входы · 60/);
  assert.match(text, /50 из 60.*Markdown.*API/, "ограничение страницы не выдаётся за полный результат");
  assert.match(text, /section-entry-049/, "последняя видимая строка присутствует");
  assert.doesNotMatch(text, /section-entry-050|section-entry-059/, "остальные строки доступны через полный экспорт");
});

test("паспорт: администратор видит формы — добавить, закрыть действующий, подтвердить удержанный; закрытый алиас кнопок не имеет", async () => {
  await auth.createSession("admin", "admin");
  const text = await pageText(await actorPage.default(props({ id: "i.petrov" })));
  assert.match(text, /Добавить алиас/);
  // Кнопки строк: «закрыть» у трёх действующих алиасов (в том числе удержанного), «подтвердить» — у удержанного; у закрытого 10.0.0.5 кнопок нет.
  assert.equal((text.match(/ закрыть /g) ?? []).length, 3, text.slice(0, 400));
  assert.equal((text.match(/ подтвердить /g) ?? []).length, 1);
  assert.match(text, /0\.30 события подтвердить закрыть/, "у удержанного алиаса — обе кнопки");
  assert.match(text, /старый адрес 1\.00 события email/, "у закрытого алиаса кнопок нет");
  assert.match(text, /Markdown/, "кнопка выгрузки");
});

test("паспорт: часть запросов упала — «Часть данных временно недоступна», остальное показано; persona без алиасов — пустой паспорт", async () => {
  await auth.createSession("analyst1", "analyst");
  for (const r of routes) if (r.when("SELECT node, count() AS count FROM events WHERE x GROUP BY node ORDER BY")) r.fail = true;
  let text = await pageText(await actorPage.default(props({ id: "i.petrov" })));
  assert.match(text, /Часть данных временно недоступна/);
  assert.match(text, /Не удалось загрузить: узлы/);
  assert.match(text, /Узлов 0/);
  assert.match(text, /Событий за 7 дней 10/, "остальные разделы на месте");

  // Персона без алиасов: предикат событий — «0», и подмена ClickHouse на такие запросы ничего не возвращает.
  routes = fullRoutes().map((r) => ({ ...r, when: (s: string) => r.when(s) && !/ AND 0 /.test(s) }));
  for (const r of routes) if (r.when("SELECT * FROM identity_aliases WHERE person_id = {id:String}")) r.rows = () => [];
  text = await pageText(await actorPage.default(props({ id: "i.petrov" })));
  assert.match(text, /Алиасов нет — паспорт пуст/);
  assert.match(text, /в окне нет событий по алиасам|Событий нет/);
  const tl = fetched.filter((s) => s.includes("ORDER BY ts DESC LIMIT")).at(-1)!;
  assert.match(tl, /WHERE ts >= .* AND 0 ORDER BY/, "без алиасов предикат — ложь, не весь журнал");
});

test("паспорт: неверный идентификатор и неизвестная персона — 404; хранилище недоступно — панель после записи в журнал", async () => {
  await auth.createSession("analyst1", "analyst");
  await assert.rejects(actorPage.default(props({ id: "Bad Id!" })), isNotFound);
  assert.equal(mocks.audit.filter((a) => a.target === "Bad Id!").length, 0, "неверный id не пишется в журнал");
  for (const r of routes) if (r.when("FROM identities GROUP BY person_id WHERE person_id = {id:String}")) r.rows = () => [];
  await assert.rejects(actorPage.default(props({ id: "nobody" })), isNotFound);
  assert.ok(mocks.audit.some((a) => a.action === "actor.view" && a.target === "nobody"), "просмотр несуществующей персоны записан");
  chDown = true;
  const text = await pageText(await actorPage.default(props({ id: "i.petrov" })));
  assert.match(text, /i\.petrov/);
  assert.match(text, /недоступн/i);
  assert.equal(await actorPage.generateMetadata!(props({ id: "i.petrov" })).then((m) => m.title), "i.petrov · Субъекты");
  assert.equal(await actorPage.generateMetadata!(props({ id: "Bad Id!" })).then((m) => m.title), "Субъект · Субъекты");
});

/* ===== Резолв по алиасу ===== */

test("по алиасу: без v — подсказка; одна персона — переход в паспорт (регистр и пробелы не мешают)", async () => {
  await auth.createSession("analyst1", "analyst");
  const text = await pageText(await byAliasPage.default(props()));
  assert.match(text, /Нет значения/);
  assert.match(text, /параметре v/);
  assert.equal(fetched.filter((s) => s.includes("LEFT JOIN")).length, 0, "без значения резолв не выполняется");

  for (const r of routes) if (r.when("LEFT JOIN")) r.rows = () => [{ ...aliases[0], display: "Иван Петров", kind: "person" }];
  await assert.rejects(byAliasPage.default(props({}, { v: "  Ivan.Petrov " })), (e: unknown) => isRedirect(e) && /\/actors\/i\.petrov/.test(String((e as { digest?: string }).digest)));
  const q = fetched.find((s) => s.includes("LEFT JOIN"))!;
  assert.match(q, /\{lv:String\}/, "нижний регистр — параметром, не в SQL");
});

test("по алиасу: не привязан — ссылка в журнал (actor для логина, src для адреса); форма привязки только у admin; удержанный алиас не резолвит", async () => {
  await auth.createSession("analyst1", "analyst");
  let text = await pageText(await byAliasPage.default(props({}, { v: "guest7" })));
  assert.match(text, /Не привязан/);
  assert.match(text, /guest7/);
  assert.match(text, /Привязать алиас к персоне может администратор/);
  assert.ok(!/Привязать к персоне/.test(text));

  for (const r of routes) if (r.when("LEFT JOIN")) r.rows = () => [{ ...aliases[2], display: "Иван Петров", kind: "person" }];
  text = await pageText(await byAliasPage.default(props({}, { v: "ivan@corp.local" })));
  assert.match(text, /Не привязан/, "алиас на удержании персону не резолвит");

  mocks.jar.clear();
  await auth.createSession("admin", "admin");
  text = await pageText(await byAliasPage.default(props({}, { v: "203.0.113.9" })));
  assert.match(text, /Не привязан/);
  assert.match(text, /Привязать к персоне/);
  assert.match(text, /только администратор/);
  assert.ok(!/может администратор/.test(text));
  assert.ok(fetched.some((s) => s.includes("FROM identities") && s.includes("ORDER BY display")), "admin получает список персон для формы");
});

test("по алиасу: неоднозначно — кандидаты с интервалами, выбор не делается; хранилище недоступно — панель", async () => {
  await auth.createSession("admin", "admin");
  for (const r of routes) if (r.when("LEFT JOIN")) r.rows = () => [
    { ...aliases[0], display: "Иван Петров", kind: "person" },
    { ...aliases[5], display: "Анна Смирнова", kind: "person" },
    { ...aliases[5], valid_from: "2019-01-01 00:00:00.000", valid_to_raw: "2019-06-01 00:00:00.000", display: "Анна Смирнова", kind: "person" },
  ];
  let text = await pageText(await byAliasPage.default(props({}, { v: "ivan.petrov" })));
  assert.match(text, /Неоднозначно 2 совпадений/);
  assert.match(text, /Иван Петров · i\.petrov · login · с 2020-01-01 00:00:00/);
  assert.match(text, /Анна Смирнова · a\.smirnova · uid · с 2020-01-01 00:00:00/, "на персону одна запись — открытый интервал предпочтительнее");
  assert.ok(!/по 2019-06-01/.test(text));
  assert.match(text, /Закройте лишний алиас/);
  assert.match(text, /Привязать к персоне/, "admin может привязать и при неоднозначности");

  chDown = true;
  text = await pageText(await byAliasPage.default(props({}, { v: "guest7" })));
  assert.match(text, /недоступн/i);
  assert.ok(!/Привязать к персоне/.test(text), "без хранилища форма не показывается");
});
