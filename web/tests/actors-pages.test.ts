// Страницы паспорта: наблюдатель получает отказ по роли (ForbiddenError →
// error.tsx «Доступ запрещён»), а без записи в журнал действий паспорт не
// читает данные и показывает «журнал действий недоступен».
import { test, before } from "node:test";
import assert from "node:assert/strict";
import fs from "node:fs";
import { installNextMocks, loadAuth } from "./_next-mock";

const auth = loadAuth();
const mocks = installNextMocks();

/* eslint-disable @typescript-eslint/no-require-imports -- страницы грузятся после моков */
type Page = { default: (props: { params: Promise<Record<string, string>>; searchParams: Promise<Record<string, string | string[] | undefined>> }) => Promise<unknown> };
const actorsPage = require("../src/app/(console)/actors/page") as Page;
const actorPage = require("../src/app/(console)/actors/[id]/page") as Page;
const byAliasPage = require("../src/app/(console)/actors/by-alias/page") as Page;
const actions = require("../src/lib/actor-actions") as typeof import("../src/lib/actor-actions");
/* eslint-enable @typescript-eslint/no-require-imports */

const fetched: string[] = [];
globalThis.fetch = (async (_url: URL | string, init?: RequestInit) => {
  const sql = String(init?.body ?? "");
  fetched.push(sql);
  if (sql.includes("FROM identities") && !sql.includes("identity_aliases")) return new Response('{"person_id":"i.petrov","display":"Иван Петров","kind":"person","team":"","note":""}\n');
  return new Response("");
}) as typeof fetch;

const isForbidden = (err: unknown): boolean => err instanceof Error && (err as { digest?: string }).digest === "FORBIDDEN";
const props = (params: Record<string, string> = {}, sp: Record<string, string> = {}) => ({ params: Promise.resolve(params), searchParams: Promise.resolve(sp) });

/** Все строки текста из дерева React-элементов (без рендера). */
function textOf(node: unknown): string {
  if (node === null || node === undefined || typeof node === "boolean") return "";
  if (typeof node === "string" || typeof node === "number") return String(node);
  if (Array.isArray(node)) return node.map(textOf).join(" ");
  if (typeof node === "object" && "props" in node) {
    const p = (node as { props: Record<string, unknown> }).props;
    return [p.children, p.label, p.title, p.reason, p.subtitle].map(textOf).join(" ");
  }
  return "";
}

before(async () => {
  await auth.getAuthState();
  const pwd = fs.readFileSync(auth.ADMIN_PASSWORD_FILE, "utf8").trim();
  assert.equal(await auth.changePassword("admin", pwd, "AdminPassw0rd."), null);
  for (const [name, role] of [["viewer1", "viewer"], ["analyst1", "analyst"]] as const) assert.ok("password" in (await auth.createUser(name, role)));
  console.error = () => undefined;
});

test("наблюдатель: все три страницы — ForbiddenError, хранилище не опрашивается", async () => {
  await auth.createSession("viewer1", "viewer");
  const n = fetched.length;
  await assert.rejects(actorsPage.default(props()), isForbidden);
  await assert.rejects(actorPage.default(props({ id: "i.petrov" })), isForbidden);
  await assert.rejects(byAliasPage.default(props({}, { v: "x" })), isForbidden);
  assert.equal(fetched.length, n);
  assert.equal(mocks.audit.filter((a) => a.action === "actor.view").length, 0, "отказ не пишет просмотр");
  // Действия admin для наблюдателя и аналитика — отказ по роли.
  for (const user of ["viewer1", "analyst1"] as const) {
    await auth.createSession(user, user === "viewer1" ? "viewer" : "analyst");
    const fd = new FormData();
    fd.set("person_id", "i.petrov"); fd.set("kind", "login"); fd.set("value", "x");
    assert.match((await actions.bindAliasAction({ error: null }, fd)).error ?? "", /Недостаточно прав/);
    assert.match((await actions.closeAliasAction(fd)).error ?? "", /Недостаточно прав/);
  }
  mocks.jar.clear();
});

test("аналитик: просмотр пишется до чтения данных; без журнала — страница без данных", async () => {
  await auth.createSession("analyst1", "analyst");
  const orig = mocks.queries.audit;
  mocks.queries.audit = async () => { throw new Error("журнал действий недоступен — действие отменено"); };
  try {
    const n = fetched.length;
    const tree = await actorPage.default(props({ id: "i.petrov" }, { range: "24h" }));
    const text = textOf(tree);
    assert.ok(text.includes("Журнал действий недоступен"), text.slice(0, 300));
    assert.ok(!text.includes("Алиасы"), "разделы паспорта не показаны");
    assert.equal(fetched.length, n, "ClickHouse не опрашивался");
  } finally {
    mocks.queries.audit = orig;
  }
  const n = mocks.audit.length;
  const tree = await actorPage.default(props({ id: "i.petrov" }, { range: "30d" }));
  const rec = mocks.audit.slice(n).find((a) => a.action === "actor.view");
  assert.ok(rec, "просмотр записан");
  assert.equal(rec!.user, "analyst1");
  assert.equal(rec!.target, "i.petrov");
  assert.equal(rec!.detail, "30d");
  assert.ok(textOf(tree).includes("Алиасы"));
  assert.ok(fetched.some((s) => s.includes("FROM identities")), "данные читались после записи");
  mocks.jar.clear();
});
