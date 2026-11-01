/* eslint-disable @typescript-eslint/no-require-imports -- авторизация подменяется до загрузки Server Component */
import { test } from "node:test";
import assert from "node:assert/strict";
import Module from "node:module";
import { Children, isValidElement, Suspense, type ReactElement, type ReactNode } from "react";

// Проверяем настоящую функцию страницы и её Suspense-границы. Авторизация —
// единственная подмена модулей; SQL/разбор ClickHouse и searchRows настоящие.
const authFile = require.resolve("../src/lib/auth");
const cache = (Module as unknown as { _cache: Record<string, Module> })._cache;
const previousAuth = cache[authFile];
const authMock = new Module(authFile);
authMock.loaded = true;
authMock.exports = { requirePageSession: async () => ({ user: "review", role: "analyst" }) };
cache[authFile] = authMock;
const SearchPage = (require("../src/app/(console)/search/page") as {
  default: (props: { searchParams: Promise<Record<string, string>> }) => Promise<ReactNode>;
}).default;
if (previousAuth) cache[authFile] = previousAuth;
else delete cache[authFile];

function deferred<T>() {
  let resolve!: (value: T) => void;
  const promise = new Promise<T>((done) => { resolve = done; });
  return { promise, resolve };
}

type Element = ReactElement<Record<string, unknown>>;
function descendants(node: ReactNode): Element[] {
  if (!isValidElement<Record<string, unknown>>(node)) return [];
  return [node, ...Children.toArray(node.props.children as ReactNode).flatMap(descendants)];
}

const timeoutResponse = () => new Response("Code: 159. DB::Exception: Timeout exceeded. (TIMEOUT_EXCEEDED)", {
  status: 500, headers: { "X-ClickHouse-Exception-Code": "159" },
});

test("страница отдаёт строки и независимые Suspense-блоки, пока гистограмма и фасеты ещё ждут", async (t) => {
  const series = deferred<Response>();
  const facets = deferred<Response>();
  const sql: string[] = [];
  t.mock.method(globalThis, "fetch", async (_url: URL | string, init?: RequestInit) => {
    const query = String(init?.body ?? "");
    sql.push(query);
    if (query.includes("OFFSET {offset:UInt32}")) return new Response(JSON.stringify({ source: "regression", raw: "visible row", severity: 3 }));
    if (query.includes("toStartOfInterval")) return series.promise;
    if (query.includes("arrayJoin")) return facets.promise;
    throw new Error(`unexpected SQL: ${query}`);
  });
  let timer: ReturnType<typeof setTimeout> | undefined;
  try {
    const page = await Promise.race([
      SearchPage({ searchParams: Promise.resolve({ index: "events", q: "sshd", range: "30d" }) }),
      new Promise<never>((_, reject) => { timer = setTimeout(() => reject(new Error("строки ждут незавершённые гистограмму/фасеты")), 1000); }),
    ]);
    assert.equal(sql.length, 3, "все части запущены, но для возврата страницы нужны только строки");
    const results = descendants(page).find((e) => Array.isArray(e.props.rows));
    assert.ok(results, "готовые строки переданы в блок результатов");
    assert.deepEqual(results.props.rows, [{ source: "regression", raw: "visible row", severity: 3 }]);
    assert.equal(typeof results.type, "function");
    const tree = (results.type as (props: Record<string, unknown>) => ReactNode)(results.props);
    const boundaries = descendants(tree).filter((e) => e.type === Suspense);
    assert.ok(boundaries.length >= 2, "гистограмма и фасеты имеют отдельные границы ожидания");

    series.resolve(timeoutResponse());
    facets.resolve(timeoutResponse());
    const [seriesResult, facetsResult] = await Promise.all([
      results.props.seriesP as Promise<{ ok: boolean }>,
      results.props.facetsP as Promise<{ ok: boolean }>,
    ]);
    assert.equal(seriesResult.ok, false);
    assert.equal(facetsResult.ok, false);
    // Ошибки обеих частей не отклоняют promises, отданные React, и не меняют
    // уже готовую страницу. API search() проверяется отдельно: он ждёт части.
    assert.equal((results.props.rows as unknown[]).length, 1);
  } finally {
    if (timer) clearTimeout(timer);
    series.resolve(timeoutResponse());
    facets.resolve(timeoutResponse());
  }
});

test("пустая дальняя страница при таймауте гистограммы сохраняет ссылку назад", async (t) => {
  t.mock.method(console, "error", () => undefined);
  t.mock.method(globalThis, "fetch", async (_url: URL | string, init?: RequestInit) => {
    const sql = String(init?.body ?? "");
    if (sql.includes("OFFSET {offset:UInt32}") || sql.includes("arrayJoin")) return new Response("");
    if (sql.includes("toStartOfInterval")) return timeoutResponse();
    throw new Error(`unexpected SQL: ${sql}`);
  });
  const page = await SearchPage({ searchParams: Promise.resolve({ index: "events", q: "sshd", range: "30d", page: "100" }) });
  const results = descendants(page).find((e) => Array.isArray(e.props.rows));
  assert.ok(results);
  assert.deepEqual(results.props.rows, []);
  const tree = (results.type as (props: Record<string, unknown>) => ReactNode)(results.props);
  // Настоящий async-компонент пейджера после отказа series выбирает fallback.
  // Затем вызываем настоящий Pager и проверяем доступную ссылку, а не только
  // арифметику pageCount: при pages=1 Pager сейчас возвращает null.
  const exactPager = descendants(tree).find((e) => e.props.seriesP === results.props.seriesP && typeof e.props.pager === "function");
  assert.ok(exactPager, "страница содержит компонент навигации");
  const pager = await (exactPager.type as (props: Record<string, unknown>) => Promise<ReactNode>)(exactPager.props);
  assert.ok(isValidElement<Record<string, unknown>>(pager));
  assert.equal(typeof pager.type, "function");
  const rendered = (pager.type as (props: Record<string, unknown>) => ReactNode)(pager.props);
  const previous = descendants(rendered).find((e) => e.props.rel === "prev");
  assert.ok(previous, "page=100, rows=0 и неизвестный total не должны убирать ссылку на предыдущую страницу");
  const href = new URL(String(previous.props.href), "http://test.invalid");
  assert.equal(href.searchParams.get("page"), "99");
  assert.equal(href.searchParams.get("q"), "sshd");
  assert.equal(href.searchParams.get("index"), "events");
});
