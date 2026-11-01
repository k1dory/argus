// Live-tail журнала без DOM: такт опроса (lib/shared/tail-poll) — догон по more,
// лимит порций, 429 с Retry-After, ошибки сервера, отмена, обрезка ленты,
// склейка инцидентов; подпись состояния; скачивание файла (lib/shared/download).
import { test } from "node:test";
import assert from "node:assert/strict";
import {
  CATCHUP_ROUNDS, MAX_ROWS, TAIL_EVERY_MS, THROTTLE_MAX_SEC, THROTTLE_MIN_SEC,
  errorStatus, nextStatus, pollTail, tailStatusText, tailUrl, throttleSeconds, type TailBody, type TailStatus,
} from "../src/lib/shared/tail-poll";
import type { JournalEvent, JournalFilters, TailState } from "../src/lib/shared/journal";
import { fetchDownload, REVOKE_AFTER_MS, saveBlob, type DownloadDom } from "../src/lib/shared/download";

const NOW = "2026-10-29 10:00:00.000";
const ev = (id: string, over: Partial<JournalEvent> = {}): JournalEvent => ({
  time: NOW, received: NOW, id, severity: 3, source: "linux.auth", source_class: "syslog", vendor: "", product: "", action: "login", outcome: "success",
  actor_name: "root", actor_kind: "user", object: "", node: "bastion", session_id: "", src_ip: "", src_port: 0, dst_ip: "", dst_port: 0, proto: "", bytes: 0, packets: 0,
  value: 0, unit: "", pii: 0, attrs: {}, raw: "", ...over,
});
const stateOf = (rows: JournalEvent[]): TailState => ({ rows, seen: new Set(rows.map((r) => r.id)) });
const filters: JournalFilters = { q: "sshd", range: "7d", source: "linux.auth", page: 3, from: "2026-10-01T00:00" };

type Call = { url: string; init?: RequestInit };
/** fetch, отдающий ответы по очереди и записывающий вызовы. */
function fakeFetch(responses: Array<{ status?: number; body?: TailBody | string; headers?: Record<string, string> }>): { fetchFn: typeof fetch; calls: Call[] } {
  const calls: Call[] = [];
  const fetchFn = (async (input: URL | string | Request, init?: RequestInit) => {
    calls.push({ url: String(input), init });
    const r = responses.shift() ?? { status: 200, body: { rows: [], more: false } };
    const body = typeof r.body === "string" ? r.body : JSON.stringify(r.body ?? {});
    return new Response(body, { status: r.status ?? 200, headers: r.headers });
  }) as typeof fetch;
  return { fetchFn, calls };
}

test("tailUrl: интервал панели не передаётся (tail — всегда «сейчас»), страница сбрасывается, курсор в query", () => {
  const u = new URL(tailUrl(filters, "2026-10-29 10:00:00|42"), "http://x");
  assert.equal(u.pathname, "/api/events/tail");
  assert.equal(u.searchParams.get("q"), "sshd");
  assert.equal(u.searchParams.get("source"), "linux.auth");
  assert.equal(u.searchParams.get("cursor"), "2026-10-29 10:00:00|42");
  assert.equal(u.searchParams.get("range"), null);
  assert.equal(u.searchParams.get("from"), null);
  assert.equal(u.searchParams.get("page"), null);
});

test("throttleSeconds: Retry-After в пределах 5–60, мусор и отсутствие — 5", () => {
  assert.equal(throttleSeconds(null), THROTTLE_MIN_SEC);
  assert.equal(throttleSeconds("abc"), THROTTLE_MIN_SEC);
  assert.equal(throttleSeconds("3"), 5);
  assert.equal(throttleSeconds("17"), 17);
  assert.equal(throttleSeconds("600"), THROTTLE_MAX_SEC);
});

test("pollTail: одна порция без more — курсор сдвинут, новые строки сверху, инциденты склеены", async () => {
  const { fetchFn, calls } = fakeFetch([{ body: { rows: [ev("2"), ev("3")], cursor: "c2", more: false, incidents: { "3": [{ incident_id: "INC-7", rule_id: "r", rule_title: "t", level: "high", status: "new", node: "", actor_name: "", sources: [], first_ts: NOW, last_ts: NOW }] } } }]);
  const r = await pollTail({ filters, cursor: "c1", state: stateOf([ev("1")]), fetchFn });
  assert.equal(calls.length, 1);
  assert.match(calls[0].url, /cursor=c1/);
  assert.equal((calls[0].init as { cache?: string }).cache, "no-store");
  assert.equal(r.cursor, "c2");
  assert.deepEqual(r.state.rows.map((x) => x.id), ["3", "2", "1"], "порция по возрастанию, лента — новые сверху");
  assert.deepEqual(r.added.map((x) => x.id), ["2", "3"]);
  assert.equal(r.trimmed, 0);
  assert.equal(r.pending, 0);
  assert.equal(r.throttled, 0);
  assert.deepEqual(Object.keys(r.incidents), ["3"]);
});

test("pollTail: догон по more — порции подряд не больше CATCHUP_ROUNDS, pending из последнего ответа", async () => {
  const many = Array.from({ length: CATCHUP_ROUNDS + 2 }, (_, i) => ({ body: { rows: [ev(`r${i}`)], cursor: `c${i + 1}`, more: true, pending: 100 - i } as TailBody }));
  const { fetchFn, calls } = fakeFetch(many);
  const r = await pollTail({ filters, cursor: "c0", state: stateOf([]), fetchFn });
  assert.equal(calls.length, CATCHUP_ROUNDS);
  assert.equal(r.cursor, `c${CATCHUP_ROUNDS}`);
  assert.equal(r.added.length, CATCHUP_ROUNDS);
  assert.equal(r.pending, 100 - (CATCHUP_ROUNDS - 1), "в очереди — по последней порции");
  assert.deepEqual(calls.map((c) => new URL(c.url, "http://x").searchParams.get("cursor")), ["c0", "c1", "c2", "c3"], "каждая порция — с курсором предыдущей");

  const { fetchFn: f2 } = fakeFetch([{ body: { rows: [ev("a")], cursor: "c1", more: true, pending: 5 } }, { body: { rows: [ev("b")], cursor: "c2", more: false, pending: 0 } }]);
  const r2 = await pollTail({ filters, cursor: "c0", state: stateOf([]), fetchFn: f2 });
  assert.equal(r2.pending, 0, "догнали — pending обнулён");
  assert.equal(r2.cursor, "c2");
});

test("pollTail: 429 — не ошибка, курсор стоит, пауза по Retry-After; собранное до лимита не теряется", async () => {
  const { fetchFn } = fakeFetch([
    { body: { rows: [ev("a")], cursor: "c1", more: true, pending: 9 } },
    { status: 429, body: { error: "rate limited" }, headers: { "Retry-After": "12" } },
  ]);
  const r = await pollTail({ filters, cursor: "c0", state: stateOf([]), fetchFn });
  assert.equal(r.cursor, "c1", "курсор — по последнему успешному ответу");
  assert.equal(r.throttled, 12);
  assert.deepEqual(r.added.map((x) => x.id), ["a"]);
  assert.equal(r.pending, 9);
  const { fetchFn: f2 } = fakeFetch([{ status: 429, body: {} }]);
  const r2 = await pollTail({ filters, cursor: "c0", state: stateOf([]), fetchFn: f2 });
  assert.equal(r2.throttled, THROTTLE_MIN_SEC);
  assert.equal(r2.cursor, "c0");
});

test("pollTail: ошибка сервера — исключение с текстом из тела или HTTP-статусом, курсор не трогается", async () => {
  const { fetchFn } = fakeFetch([{ status: 400, body: { error: "cursor: ожидается «YYYY-MM-DD HH:MM:SS|id»" } }]);
  await assert.rejects(pollTail({ filters, cursor: "bad", state: stateOf([]), fetchFn }), /cursor: ожидается/);
  const { fetchFn: f2 } = fakeFetch([{ status: 503, body: {} }]);
  await assert.rejects(pollTail({ filters, cursor: "c0", state: stateOf([]), fetchFn: f2 }), /HTTP 503/);
  const { fetchFn: f3 } = fakeFetch([{ status: 200, body: "<html>not json" }]);
  await assert.rejects(pollTail({ filters, cursor: "c0", state: stateOf([]), fetchFn: f3 }), SyntaxError);
});

test("pollTail: отменённый signal — ни одного запроса; отмена между порциями останавливает догон", async () => {
  const ctrl = new AbortController();
  ctrl.abort();
  const { fetchFn, calls } = fakeFetch([]);
  const r = await pollTail({ filters, cursor: "c0", state: stateOf([ev("1")]), fetchFn, signal: ctrl.signal });
  assert.equal(calls.length, 0);
  assert.equal(r.cursor, "c0");
  assert.equal(r.state.rows.length, 1);

  const c2 = new AbortController();
  const stopAfterFirst = (async (input: URL | string | Request, init?: RequestInit) => {
    c2.abort();
    return new Response(JSON.stringify({ rows: [ev("x")], cursor: "c1", more: true, pending: 50 }), { status: 200, headers: init?.headers as HeadersInit });
  }) as typeof fetch;
  const r2 = await pollTail({ filters, cursor: "c0", state: stateOf([]), fetchFn: stopAfterFirst, signal: c2.signal });
  assert.equal(r2.cursor, "c1", "первая порция применена");
  assert.equal(r2.added.length, 1, "вторую порцию при отмене не спрашивали");
  assert.equal(r2.pending, 50);
});

test("pollTail: лента не длиннее maxRows — старые уходят вниз, trimmed считает их; дубли по id не добавляются", async () => {
  const initial = Array.from({ length: 4 }, (_, i) => ev(`old${i}`));
  const { fetchFn } = fakeFetch([{ body: { rows: [ev("old1"), ev("n1"), ev("n2"), ev("n3")], cursor: "c1", more: false } }]);
  const r = await pollTail({ filters, cursor: "c0", state: stateOf(initial), fetchFn, maxRows: 5 });
  assert.deepEqual(r.added.map((x) => x.id), ["n1", "n2", "n3"], "old1 уже в ленте");
  assert.equal(r.state.rows.length, 5);
  assert.deepEqual(r.state.rows.map((x) => x.id), ["n3", "n2", "n1", "old0", "old1"]);
  assert.equal(r.trimmed, 2);
  assert.ok(r.state.seen.has("n3") && !r.state.seen.has("old3"), "seen — ровно то, что в ленте");
  assert.equal(MAX_ROWS, 500);
});

test("статус: накопление added/trimmed между тактами, ошибка сохраняет суммы; подписи всех состояний", () => {
  const r1 = nextStatus(null, { added: [ev("1"), ev("2")], trimmed: 0, pending: 7, throttled: 0 }, "2026-10-29T10:00:05.000Z");
  assert.equal(r1.added, 2);
  const r2 = nextStatus(r1, { added: [ev("3")], trimmed: 4, pending: 0, throttled: 0 }, "2026-10-29T10:00:10.000Z");
  assert.equal(r2.added, 3);
  assert.equal(r2.trimmed, 4);
  assert.equal(r2.pending, 0);
  const e1 = errorStatus(r2, new Error("HTTP 503"), "2026-10-29T10:00:15.000Z");
  assert.equal(e1.error, "HTTP 503");
  assert.equal(e1.added, 3, "ошибка не сбрасывает счётчики");
  assert.equal(e1.trimmed, 4);
  assert.equal(errorStatus(null, "строка").error, "ошибка");
  assert.equal(errorStatus(null, "x").added, 0);

  assert.equal(tailStatusText(null, true, false), "live-tail недоступен для прошлого интервала");
  assert.equal(tailStatusText(null, false, true), "лента зафиксирована на момент загрузки");
  assert.equal(tailStatusText(null, true, true), "ждём новые события…");
  assert.equal(tailStatusText(e1, true, true), `ошибка обновления: HTTP 503 — повторим через ${TAIL_EVERY_MS / 1000} с, события не пропадут`);
  const th: TailStatus = { ...r2, throttled: 15 };
  assert.equal(tailStatusText(th, true, true), "пауза 15 с, догоняем — события не пропадут");
  assert.equal(tailStatusText(r1, true, true), "обновлено 10:00:05 UTC · пришло с начала live 2 · догоняем, в очереди ещё 7");
  assert.equal(tailStatusText(r2, true, true), "обновлено 10:00:10 UTC · пришло с начала live 3");
});

test("fetchDownload: blob при 2xx с same-origin; ошибка — текст {error} из JSON, иначе HTTP-статус", async () => {
  const calls: Call[] = [];
  const ok = (async (input: URL | string | Request, init?: RequestInit) => {
    calls.push({ url: String(input), init });
    return new Response("a,b\n1,2\n", { status: 200, headers: { "Content-Type": "text/csv" } });
  }) as typeof fetch;
  const blob = await fetchDownload("/api/search?format=csv", ok);
  assert.equal(await blob.text(), "a,b\n1,2\n");
  assert.equal(calls[0].init?.credentials, "same-origin");
  const json = (async () => new Response(JSON.stringify({ error: "лимит экспорта 10000 строк" }), { status: 400 })) as typeof fetch;
  await assert.rejects(fetchDownload("/x", json), /лимит экспорта 10000 строк/);
  const plain = (async () => new Response("Service Unavailable", { status: 503 })) as typeof fetch;
  await assert.rejects(fetchDownload("/x", plain), /^Error: HTTP 503$/);
  const emptyJson = (async () => new Response("{}", { status: 404 })) as typeof fetch;
  await assert.rejects(fetchDownload("/x", emptyJson), /^Error: HTTP 404$/);
});

test("saveBlob: ссылка с download добавлена, нажата и убрана; объектный URL отзывается через REVOKE_AFTER_MS", () => {
  const log: string[] = [];
  let scheduled: { fn: () => void; ms: number } | null = null;
  const anchor = { href: "", download: "", click: () => log.push("click"), remove: () => log.push("remove") };
  const dom: DownloadDom = {
    createObjectURL: () => "blob:argus/1",
    revokeObjectURL: (u) => log.push(`revoke ${u}`),
    createElement: () => anchor,
    append: (n) => log.push(`append ${n.href}`),
    schedule: (fn, ms) => { scheduled = { fn, ms }; },
  };
  const url = saveBlob(new Blob(["x"]), "actor-i.petrov.md", dom);
  assert.equal(url, "blob:argus/1");
  assert.equal(anchor.download, "actor-i.petrov.md");
  assert.deepEqual(log, ["append blob:argus/1", "click", "remove"]);
  assert.equal(scheduled!.ms, REVOKE_AFTER_MS);
  scheduled!.fn();
  assert.equal(log.at(-1), "revoke blob:argus/1");
});
