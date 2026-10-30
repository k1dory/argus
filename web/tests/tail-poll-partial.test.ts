// Live-tail: сбой на второй порции догона не отменяет первую — курсор, строки и
// инциденты уже забранных порций остаются, ошибка уходит в статус. Сбой на первой
// порции по-прежнему исключение (следующий такт спросит то же место).
import { test } from "node:test";
import assert from "node:assert/strict";
import { parseJournalParams, type JournalEvent } from "../src/lib/shared/journal";
import { errorStatus, nextStatus, pollTail, tailStatusText } from "../src/lib/shared/tail-poll";

const filters = parseJournalParams({});
const row = (id: string) => ({ id, time: "2026-10-30 10:00:00.000", received: "2026-10-30 10:00:00" }) as unknown as JournalEvent;
const json = (body: unknown, status = 200) => new Response(JSON.stringify(body), { status, headers: { "Content-Type": "application/json" } });

function scripted(replies: (() => Response | Promise<Response>)[]) {
  const urls: string[] = [];
  const fetchFn = (async (url: string | URL) => {
    urls.push(String(url));
    const next = replies.shift();
    if (!next) throw new Error("лишний запрос");
    return next();
  }) as typeof fetch;
  return { fetchFn, urls };
}

for (const [name, second] of [
  ["503 со своим текстом", () => json({ error: "хранилище недоступно" }, 503)],
  ["HTML-страница прокси вместо JSON", () => new Response("<html>502 Bad Gateway</html>", { status: 502 })],
  ["сетевой сбой", () => Promise.reject(new TypeError("fetch failed"))],
] as const) {
  test(`догон: ${name} на второй порции — первая порция применена, курсор сдвинут, ошибка в статусе`, async () => {
    const { fetchFn, urls } = scripted([
      () => json({ rows: [row("a1"), row("a2")], cursor: "c1", more: true, pending: 300, incidents: { a1: [{ incident_id: "INC-1" }] } }),
      second,
    ]);
    const r = await pollTail({ filters, cursor: "c0", state: { rows: [], seen: new Set() }, fetchFn });
    assert.equal(urls.length, 2);
    assert.match(urls[1], /cursor=c1/, "вторая порция спрошена с нового курсора");
    assert.equal(r.cursor, "c1", "курсор после первой порции не теряется");
    assert.deepEqual(r.added.map((x) => x.id), ["a1", "a2"]);
    assert.deepEqual(r.state.rows.map((x) => x.id).sort(), ["a1", "a2"]);
    assert.ok(r.incidents.a1, "инциденты первой порции");
    assert.ok(r.error && r.error.length > 0, "текст сбоя");
    assert.equal(r.throttled, 0);
    const st = nextStatus(null, r);
    assert.equal(st.added, 2, "в статусе учтены забранные строки");
    assert.equal(st.error, r.error);
    assert.match(tailStatusText(st, true, true), /^ошибка обновления: /);
  });
}

test("сбой на первой порции — исключение, как раньше; успешный такт — без ошибки", async () => {
  const { fetchFn } = scripted([() => json({ error: "cursor: ожидается received_at|id" }, 400)]);
  await assert.rejects(pollTail({ filters, cursor: "bad", state: { rows: [], seen: new Set() }, fetchFn }), /cursor: ожидается/);
  const ok = scripted([() => json({ rows: [row("b1")], cursor: "c2", more: false })]);
  const r = await pollTail({ filters, cursor: "c1", state: { rows: [], seen: new Set() }, fetchFn: ok.fetchFn });
  assert.equal(r.error, null);
  assert.equal(nextStatus(errorStatus(null, new Error("x")), r).error, null, "успешный такт снимает ошибку");
});
