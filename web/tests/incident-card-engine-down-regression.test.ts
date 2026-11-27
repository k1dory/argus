// C9 (ревью дизайна «Инциденты»): на карточке инцидента в next dev висел
// оверлей «1 Issue». Причина — respondStatus() при недоступном движке писал
// console.error, а next dev пересылает серверный console.error в браузер и
// считает его ошибкой страницы. Недоступный движок — ожидаемая деградация
// (карточка показывает «движок недоступен»), поэтому это предупреждение.
import { test } from "node:test";
import assert from "node:assert/strict";

test("C9: недоступный движок — без console.error (оверлей «1 Issue» в next dev), ошибка видна в ответе", async () => {
  process.env.ENGINE_URL = "http://engine.invalid:8090";
  const realFetch = globalThis.fetch;
  globalThis.fetch = (async (input: RequestInfo | URL) => {
    const url = String(input instanceof Request ? input.url : input);
    if (url.startsWith("http://engine.invalid")) throw new TypeError("fetch failed");
    return new Response(""); // ClickHouse: пустой результат
  }) as typeof fetch;
  const errors: unknown[][] = [];
  const warns: unknown[][] = [];
  const realError = console.error;
  const realWarn = console.warn;
  console.error = (...a: unknown[]) => { errors.push(a); };
  console.warn = (...a: unknown[]) => { warns.push(a); };
  try {
    const q = await import("../src/lib/argus-queries");
    const st = await q.respondStatus();
    assert.equal(st.error, "движок недоступен");
    assert.deepEqual(st.active, []);
    const rules = await q.engineRules();
    assert.equal(rules.error, "движок недоступен");
    assert.equal(errors.length, 0, `console.error поднимает оверлей next dev: ${JSON.stringify(errors)}`);
    assert.ok(warns.some((w) => String(w[0]).includes("engine.respond_status")), "причина остаётся в логе сервера");
  } finally {
    globalThis.fetch = realFetch;
    console.error = realError;
    console.warn = realWarn;
  }
});
